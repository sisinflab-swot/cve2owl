from datetime import UTC, datetime
from fnmatch import fnmatch
from pathlib import Path

import cowl

from .core.jsonio import read_json_record, walk
from .core.log import logger as log
from .core.sink import AxiomSink
from .cpe.abox import CpeWriter, component_declarations, deprecation_axioms
from .cpe.fetch import record_path
from .cpe.tbox import CPE, cpe_tbox
from .cpe.uri import ANY, parse_cpe
from .cve.abox import CveWriter
from .cve.dates import date_in_range, record_date
from .cve.links import CveLinker, link_declarations
from .cve.tbox import cve_tbox
from .cve.vocab import CVE
from .cwe.abox import DIRECTORIES, CweWriter, link_axioms
from .cwe.tbox import CWE, cwe_tbox
from .data import (
    CPE_RECORDS_DIR,
    CPE_SCHEMA,
    CVE_RECORDS_DIR,
    CVE_SCHEMA,
    CWE_CATALOGUE_DIR,
    CWE_SCHEMA,
)

DEFAULT_OUTPUT_DIR = Path("output")

CPE_MODES = ("none", "referenced", "all")


class MissingDataError(Exception):
    pass


def check_data(*, cpe: str, cwe: bool) -> None:
    required = [
        (CVE_SCHEMA, "fetch"),
        (CPE_SCHEMA, "fetch"),
        (CWE_SCHEMA, "fetch"),
        (CVE_RECORDS_DIR, "fetch cve"),
    ]
    if cpe != "none":
        required.append((CPE_RECORDS_DIR, "fetch cpe"))
    if cwe:
        required.append((CWE_CATALOGUE_DIR, "fetch cwe"))
    for path, command in required:
        if not path.exists():
            msg = f"{path} not found: run `cve2owl {command}` first."
            raise MissingDataError(msg)


def write_tboxes(sink: AxiomSink) -> None:
    log.info("Loading CVE schema...")
    with read_json_record(CVE_SCHEMA) as schema:
        cve_onto = cve_tbox(schema)
        sink.write_header(CVE.iri, [CVE, CPE, CWE])
        sink.write_axioms(cve_onto)

    log.info("Loading CPE schema...")
    with read_json_record(CPE_SCHEMA) as schema:
        sink.write_axioms(cpe_tbox(schema))

    log.info("Loading CWE schema...")
    with read_json_record(CWE_SCHEMA) as schema:
        sink.write_axioms(cwe_tbox(schema))


def write_extras(sink: AxiomSink) -> None:
    count = sink.write_extra([
        *link_declarations(),
        *component_declarations(),
        *deprecation_axioms(),
        *link_axioms(),
    ])
    log.info("Enriched with %d extra axioms", count)


def process_cwe_catalog(writer: CweWriter) -> None:
    log.info("Processing CWE catalogue...")
    for subdir, class_name in DIRECTORIES:
        for json_file in walk(CWE_CATALOGUE_DIR / subdir, "CWE-*.json"):
            writer.process_record(json_file, class_name)


def process_cve_records(
    writer: CveWriter,
    ids: list[str] | None,
    from_date: str | None,
    to_date: str | None,
) -> None:
    log.info("Processing CVE data...")
    filter_by_date = bool(from_date or to_date)
    for json_file in walk(CVE_RECORDS_DIR, "CVE-*.json"):
        if ids and not any(fnmatch(json_file.stem, pattern) for pattern in ids):
            continue
        if filter_by_date and not date_in_range(record_date(json_file), from_date, to_date):
            continue
        writer.process_record(json_file)


def process_cpe_dictionary(writer: CpeWriter, *, all_cpe: bool) -> None:
    if all_cpe:
        log.info("Processing the whole CPE dictionary...")
        for json_file in walk(CPE_RECORDS_DIR, "*.json"):
            writer.process_record(json_file)
        return

    log.info("Processing CPE dictionary...")
    found = 0
    missing = 0
    families = 0
    # Copy, as process_record() updates writer.described.
    for cpe_string in list(writer.described.values()):
        cpe = parse_cpe(cpe_string)
        # Any version: a product family, not a product.
        if cpe.version == ANY:
            families = families + 1
            continue
        json_file = record_path(CPE_RECORDS_DIR, cpe)
        if json_file.exists():
            writer.process_record(json_file)
            found = found + 1
        else:
            missing = missing + 1
    log.info(
        "  %d products found in the dictionary, %d missing, %d product families",
        found,
        missing,
        families,
    )


def generate(
    *,
    ids: list[str] | None = None,
    from_date: str | None = None,
    to_date: str | None = None,
    cpe: str = "referenced",
    cwe: bool = True,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
) -> None:
    check_data(cpe=cpe, cwe=cwe)
    output_dir.mkdir(parents=True, exist_ok=True)

    stem = f"cve2owl_{datetime.now(tz=UTC).strftime('%Y%m%d_%H%M%S')}"
    log.open(output_dir / f"{stem}.csv")

    output_path = output_dir / f"{stem}.owl"
    writer = cowl.Writer.functional()

    with writer.stream(output_path) as stream:
        sink = AxiomSink(stream)
        write_tboxes(sink)
        write_extras(sink)

        cpe_writer = CpeWriter(sink)
        cwe_writer = CweWriter(sink, cve_mapper=CVE.individual)

        if cwe:
            process_cwe_catalog(cwe_writer)

        linker = CveLinker(sink, cpe_writer, cwe_writer)
        cve_writer = CveWriter(sink, on_object=linker)
        process_cve_records(cve_writer, ids, from_date, to_date)

        if cpe != "none":
            process_cpe_dictionary(cpe_writer, all_cpe=cpe == "all")

    log.close()
    log.info("Ontology written to %s", output_path)
