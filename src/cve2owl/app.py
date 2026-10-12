from datetime import UTC, datetime
from fnmatch import fnmatch
from pathlib import Path

import cowl

from .core.jsonio import read_json_record, walk
from .core.log import logger as log
from .core.sink import AxiomSink
from .cpe.abox import CpeWriter, extra_axioms as cpe_extra_axioms
from .cpe.fetch import record_path
from .cpe.tbox import CPE, cpe_tbox
from .cpe.uri import ANY, parse_cpe
from .cve.abox import CveWriter
from .cve.dates import date_in_range, record_date
from .cve.links import CveLinker, extra_axioms as cve_extra_axioms
from .cve.tbox import cve_tbox
from .cve.vocab import CVE
from .cwe.abox import DIRECTORIES, CweWriter, extra_axioms as cwe_extra_axioms
from .cwe.tbox import CWE, cwe_tbox
from .data import DEFAULT_DATA_DIR, DataDir

DEFAULT_OUTPUT_DIR = Path("output")

CPE_MODES = ("none", "referenced", "all")


class MissingDataError(Exception):
    pass


def check_data(data: DataDir, *, cpe: str, cwe: bool) -> None:
    # Path -> arguments of the fetch command that creates it.
    required = [
        (data.cve_schema, ""),
        (data.cpe_schema, ""),
        (data.cwe_schema, ""),
        (data.cve_records_dir, " cve"),
    ]
    if cpe != "none":
        required.append((data.cpe_records_dir, " cpe"))
    if cwe:
        required.append((data.cwe_catalogue_dir, " cwe"))
    data_option = "" if data.root == DEFAULT_DATA_DIR else f" -d {data.root}"
    for path, datasets in required:
        if not path.exists():
            msg = f"{path} not found: run `cve2owl fetch{data_option}{datasets}` first."
            raise MissingDataError(msg)


def write_tboxes(data: DataDir, sink: AxiomSink) -> None:
    log.info("Loading CVE schema...")
    with read_json_record(data.cve_schema) as schema:
        cve_onto = cve_tbox(schema)
        sink.write_header(CVE.iri, [CVE, CPE, CWE])
        sink.write_axioms(cve_onto)

    log.info("Loading CPE schema...")
    with read_json_record(data.cpe_schema) as schema:
        sink.write_axioms(cpe_tbox(schema))

    log.info("Loading CWE schema...")
    with read_json_record(data.cwe_schema) as schema:
        sink.write_axioms(cwe_tbox(schema))


def write_extras(sink: AxiomSink) -> None:
    count = sink.write_extra([*cve_extra_axioms(), *cpe_extra_axioms(), *cwe_extra_axioms()])
    log.info("Enriched with %d extra axioms", count)


def process_cwe_catalog(data: DataDir, writer: CweWriter) -> None:
    log.info("Processing CWE catalogue...")
    for subdir, class_name in DIRECTORIES:
        for json_file in walk(data.cwe_catalogue_dir / subdir, "CWE-*.json"):
            writer.process_record(json_file, class_name)


def process_cve_records(
    data: DataDir,
    writer: CveWriter,
    ids: list[str] | None,
    from_date: str | None,
    to_date: str | None,
) -> None:
    log.info("Processing CVE data...")
    filter_by_date = bool(from_date or to_date)
    for json_file in walk(data.cve_records_dir, "CVE-*.json"):
        if ids and not any(fnmatch(json_file.stem, pattern) for pattern in ids):
            continue
        if filter_by_date and not date_in_range(record_date(json_file), from_date, to_date):
            continue
        writer.process_record(json_file)


def process_cpe_dictionary(data: DataDir, writer: CpeWriter, *, all_cpe: bool) -> None:
    records_dir = data.cpe_records_dir
    if all_cpe:
        log.info("Processing the whole CPE dictionary...")
        for json_file in walk(records_dir, "*.json"):
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
            families += 1
            continue
        json_file = record_path(records_dir, cpe)
        if json_file.exists():
            writer.process_record(json_file)
            found += 1
        else:
            missing += 1
    log.info("CPE products: %d found, %d missing, %d families", found, missing, families)


def generate(
    *,
    data: DataDir,
    ids: list[str] | None = None,
    from_date: str | None = None,
    to_date: str | None = None,
    cpe: str = "referenced",
    cwe: bool = True,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
) -> None:
    check_data(data, cpe=cpe, cwe=cwe)
    output_dir.mkdir(parents=True, exist_ok=True)

    stem = f"cve2owl_{datetime.now(tz=UTC).strftime('%Y%m%d_%H%M%S')}"
    log.open(output_dir / f"{stem}.csv")

    output_path = output_dir / f"{stem}.owl"
    writer = cowl.Writer.functional()

    with writer.stream(output_path) as stream:
        sink = AxiomSink(stream)
        write_tboxes(data, sink)
        write_extras(sink)

        cpe_writer = CpeWriter(sink)
        cwe_writer = CweWriter(sink, cve_mapper=CVE.individual)

        if cwe:
            process_cwe_catalog(data, cwe_writer)

        linker = CveLinker(sink, cpe_writer, cwe_writer)
        cve_writer = CveWriter(sink, on_object=linker)
        process_cve_records(data, cve_writer, ids, from_date, to_date)

        if cpe != "none":
            process_cpe_dictionary(data, cpe_writer, all_cpe=cpe == "all")

    log.close()
    log.info("Ontology written to %s", output_path)
