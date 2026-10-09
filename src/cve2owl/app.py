import argparse
from datetime import UTC, datetime
from pathlib import Path

import cowl

from .core.jsonio import read_json_record, walk
from .core.log import logger as log
from .core.sink import AxiomSink
from .cpe.abox import CpeWriter, component_declarations
from .cpe.feed import record_path
from .cpe.tbox import CPE, cpe_tbox
from .cpe.uri import ANY, parse_cpe
from .cve.abox import CveWriter
from .cve.dates import date_in_range, record_date
from .cve.links import CveLinker, link_declarations
from .cve.tbox import cve_tbox
from .cve.vocab import CVE
from .cwe.abox import DIRECTORIES, CweWriter
from .cwe.tbox import CWE, cwe_tbox

DEFAULT_CPE_SCHEMA = "data/cpe-schema/cpe_api_json_2.0.schema"
DEFAULT_CWE_SCHEMA = "data/cwe-schema/openapi.json"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Transforms the CVE data from cvelistV5 into an OWL ontology.",
    )
    parser.add_argument(
        "input_dirs",
        metavar="INPUT_DIR",
        nargs="+",
        help="Paths to the directories containing the CVE records.",
    )
    parser.add_argument(
        "--schema",
        "-s",
        required=True,
        help="Path to the JSON Schema file defining the structure of the CVE data.",
    )
    parser.add_argument(
        "--cpe-schema",
        default=DEFAULT_CPE_SCHEMA,
        help=f"Path to the NVD CPE JSON Schema (default: {DEFAULT_CPE_SCHEMA}).",
    )
    parser.add_argument(
        "--cpe-dir",
        help="Path to the exploded CPE dictionary records (see cve2owl.cpe.feed). "
        "If omitted, the dictionary is not ingested and CPE nodes are described "
        "from the CPE strings found in the CVE records only.",
    )
    parser.add_argument(
        "--all-cpe",
        action="store_true",
        help="Read the whole CPE dictionary instead of only the products the CVE "
        "records mention. About 1.7 million products, so the result is a much "
        "bigger file: only use it if every product really has to be in the graph.",
    )
    parser.add_argument(
        "--cwe-schema",
        default=DEFAULT_CWE_SCHEMA,
        help=f"Path to the CWE REST API OpenAPI document (default: {DEFAULT_CWE_SCHEMA}).",
    )
    parser.add_argument(
        "--cwe-dir",
        help="Path to the downloaded CWE catalogue, the folder holding the "
        "weaknesses, categories and views subfolders (see README). If omitted, "
        "the catalogue is not ingested and the CWE nodes linked from a CVE stay "
        "bare, since nothing can be derived from a CWE identifier alone.",
    )
    parser.add_argument(
        "--from-date",
        help="Only process the CVE records published on this date or after it. "
        "The date can be a year, a month or a day: 2024, 2024-03, 2024-03-15.",
    )
    parser.add_argument(
        "--to-date",
        help="Only process the CVE records published on this date or before it. "
        "Same formats as --from-date.",
    )
    parser.add_argument(
        "--output-dir",
        "-o",
        default="output",
        help="Path to the directory where the OWL ontology will be saved.",
    )
    return parser.parse_args()


def write_tboxes(
    sink: AxiomSink,
    cve_schema: Path,
    cpe_schema: Path,
    cwe_schema: Path,
) -> None:
    # The output is a single ontology with the CVE IRI, so the CVE record also writes the header.
    log.info("Loading CVE schema...")
    with read_json_record(cve_schema) as schema:
        cve_onto = cve_tbox(schema)
        sink.write_header(CVE.iri, [CVE, CPE, CWE])
        sink.write_axioms(cve_onto)

    log.info("Loading CPE schema...")
    with read_json_record(cpe_schema) as schema:
        sink.write_axioms(cpe_tbox(schema))

    log.info("Loading CWE schema...")
    with read_json_record(cwe_schema) as schema:
        sink.write_axioms(cwe_tbox(schema))


def process_cwe_catalog(cwe_dir: Path, writer: CweWriter) -> None:
    log.info("Processing CWE catalogue...")
    for subdir, class_name in DIRECTORIES:
        for json_file in walk(cwe_dir / subdir, "CWE-*.json"):
            writer.process_record(json_file, class_name)


def process_cve_records(
    input_dirs: list[str],
    writer: CveWriter,
    from_date: str | None,
    to_date: str | None,
) -> None:
    log.info("Processing CVE data...")
    filter_by_date = bool(from_date or to_date)
    for input_dir in input_dirs:
        for json_file in walk(Path(input_dir), "CVE-*.json"):
            # Folders are named after the ID year, not the publication year.
            if filter_by_date and not date_in_range(record_date(json_file), from_date, to_date):
                continue
            writer.process_record(json_file)


def process_cpe_dictionary(cpe_dir: Path, writer: CpeWriter, *, all_cpe: bool) -> None:
    if all_cpe:
        log.info("Processing the whole CPE dictionary...")
        for json_file in walk(cpe_dir, "*.json"):
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
        json_file = record_path(cpe_dir, cpe)
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


def app() -> None:
    args = parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    stem = f"cve2owl_{datetime.now(tz=UTC).strftime('%Y%m%d_%H%M%S')}"
    log.open(output_dir / f"{stem}.csv")

    output_path = output_dir / f"{stem}.owl"
    writer = cowl.Writer.functional()

    with writer.stream(output_path) as stream:
        sink = AxiomSink(stream)
        write_tboxes(
            sink,
            Path(args.schema),
            Path(args.cpe_schema),
            Path(args.cwe_schema),
        )

        # Properties not described by any schema. Not a record, as there is no input file.
        count = sink.write_extra([
            *link_declarations(),
            *component_declarations(),
        ])
        log.info("  %d properties declared by the enrichment module", count)

        cpe_writer = CpeWriter(sink)
        cwe_writer = CweWriter(sink)

        if args.cwe_dir:
            process_cwe_catalog(Path(args.cwe_dir), cwe_writer)

        linker = CveLinker(sink, cpe_writer, cwe_writer)
        cve_writer = CveWriter(sink, on_object=linker)
        process_cve_records(args.input_dirs, cve_writer, args.from_date, args.to_date)

        if args.cpe_dir:
            process_cpe_dictionary(Path(args.cpe_dir), cpe_writer, all_cpe=args.all_cpe)

    log.close()
    log.info("Ontology written to %s", output_path)
