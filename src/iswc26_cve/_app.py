import argparse
from datetime import UTC, datetime
from pathlib import Path

import cowl

from ._cve import CVEWriter
from ._log import logger as log
from ._schema import schema_path_to_ontology, write_ontology
from ._util import walk


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
        "--output-dir",
        "-o",
        default="output",
        help="Path to the directory where the OWL ontology will be saved.",
    )
    return parser.parse_args()


def app() -> None:
    args = parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    stem = f"iswc26_cve_{datetime.now(tz=UTC).strftime('%Y%m%d_%H%M%S')}"
    log.open(output_dir / f"{stem}.csv")

    log.info("Loading schema...")
    schema = schema_path_to_ontology(Path(args.schema))

    log.info("Processing CVE data...")
    output_path = output_dir / f"{stem}.owl"
    writer = cowl.Writer.functional()

    with writer.stream(output_path) as stream:
        # Write schema
        write_ontology(schema, stream)

        # Process CVE records
        cve_writer = CVEWriter(schema, stream)
        for input_dir in args.input_dirs:
            for json_file in walk(Path(input_dir), "CVE-*.json"):
                cve_writer.process_record(json_file)

    log.close()
    log.info("Ontology written to %s", output_path)
