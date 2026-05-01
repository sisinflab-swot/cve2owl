import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

from ._cve import add_vulnerability
from ._schema import schema_to_ontology


def app() -> None:
    parser = argparse.ArgumentParser(
        description="Transforms the CVE data from cvelistV5 into an OWL ontology.",
    )
    parser.add_argument(
        "--schema-file",
        "-s",
        required=True,
        help="Path to the JSON Schema file defining the structure of the CVE data.",
    )
    parser.add_argument(
        "--input-dir",
        "-i",
        required=True,
        help="Path to the directory containing the CVE JSON files (cvelistV5).",
    )
    parser.add_argument(
        "--output-dir",
        "-o",
        default="output",
        help="Path to the directory where the OWL ontology will be saved.",
    )
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    with Path(args.schema_file).open(encoding="utf-8") as f:
        onto = schema_to_ontology(json.load(f))

    input_dir = Path(args.input_dir)
    for json_file in input_dir.rglob("*.json"):
        with json_file.open(encoding="utf-8") as f:
            add_vulnerability(onto, json_file.stem, json.load(f))

    timestamp = datetime.now(tz=UTC).strftime("%Y%m%d_%H%M%S")
    output_path = output_dir / f"iswc26_cve_{timestamp}.owl"
    onto.to_path(output_path)
