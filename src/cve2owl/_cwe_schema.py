import json
from pathlib import Path
from typing import Any

import cowl

from ._json import JSONValue
from ._log import logger as log
from ._schema import UnresolvedRefError, process_definition

CWE_ONTOLOGY_IRI = "https://swot.sisinflab.poliba.it/cwe"

IGNORE = {
    "Ancestors",
    "Children",
    "CWEInfo",
    "CWEVersion",
    "Descendants",
    "Node",
    "Parents",
}

# Guards against $refs that can never be resolved
MAX_PASSES = 10


def rewrite_refs(node: JSONValue) -> None:
    # OpenAPI refs (#/components/schemas/X) to the JSON Schema form expected by resolve_ref().
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "$ref" and isinstance(value, str):
                node[key] = value.replace("#/components/schemas/", "#/definitions/")
            else:
                rewrite_refs(value)
    elif isinstance(node, list):
        for item in node:
            rewrite_refs(item)


def cwe_schema_to_ontology(spec: dict[str, Any]) -> cowl.Ontology:
    onto = cowl.Ontology()
    onto.set_iri(CWE_ONTOLOGY_IRI, update_prefix=True)

    definitions = spec["components"]["schemas"]
    rewrite_refs(definitions)

    passes = 0
    should_continue = True
    while should_continue:
        passes += 1
        if passes > MAX_PASSES:
            msg = f"the $ref resolution loop did not converge in {MAX_PASSES} passes"
            raise RuntimeError(msg)

        should_continue = False
        for name, def_schema in definitions.items():
            if name in IGNORE:
                continue
            try:
                process_definition(onto, name, def_schema)
            except UnresolvedRefError:
                should_continue = True

    return onto


def cwe_schema_path_to_ontology(schema_path: Path) -> cowl.Ontology:
    log.begin_record(schema_path)

    with schema_path.open(encoding="utf-8") as f:
        spec = json.load(f)
        log.mark_json_parsed()
        return cwe_schema_to_ontology(spec)
