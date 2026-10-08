import json
from pathlib import Path
from typing import Any

import cowl

from ._log import logger as log
from ._schema import UnresolvedRefError, process_definition

CPE_ONTOLOGY_IRI = "https://swot.sisinflab.poliba.it/cpe"


def cpe_schema_to_ontology(schema: dict[str, Any]) -> cowl.Ontology:
    onto = cowl.Ontology()
    onto.set_iri(CPE_ONTOLOGY_IRI, update_prefix=True)

    # The product schema is inlined in defCpe: hoist it so that it becomes the CpeName class.
    cpe_name_schema = schema["definitions"]["defCpe"]["properties"]["cpe"]
    schema["definitions"]["CpeName"] = cpe_name_schema
    schema["definitions"]["defCpe"]["properties"]["cpe"] = {"$ref": "#/definitions/CpeName"}

    should_continue = True
    while should_continue:
        should_continue = False
        for name, def_schema in schema["definitions"].items():
            try:
                process_definition(onto, name, def_schema)
            except UnresolvedRefError:
                should_continue = True

    return onto


def cpe_schema_path_to_ontology(schema_path: Path) -> cowl.Ontology:
    log.begin_record(schema_path)

    with schema_path.open(encoding="utf-8") as f:
        json_schema = json.load(f)
        log.mark_json_parsed()
        return cpe_schema_to_ontology(json_schema)
