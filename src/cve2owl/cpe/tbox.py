from typing import Any

import cowl

from cve2owl.core.naming import Namespace
from cve2owl.core.tbox import SchemaTranslator, hoist_definition

CPE = Namespace("cpe", "https://swot.sisinflab.poliba.it/cpe")

CPE_NAME_CLASS = "CpeName"


def cpe_tbox(schema: dict[str, Any]) -> cowl.Ontology:
    # The product schema is inlined in defCpe: hoist it so that it becomes the CpeName class.
    hoist_definition(schema, ["definitions", "defCpe", "properties", "cpe"], CPE_NAME_CLASS)
    return SchemaTranslator(CPE).translate(schema["definitions"])
