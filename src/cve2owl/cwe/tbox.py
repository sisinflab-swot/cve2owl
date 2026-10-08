from typing import Any

import cowl

from cve2owl.core.naming import Namespace
from cve2owl.core.tbox import SchemaTranslator, rewrite_openapi_refs

CWE = Namespace("cwe", "https://swot.sisinflab.poliba.it/cwe")

IGNORE = frozenset({
    "Ancestors",
    "Children",
    "CWEInfo",
    "CWEVersion",
    "Descendants",
    "Node",
    "Parents",
})


def cwe_tbox(spec: dict[str, Any]) -> cowl.Ontology:
    definitions = spec["components"]["schemas"]
    rewrite_openapi_refs(definitions)
    return SchemaTranslator(CWE, ignore=IGNORE).translate(definitions)
