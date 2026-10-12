from typing import Any

import cowl

from cve2owl.core.jsonio import JSONObject
from cve2owl.core.naming import Namespace
from cve2owl.core.tbox import SchemaTranslator, rewrite_openapi_refs, rewrite_properties

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

# Data keys holding the ID of a CWE entry -> name of the property linking to the entry itself.
DATA_RENAMED_KEYS = {"CweID": "Cwe", "ViewID": "View"}

# Schema also has "CWE_ID" and "View_ID", where the data has "CweID" and "ViewID".
RENAMED_KEYS = {"CWE_ID": "Cwe", "View_ID": "View", **DATA_RENAMED_KEYS}

# Keys of the properties linking to CWE entries -> classes of the entries they can refer to.
# Their values are mapped to the entry individuals instead of literals.
REF_KEYS = {
    "Cwe": ["Weakness", "Category", "View"],
    "View": ["View"],
}


def _ref_schema(class_names: list[str]) -> JSONObject:
    return {"anyOf": [{"$ref": f"#/definitions/{name}"} for name in class_names]}


def cwe_tbox(spec: dict[str, Any]) -> cowl.Ontology:
    definitions = spec["components"]["schemas"]
    rewrite_openapi_refs(definitions)

    # Schema has category IDs as integers and no mapping notes for categories and views.
    # Data has string IDs and mapping notes for every entry.
    weakness = definitions["Weakness"]["properties"]
    for name in ("Category", "View"):
        properties = definitions[name]["properties"]
        properties["ID"] = weakness["ID"]
        properties["MappingNotes"] = weakness["MappingNotes"]

    rewrite_properties(
        definitions,
        rename=RENAMED_KEYS,
        schemas={key: _ref_schema(names) for key, names in REF_KEYS.items()},
    )

    translator = SchemaTranslator(CWE, ignore=IGNORE)
    # Entries refer to each other through REF_KEYS: declaring the targets up front breaks the
    # cycle, as a $ref only resolves to classes already in the ontology.
    for name in sorted({name for names in REF_KEYS.values() for name in names}):
        translator.add(cowl.Declaration(CWE.cls(name)))
    return translator.translate(definitions)
