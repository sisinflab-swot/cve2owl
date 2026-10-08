from typing import Any

import cowl

from cve2owl.core.tbox import SchemaTranslator, enum_as_class, hoist_definition

from .vocab import CVE, ENUM_TYPES, IGNORE, RECORD_CLASS

# Inline in the metrics schema, each with its own definitions.
CVSS_VERSIONS = ["cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"]


def cve_tbox(schema: dict[str, Any]) -> cowl.Ontology:
    definitions = schema["definitions"]

    for version in CVSS_VERSIONS:
        hoist_definition(
            schema,
            ["definitions", "metrics", "items", "properties", version],
            version,
        )

    translator = SchemaTranslator(
        CVE,
        overrides=dict.fromkeys(ENUM_TYPES, enum_as_class),
        ignore=IGNORE,
    )
    return translator.translate(
        {RECORD_CLASS: schema},
        definitions,
        *(definitions[version]["definitions"] for version in CVSS_VERSIONS),
    )
