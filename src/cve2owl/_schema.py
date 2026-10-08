import json
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast, overload

import cowl

from ._json import JSONObject, get_as
from ._log import logger as log
from ._owl import (
    owl_class,
    owl_data_property,
    owl_datatype,
    owl_individual,
    owl_object_property,
)
from ._util import to_camel_case

type ExpressionOrRange = cowl.ClassExpression | cowl.DataRange


def add_unique_axiom(onto: cowl.Ontology, axiom: cowl.Axiom) -> None:
    if axiom not in onto:
        onto.add(axiom)


def override_enum_as_class(
    onto: cowl.Ontology,
    base_class_name: str,
    schema: JSONObject,
) -> ExpressionOrRange:
    if (enum := get_as(schema, "enum", list[str])) is None:
        msg = f"Expected 'enum' in schema: {schema}"
        raise ValueError(msg)

    base_class = owl_class(onto, base_class_name)
    base_class_name = base_class.remainder()
    individuals = [owl_individual(onto, base_class_name + to_camel_case(value)) for value in enum]

    for i in individuals:
        add_unique_axiom(onto, i.is_a(base_class))

    return cowl.one_of(*individuals)


TYPE_OVERRIDES: dict[str, Callable[[cowl.Ontology, str, JSONObject], ExpressionOrRange]] = {
    "accessComplexityType": override_enum_as_class,
    "accessVectorType": override_enum_as_class,
    "attackComplexityType": override_enum_as_class,
    "attackRequirementsType": override_enum_as_class,
    "attackVectorType": override_enum_as_class,
    "authenticationType": override_enum_as_class,
    "automatableType": override_enum_as_class,
    "ciaRequirementType": override_enum_as_class,
    "ciaType": override_enum_as_class,
    "collateralDamagePotentialType": override_enum_as_class,
    "confidenceType": override_enum_as_class,
    "exploitabilityType": override_enum_as_class,
    "exploitCodeMaturityType": override_enum_as_class,
    "exploitMaturityType": override_enum_as_class,
    "modifiedAttackComplexityType": override_enum_as_class,
    "modifiedAttackRequirementsType": override_enum_as_class,
    "modifiedAttackVectorType": override_enum_as_class,
    "modifiedCiaType": override_enum_as_class,
    "modifiedPrivilegesRequiredType": override_enum_as_class,
    "modifiedScopeType": override_enum_as_class,
    "modifiedSubCiaType": override_enum_as_class,
    "modifiedSubCType": override_enum_as_class,
    "modifiedSubIaType": override_enum_as_class,
    "modifiedUserInteractionType": override_enum_as_class,
    "modifiedVulnCiaType": override_enum_as_class,
    "privilegesRequiredType": override_enum_as_class,
    "providerUrgencyType": override_enum_as_class,
    "recoveryType": override_enum_as_class,
    "remediationLevelType": override_enum_as_class,
    "reportConfidenceType": override_enum_as_class,
    "safetyType": override_enum_as_class,
    "scopeType": override_enum_as_class,
    "severityType": override_enum_as_class,
    "subCiaType": override_enum_as_class,
    "targetDistributionType": override_enum_as_class,
    "userInteractionType": override_enum_as_class,
    "valueDensityType": override_enum_as_class,
    "vulnCiaType": override_enum_as_class,
    "vulnerabilityResponseEffortType": override_enum_as_class,
}


IGNORE: set[str] = {
    "noneSeverityType",
    "lowSeverityType",
    "mediumSeverityType",
    "highSeverityType",
    "criticalSeverityType",
}


class UnresolvedRefError(Exception):
    pass


def resolve_ref(onto: cowl.Ontology, ref: str) -> cowl.Class | cowl.Datatype:
    if (index := ref.rfind("/definitions/")) == -1:
        msg = f"Unsupported $ref format: {ref}"
        raise ValueError(msg)

    name = ref[index + len("/definitions/") :]

    if (cls := owl_class(onto, name)) in onto:
        return cls
    if (dt := owl_datatype(onto, name)) in onto:
        return dt

    msg = f"Unresolved $ref: {ref}"
    raise UnresolvedRefError(msg)


def type_expression(onto: cowl.Ontology, schema: JSONObject) -> ExpressionOrRange:
    match get_as(schema, "type", str):
        case "boolean":
            return cowl.xsd.boolean
        case "integer":
            return integer_restriction(schema)
        case "number":
            return number_restriction(schema)
        case "string":
            return string_restriction(schema)
        case "array":
            return array_restriction(onto, schema)
        case _:
            return object_restriction(onto, schema)


def bool_expression(onto: cowl.Ontology, schema: JSONObject) -> ExpressionOrRange:
    if all_of := get_as(schema, "allOf", list[JSONObject]):
        return intersection(*(owl_object(onto, item) for item in all_of))
    if any_of := get_as(schema, "anyOf", list[JSONObject]):
        return union(*(owl_object(onto, item) for item in any_of))
    if one_of := get_as(schema, "oneOf", list[JSONObject]):
        return union(*(owl_object(onto, item) for item in one_of))
    return cowl.owl.thing


def owl_object(onto: cowl.Ontology, schema: JSONObject) -> ExpressionOrRange:
    if ref := get_as(schema, "$ref", str):
        return resolve_ref(onto, ref)

    if (const := get_as(schema, "const", str)) is not None:
        return cowl.one_of(const)

    # TODO: handle mixed boolean and type expressions.
    if (type_expr := type_expression(onto, schema)) != cowl.owl.thing:
        return type_expr
    return bool_expression(onto, schema)


def integer_restriction(schema: JSONObject) -> cowl.DataRange:
    if enum := get_as(schema, "enum", list[int]):
        return cowl.one_of(*enum)
    if any(key in schema for key in ("minimum", "maximum")):
        return cowl.xsd.integer.that_has(
            value_ge=get_as(schema, "minimum", int),
            value_le=get_as(schema, "maximum", int),
        )
    return cowl.xsd.integer


def number_restriction(schema: JSONObject) -> cowl.DataRange:
    if enum := get_as(schema, "enum", list[float]):
        return cowl.one_of(*(cowl.xsd.decimal(v) for v in enum))
    if any(key in schema for key in ("minimum", "maximum")):
        return cowl.xsd.decimal.that_has(
            value_ge=get_as(schema, "minimum", float),
            value_le=get_as(schema, "maximum", float),
        )
    return cowl.xsd.decimal


def string_restriction(schema: JSONObject) -> ExpressionOrRange:
    if enum := get_as(schema, "enum", list[str]):
        return cowl.one_of(*enum)
    if const := get_as(schema, "const", str):
        return cowl.one_of(const)
    if any(key in schema for key in ("minLength", "maxLength", "pattern")):
        return cowl.xsd.string.that_has(
            min_length=get_as(schema, "minLength", int),
            max_length=get_as(schema, "maxLength", int),
            pattern=get_as(schema, "pattern", str),
        )
    return cowl.xsd.string


def array_restriction(
    onto: cowl.Ontology,
    schema: JSONObject,
) -> ExpressionOrRange:
    if items := get_as(schema, "items", JSONObject):
        return owl_object(onto, items)
    return cowl.owl.thing


def property_value_restriction(
    onto: cowl.Ontology,
    name: str,
    schema: JSONObject,
    *,
    min_: int = 0,
    max_: int | None = None,
) -> cowl.ClassExpression:
    filler = owl_object(onto, schema)
    operands: list[cowl.ClassExpression] = []

    if cowl.is_class_expression(filler):
        prop = owl_object_property(onto, name)
        if filler != cowl.owl.thing:
            operands.append(prop.only(filler))
    else:
        prop = owl_data_property(onto, name)
        operands.append(prop.only(filler))

    if min_ == max_:
        operands.append(prop.exactly(min_))
    else:
        if min_ > 0:
            operands.append(prop.min(min_))
        if max_ is not None:
            operands.append(prop.max(max_))

    return intersection(*operands)


def object_restriction(
    onto: cowl.Ontology,
    schema: JSONObject,
) -> ExpressionOrRange:
    if props := get_as(schema, "properties", dict[str, JSONObject]):
        return intersection(
            *(property_value_restriction(onto, pname, pschema) for pname, pschema in props.items()),
        )
    return cowl.owl.thing


@overload
def intersection(*exprs: cowl.ClassExpression) -> cowl.ClassExpression: ...


@overload
def intersection(*exprs: cowl.DataRange) -> cowl.DataRange: ...


@overload
def intersection(*exprs: ExpressionOrRange) -> ExpressionOrRange: ...


def intersection(*exprs: ExpressionOrRange) -> ExpressionOrRange:
    filtered = [e for e in exprs if e != cowl.owl.thing]
    if not filtered:
        return cowl.owl.thing
    if len(filtered) == 1:
        return filtered[0]
    return cowl.intersection_of(*cast("list[cowl.ClassExpression]", filtered))


def union(*exprs: ExpressionOrRange) -> ExpressionOrRange:
    if not exprs:
        return cowl.owl.thing
    if len(exprs) == 1:
        return exprs[0]
    return cowl.union_of(*cast("list[cowl.ClassExpression]", exprs))


def process_definition(onto: cowl.Ontology, name: str, schema: JSONObject) -> None:
    if name in IGNORE:
        return

    obj = o(onto, name, schema) if (o := TYPE_OVERRIDES.get(name)) else owl_object(onto, schema)

    if cowl.is_data_range(obj):
        add_unique_axiom(onto, owl_datatype(onto, name).is_defined_as(obj))
        return

    if not isinstance(obj, cowl.ObjectIntersectionOf):
        add_unique_axiom(onto, owl_class(onto, name).is_a(obj))
        return

    for operand in obj.operands():
        add_unique_axiom(onto, owl_class(onto, name).is_a(operand))


def schema_to_ontology(schema: dict[str, Any]) -> cowl.Ontology:
    onto = cowl.Ontology()
    onto.set_iri("https://swot.sisinflab.poliba.it/cve", update_prefix=True)

    cvssv40 = schema["definitions"]["metrics"]["items"]["properties"]["cvssV4_0"]
    cvssv31 = schema["definitions"]["metrics"]["items"]["properties"]["cvssV3_1"]
    cvssv30 = schema["definitions"]["metrics"]["items"]["properties"]["cvssV3_0"]
    cvssv20 = schema["definitions"]["metrics"]["items"]["properties"]["cvssV2_0"]

    schema["definitions"]["cvssV4_0"] = cvssv40
    schema["definitions"]["cvssV3_1"] = cvssv31
    schema["definitions"]["cvssV3_0"] = cvssv30
    schema["definitions"]["cvssV2_0"] = cvssv20

    schema["definitions"]["metrics"]["items"]["properties"]["cvssV4_0"] = {
        "$ref": "#/definitions/cvssV4_0",
    }
    schema["definitions"]["metrics"]["items"]["properties"]["cvssV3_1"] = {
        "$ref": "#/definitions/cvssV3_1",
    }
    schema["definitions"]["metrics"]["items"]["properties"]["cvssV3_0"] = {
        "$ref": "#/definitions/cvssV3_0",
    }
    schema["definitions"]["metrics"]["items"]["properties"]["cvssV2_0"] = {
        "$ref": "#/definitions/cvssV2_0",
    }

    schemas: list[dict[str, JSONObject]] = [
        {"CveRecord": schema},
        schema["definitions"],
        schema["definitions"]["cvssV4_0"]["definitions"],
        schema["definitions"]["cvssV3_1"]["definitions"],
        schema["definitions"]["cvssV3_0"]["definitions"],
        schema["definitions"]["cvssV2_0"]["definitions"],
    ]

    should_continue = True

    while should_continue:
        should_continue = False
        for s in schemas:
            for name, def_schema in s.items():
                try:
                    process_definition(onto, name, def_schema)
                except UnresolvedRefError:
                    should_continue = True

    return onto


def schema_path_to_ontology(schema_path: Path) -> cowl.Ontology:
    log.begin_record(schema_path)

    with schema_path.open(encoding="utf-8") as f:
        json_schema = json.load(f)
        log.mark_json_parsed()
        return schema_to_ontology(json_schema)


def write(writer: cowl.StreamWriter, construct: cowl.Axiom | cowl.Header) -> int:
    cur_written = writer.written_bytes
    writer.write(construct)
    return writer.written_bytes - cur_written


def write_ontology(onto: cowl.Ontology, stream: cowl.StreamWriter) -> None:
    log.mark_written(write(stream, cowl.Header.from_ontology(onto)))
    for axiom in onto.axioms():
        log.mark_axiom_written(write(stream, axiom))
    log.end_record()
