from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast, overload

import cowl

from ._util import add_unique_axiom, to_camel_case

if TYPE_CHECKING:
    from collections.abc import Callable

type JSONValue = dict[str, JSONValue] | list[JSONValue] | str | int | float | bool | None
type ExpressionOrRange = cowl.ClassExpression | cowl.DataRange
JSONObject = dict[str, "JSONValue"]

LITERAL_TRANS_TABLE = str.maketrans({
    "\\": "\\\\",
    '"': '\\"',
})


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

    add_unique_axiom(onto, cowl.all_different(*individuals))
    return cowl.one_of(*individuals)


TYPE_OVERRIDES: dict[str, Callable[[cowl.Ontology, str, JSONObject], ExpressionOrRange]] = {
    "attackVectorType": override_enum_as_class,
    "modifiedAttackVectorType": override_enum_as_class,
    "attackComplexityType": override_enum_as_class,
    "modifiedAttackComplexityType": override_enum_as_class,
    "attackRequirementsType": override_enum_as_class,
    "modifiedAttackRequirementsType": override_enum_as_class,
    "privilegesRequiredType": override_enum_as_class,
    "modifiedPrivilegesRequiredType": override_enum_as_class,
    "userInteractionType": override_enum_as_class,
    "modifiedUserInteractionType": override_enum_as_class,
    "vulnCiaType": override_enum_as_class,
    "modifiedVulnCiaType": override_enum_as_class,
    "subCiaType": override_enum_as_class,
    "modifiedSubCiaType": override_enum_as_class,
    "modifiedSubIaType": override_enum_as_class,
    "exploitMaturityType": override_enum_as_class,
    "ciaRequirementType": override_enum_as_class,
    "safetyType": override_enum_as_class,
    "automatableType": override_enum_as_class,
    "recoveryType": override_enum_as_class,
    "valueDensityType": override_enum_as_class,
    "vulnerabilityResponseEffortType": override_enum_as_class,
    "providerUrgencyType": override_enum_as_class,
    "severityType": override_enum_as_class,
    "scopeType": override_enum_as_class,
    "modifiedScopeType": override_enum_as_class,
    "ciaType": override_enum_as_class,
    "modifiedCiaType": override_enum_as_class,
    "exploitCodeMaturityType": override_enum_as_class,
    "remediationLevelType": override_enum_as_class,
    "confidenceType": override_enum_as_class,
    "accessVectorType": override_enum_as_class,
    "accessComplexityType": override_enum_as_class,
    "authenticationType": override_enum_as_class,
    "exploitabilityType": override_enum_as_class,
    "reportConfidenceType": override_enum_as_class,
    "collateralDamagePotentialType": override_enum_as_class,
    "targetDistributionType": override_enum_as_class,
    "modifiedSubCType": override_enum_as_class,
}


NAME_OVERRIDES: dict[str, str] = {}


IGNORE: set[str] = {
    "noneSeverityType",
    "lowSeverityType",
    "mediumSeverityType",
    "highSeverityType",
    "criticalSeverityType",
}


class UnresolvedRefError(Exception):
    pass


@overload
def get_as[T](
    schema: JSONObject,
    key: str,
    expected_type: Callable[[Any], T],
    default: None = None,
) -> T | None: ...


@overload
def get_as[T](
    schema: JSONObject,
    key: str,
    expected_type: Callable[[Any], T],
    default: T,
) -> T: ...


def get_as[T](
    schema: JSONObject,
    key: str,
    expected_type: Callable[[Any], T],
    default: T | None = None,
) -> T | None:
    return default if (value := schema.get(key)) is None else expected_type(value)


def escape_literal(literal: str) -> str:
    return literal.translate(LITERAL_TRANS_TABLE)


def to_owl_name(name: str, owl_type: type) -> str:
    if override_name := NAME_OVERRIDES.get(name):
        return override_name
    if owl_type in (cowl.Class, cowl.Datatype):
        name = name.removesuffix("Type")
    if owl_type != cowl.Datatype:
        name = to_camel_case(name)
    if owl_type in (cowl.ObjectProperty, cowl.DataProperty):
        name = "has" + name
    return name


def owl_class(onto: cowl.Ontology, name: str) -> cowl.Class:
    return onto.Class(to_owl_name(name, cowl.Class))


def owl_datatype(onto: cowl.Ontology, name: str) -> cowl.Datatype:
    return onto.Datatype(to_owl_name(name, cowl.Datatype))


def owl_object_property(onto: cowl.Ontology, name: str) -> cowl.ObjectProperty:
    return onto.ObjectProperty(to_owl_name(name, cowl.ObjectProperty))


def owl_data_property(onto: cowl.Ontology, name: str) -> cowl.DataProperty:
    return onto.DataProperty(to_owl_name(name, cowl.DataProperty))


def owl_individual(onto: cowl.Ontology, name: str) -> cowl.NamedIndividual:
    return onto.NamedIndividual(to_owl_name(name, cowl.NamedIndividual))


def schema_to_ontology(schema: dict[str, Any]) -> cowl.Ontology:
    onto = cowl.Ontology()
    onto.set_iri("http://swot.sisinflab.poliba.it/cvelist", update_prefix=True)

    schemas: list[JSONObject] = [
        schema,
        schema["definitions"]["metrics"]["items"]["properties"]["cvssV4_0"],
        schema["definitions"]["metrics"]["items"]["properties"]["cvssV3_1"],
        schema["definitions"]["metrics"]["items"]["properties"]["cvssV3_0"],
        schema["definitions"]["metrics"]["items"]["properties"]["cvssV2_0"],
    ]

    should_continue = True

    while should_continue:
        should_continue = False
        for s in schemas:
            for name, def_schema in get_as(s, "definitions", dict[str, JSONObject], {}).items():
                try:
                    process_definition(onto, name, def_schema)
                except UnresolvedRefError:
                    should_continue = True

    return onto


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


def owl_object(onto: cowl.Ontology, schema: JSONObject) -> ExpressionOrRange:
    if ref := get_as(schema, "$ref", str):
        return resolve_ref(onto, ref)
    match get_as(schema, "type", str, "object"):
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
        case "object":
            return object_restriction(onto, schema)
        case _:
            msg = f"Unsupported type: {schema.get('type')}, schema: {schema}"
            raise ValueError(msg)


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
            pattern=get_as(schema, "pattern", escape_literal),
        )
    return cowl.xsd.string


def array_restriction(
    onto: cowl.Ontology,
    schema: JSONObject,
) -> ExpressionOrRange:
    if not (items := get_as(schema, "items", JSONObject)):
        return cowl.owl.thing

    if len(items) == 1 and (one_of := get_as(items, "oneOf", list[JSONObject])):
        objs = [owl_object(onto, item) for item in one_of]
        return cowl.union_of(*cast("list[cowl.ClassExpression]", objs))  # Suppress warning.

    return owl_object(onto, items)


def property_restriction(
    onto: cowl.Ontology,
    name: str,
    schema: JSONObject,
    *,
    min_: int = 0,
    max_: int | None = None,
) -> cowl.ClassExpression:
    filler = owl_object(onto, schema)

    if cowl.is_class_expression(filler):
        prop = owl_object_property(onto, name)
        restr = prop.only(filler)
    else:
        prop = owl_data_property(onto, name)
        restr = prop.only(filler)

    if min_ == max_:
        return restr & prop.exactly(min_)

    if min_ > 0:
        restr &= prop.min(min_)
    if max_ is not None:
        restr &= prop.max(max_)

    return restr


def intersection(*exprs: cowl.ClassExpression) -> cowl.ClassExpression:
    if not exprs:
        return cowl.owl.thing
    if len(exprs) == 1:
        return exprs[0]
    args: list[cowl.ClassExpression] = []
    for expr in exprs:
        if isinstance(expr, cowl.ObjectIntersectionOf):
            args.extend(expr.operands())
        else:
            args.append(expr)
    return cowl.ObjectIntersectionOf(*args)


def object_restriction(onto: cowl.Ontology, schema: JSONObject) -> ExpressionOrRange:
    if (const := get_as(schema, "const", str)) is not None:
        return cowl.one_of(const)

    required_props = get_as(schema, "required", list[str], default=[])
    if properties := get_as(schema, "properties", dict[str, JSONObject]):
        restrs = [
            property_restriction(onto, pname, pschema, min_=1 if pname in required_props else 0)
            for pname, pschema in properties.items()
        ]
        return intersection(*restrs)

    return cowl.owl.thing


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
