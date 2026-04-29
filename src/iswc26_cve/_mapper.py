from collections.abc import Callable
from typing import Any, overload

import cowl

JSONObject = dict[str, "JSONObject"]


LITERAL_TRANS_TABLE = str.maketrans({
    "\\": "\\\\",
    '"': '\\"',
})


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


def schema_to_ontology(schema: JSONObject) -> cowl.Ontology:
    onto = cowl.Ontology()
    onto.set_iri("http://swot.sisinflab.poliba.it/cvelist", update_prefix=True)

    schemas: list[Any] = [
        schema,
        schema["definitions"]["metrics"]["items"]["properties"]["cvssV2_0"],
        schema["definitions"]["metrics"]["items"]["properties"]["cvssV3_0"],
        schema["definitions"]["metrics"]["items"]["properties"]["cvssV3_1"],
        schema["definitions"]["metrics"]["items"]["properties"]["cvssV4_0"],
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
    if (cls := onto.Class(name)) in onto:
        return cls
    if (dt := onto.Datatype(name)) in onto:
        return dt

    msg = f"Unresolved $ref: {ref}"
    raise UnresolvedRefError(msg)


def owl_object(onto: cowl.Ontology, schema: JSONObject) -> cowl.ClassExpression | cowl.DataRange:
    if ref := get_as(schema, "$ref", str):
        return resolve_ref(onto, ref)
    match get_as(schema, "type", str, "object"):
        case "boolean":
            return cowl.XSD.boolean
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
        return cowl.XSD.integer.that_has(
            value_ge=get_as(schema, "minimum", int),
            value_le=get_as(schema, "maximum", int),
        )
    return cowl.XSD.integer


def number_restriction(schema: JSONObject) -> cowl.DataRange:
    if enum := get_as(schema, "enum", list[float]):
        return cowl.one_of(*(cowl.XSD.decimal(v) for v in enum))
    if any(key in schema for key in ("minimum", "maximum")):
        return cowl.XSD.decimal.that_has(
            value_ge=get_as(schema, "minimum", float),
            value_le=get_as(schema, "maximum", float),
        )
    return cowl.XSD.decimal


def string_restriction(schema: JSONObject) -> cowl.DataRange:
    if enum := get_as(schema, "enum", list[str]):
        return cowl.one_of(*enum)
    if const := get_as(schema, "const", str):
        return cowl.one_of(const)
    if any(key in schema for key in ("minLength", "maxLength", "pattern")):
        return cowl.XSD.string.that_has(
            min_length=get_as(schema, "minLength", int),
            max_length=get_as(schema, "maxLength", int),
            pattern=get_as(schema, "pattern", escape_literal),
        )
    return cowl.XSD.string


def array_restriction(
    onto: cowl.Ontology,
    schema: JSONObject,
) -> cowl.ClassExpression | cowl.DataRange:
    if not (items := get_as(schema, "items", JSONObject)):
        return cowl.owl.thing

    if len(items) == 1 and (one_of := get_as(items, "oneOf", list[JSONObject])):
        objects = [owl_object(onto, item) for item in one_of]
        if all(obj.is_class_expression() for obj in objects):
            return cowl.ObjectUnionOf(*objects)
        return cowl.DataUnionOf(*objects)

    return owl_object(onto, items)


def property_restriction(
    onto: cowl.Ontology,
    name: str,
    schema: JSONObject,
    *,
    min_: int = 0,
    max_: int | None = None,
) -> cowl.ClassExpression:
    name = f"has{name.capitalize()}"
    filler = owl_object(onto, schema)
    prop = onto.ObjectProperty(name) if filler.is_class_expression() else onto.DataProperty(name)
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


def object_restriction(onto: cowl.Ontology, schema: JSONObject) -> cowl.ClassExpression:
    required_props = get_as(schema, "required", list[str], default=[])
    if properties := get_as(schema, "properties", dict[str, JSONObject]):
        restrs = [
            property_restriction(onto, pname, pschema, min_=1 if pname in required_props else 0)
            for pname, pschema in properties.items()
        ]
        return intersection(*restrs)
    return cowl.owl.thing


def add_unique(onto: cowl.Ontology, axiom: cowl.Axiom) -> None:
    if axiom not in onto:
        onto.add(axiom)


def process_definition(onto: cowl.Ontology, name: str, schema: JSONObject) -> None:
    obj = owl_object(onto, schema)
    if obj.is_class_expression():
        if isinstance(obj, cowl.ObjectIntersectionOf):
            for operand in obj.operands():
                add_unique(onto, onto.Class(name).is_subclass_of(operand))
        else:
            add_unique(onto, onto.Class(name).is_subclass_of(obj))
    elif obj.is_data_range():
        add_unique(onto, onto.Datatype(name).is_defined_as(obj))
    else:
        msg = f"Unsupported definition type for '{name}': {obj}"
        raise ValueError(msg)
