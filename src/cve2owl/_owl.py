import cowl

from ._util import to_camel_case

LITERAL_TRANS_TABLE = str.maketrans({
    "\\": "\\\\",
    '"': '\\"',
})


NAME_OVERRIDES: dict[str, str] = {}


def escape_literal(literal: str) -> str:
    return literal.translate(LITERAL_TRANS_TABLE)


def owl_name(name: str, owl_type: type) -> str:
    if override_name := NAME_OVERRIDES.get(name):
        return override_name
    name = name.replace(" ", "_")
    if owl_type in (cowl.Class, cowl.Datatype):
        name = name.removesuffix("Type")
    if owl_type != cowl.Datatype:
        name = to_camel_case(name)
    if owl_type in (cowl.ObjectProperty, cowl.DataProperty):
        name = "has" + name
    return name


def owl_class(factory: cowl.PrimitiveFactory, name: str) -> cowl.Class:
    return factory.Class(owl_name(name, cowl.Class))


def owl_datatype(factory: cowl.PrimitiveFactory, name: str) -> cowl.Datatype:
    return factory.Datatype(owl_name(name, cowl.Datatype))


def owl_object_property(factory: cowl.PrimitiveFactory, name: str) -> cowl.ObjectProperty:
    return factory.ObjectProperty(owl_name(name, cowl.ObjectProperty))


def owl_data_property(factory: cowl.PrimitiveFactory, name: str) -> cowl.DataProperty:
    return factory.DataProperty(owl_name(name, cowl.DataProperty))


def owl_individual(factory: cowl.PrimitiveFactory, name: str) -> cowl.NamedIndividual:
    return factory.NamedIndividual(owl_name(name, cowl.NamedIndividual))
