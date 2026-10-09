from functools import cache

import cowl


# Creates entities whose IRIs are the namespace plus the given name, which is used as is.
# The owl_* helpers below apply the naming conventions.
class Namespace:
    def __init__(self, prefix: str, iri: str) -> None:
        self.prefix = prefix
        self.iri = iri
        self.namespace = iri + "#"
        self._factory = prefix_map(self)
        self._classes: dict[str, cowl.Class] = {}
        self._datatypes: dict[str, cowl.Datatype] = {}
        self._object_properties: dict[str, cowl.ObjectProperty] = {}
        self._data_properties: dict[str, cowl.DataProperty] = {}

    def _iri(self, name: str) -> str:
        return f"{self.prefix}:{name}"

    def cls(self, name: str) -> cowl.Class:
        if (entity := self._classes.get(name)) is None:
            entity = self._classes[name] = self._factory.Class(self._iri(name))
        return entity

    def datatype(self, name: str) -> cowl.Datatype:
        if (entity := self._datatypes.get(name)) is None:
            entity = self._datatypes[name] = self._factory.Datatype(self._iri(name))
        return entity

    def object_property(self, name: str) -> cowl.ObjectProperty:
        if (entity := self._object_properties.get(name)) is None:
            entity = self._object_properties[name] = self._factory.ObjectProperty(self._iri(name))
        return entity

    def data_property(self, name: str) -> cowl.DataProperty:
        if (entity := self._data_properties.get(name)) is None:
            entity = self._data_properties[name] = self._factory.DataProperty(self._iri(name))
        return entity

    def individual(self, name: str) -> cowl.NamedIndividual:
        return self._factory.NamedIndividual(self._iri(name))


def prefix_map(*namespaces: Namespace) -> cowl.PrefixMap:
    # The pycowl 0.1.2 stub does not declare PrefixMap's Mapping methods, so it looks abstract.
    pm = cowl.PrefixMap()  # pyright: ignore[reportAbstractUsage]
    for ns in namespaces:
        pm[ns.prefix] = ns.namespace
    return pm


def cap_first(string: str) -> str:
    return string[0].upper() + string[1:] if string else string


def to_camel_case(string: str) -> str:
    return "".join(cap_first(x.lower() if x.isupper() else x) for x in string.split("_"))


# Cached, as it is called for every value written: only pass names from a bounded set.
@cache
def owl_name(name: str, owl_type: type) -> str:
    name = name.replace(" ", "_")
    if owl_type in (cowl.Class, cowl.Datatype):
        name = name.removesuffix("Type")
    if owl_type != cowl.Datatype:
        name = to_camel_case(name)
    if owl_type in (cowl.ObjectProperty, cowl.DataProperty):
        name = "has" + name
    return name


def owl_class(ns: Namespace, name: str) -> cowl.Class:
    return ns.cls(owl_name(name, cowl.Class))


def owl_datatype(ns: Namespace, name: str) -> cowl.Datatype:
    return ns.datatype(owl_name(name, cowl.Datatype))


def owl_object_property(ns: Namespace, name: str) -> cowl.ObjectProperty:
    return ns.object_property(owl_name(name, cowl.ObjectProperty))


def owl_data_property(ns: Namespace, name: str) -> cowl.DataProperty:
    return ns.data_property(owl_name(name, cowl.DataProperty))


def enum_individual(ns: Namespace, type_name: str, value: str) -> cowl.NamedIndividual:
    return ns.individual(owl_name(type_name, cowl.Class) + owl_name(value, cowl.Individual))
