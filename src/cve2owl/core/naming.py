from collections.abc import Callable

import cowl


class _EntityCache[E]:
    def __init__(self, factory: Callable[[str], E], owl_type: type) -> None:
        self._factory = factory
        self._owl_type = owl_type
        self._normalized: dict[str, E] = {}
        self._raw: dict[str, E] = {}

    def get(self, name: str, *, raw: bool) -> E:
        cache = self._raw if raw else self._normalized
        if (entity := cache.get(name)) is None:
            iri_name = name if raw else owl_name(name, self._owl_type)
            entity = cache[name] = self._factory(iri_name)
        return entity


class Namespace:
    def __init__(self, prefix: str, iri: str) -> None:
        self.prefix = prefix
        self.iri = iri
        self.namespace = iri + "#"
        self._factory = factory = prefix_map(self)
        self._classes = _EntityCache(lambda n: factory.Class(self._iri(n)), cowl.Class)
        self._datatypes = _EntityCache(lambda n: factory.Datatype(self._iri(n)), cowl.Datatype)
        self._object_properties = _EntityCache(
            lambda n: factory.ObjectProperty(self._iri(n)),
            cowl.ObjectProperty,
        )
        self._data_properties = _EntityCache(
            lambda n: factory.DataProperty(self._iri(n)),
            cowl.DataProperty,
        )

    def _iri(self, name: str) -> str:
        return f"{self.prefix}:{name}"

    def cls(self, name: str, *, raw: bool = False) -> cowl.Class:
        return self._classes.get(name, raw=raw)

    def datatype(self, name: str, *, raw: bool = False) -> cowl.Datatype:
        return self._datatypes.get(name, raw=raw)

    def object_property(self, name: str, *, raw: bool = False) -> cowl.ObjectProperty:
        return self._object_properties.get(name, raw=raw)

    def data_property(self, name: str, *, raw: bool = False) -> cowl.DataProperty:
        return self._data_properties.get(name, raw=raw)

    def individual(self, name: str) -> cowl.NamedIndividual:
        return self._factory.NamedIndividual(self._iri(name))

    def enum_individual(self, type_name: str, value: str) -> cowl.NamedIndividual:
        name = owl_name(type_name, cowl.Class) + owl_name(value, cowl.Individual)
        return self.individual(name)


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


def owl_name(name: str, owl_type: type) -> str:
    name = name.replace(" ", "_")
    if owl_type in (cowl.Class, cowl.Datatype):
        name = name.removesuffix("Type")
    if owl_type != cowl.Datatype:
        name = to_camel_case(name)
    if owl_type in (cowl.ObjectProperty, cowl.DataProperty):
        name = "has" + name
    return name
