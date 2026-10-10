from collections.abc import Callable, Iterator, Mapping, Set as AbstractSet
from functools import cache
from typing import cast

import cowl

from .jsonio import JSONObject, JSONValue
from .naming import Namespace, owl_name
from .sink import AxiomSink

type IndividualOrLiteral = cowl.Individual | cowl.Literal

# Maps a string value (an ID, an enum value) to the individual it refers to.
type IndividualMapper = Callable[[str], cowl.NamedIndividual]

# Called after the properties of each object have been written.
type ObjectHook = Callable[[JSONObject, cowl.NamedIndividual], None]


@cache
def _key_name(key: str) -> str:
    return owl_name(key, cowl.Individual)


class JsonAboxMapper:
    def __init__(
        self,
        ns: Namespace,
        sink: AxiomSink,
        *,
        key_mappers: Mapping[str, IndividualMapper] | None = None,
        on_object: ObjectHook | None = None,
    ) -> None:
        self.ns = ns
        self.sink = sink
        self.key_mappers = key_mappers or {}  # JSON key -> mapper of its string values
        self.on_object = on_object

    def individual(self, obj: JSONObject, name: str) -> cowl.NamedIndividual:
        ind = self.ns.individual(name)
        self.assert_properties(ind, obj, name)
        return ind

    def assert_properties(
        self,
        ind: cowl.NamedIndividual,
        obj: JSONObject,
        name: str,
        *,
        exclude: AbstractSet[str] = frozenset(),
    ) -> None:
        for key, value in obj.items():
            if key in exclude:
                continue
            if (mapper := self.key_mappers.get(key)) and isinstance(value, str):
                self.assert_value(ind, key, mapper(value))
            else:
                for v in self.values(value, f"{name}_{_key_name(key)}"):
                    self.assert_value(ind, key, v)
        if self.on_object:
            self.on_object(obj, ind)

    def values(self, value: JSONValue, name: str) -> Iterator[IndividualOrLiteral]:
        if isinstance(value, (str, int, bool)):
            yield cowl.Literal(value)
        elif isinstance(value, float):
            yield cowl.Literal(value, datatype=cowl.xsd.decimal)
        elif isinstance(value, list):
            if len(value) == 1:
                yield from self.values(value[0], name)
            else:
                for i, v in enumerate(value):
                    yield from self.values(v, f"{name}_{i}")
        elif isinstance(value, dict):
            yield self.individual(cast("JSONObject", value), name)

    def assert_value(self, subject: cowl.Individual, prop: str, obj: IndividualOrLiteral) -> None:
        if cowl.is_individual(obj):
            self.sink.write(self.ns.object_property(prop)(subject, obj))
        else:
            self.sink.write(self.ns.data_property(prop)(subject, obj))
