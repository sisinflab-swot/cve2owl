from collections.abc import Callable, Iterator, Mapping, Set as AbstractSet
from functools import cache
from typing import cast

import cowl

from .jsonio import JSONObject, JSONValue
from .naming import Namespace, owl_name
from .sink import AxiomSink

type IndividualOrLiteral = cowl.Individual | cowl.Literal

# Called after the properties of each object have been written.
type ObjectHook = Callable[[JSONObject, cowl.NamedIndividual], None]


@cache
def _key_name(key: str) -> str:
    return owl_name(key, cowl.Individual)


# Objects become named individuals (named after their parent and key, plus the index when a list
# has more than one element), scalars become literals.
class JsonAboxMapper:
    def __init__(
        self,
        ns: Namespace,
        sink: AxiomSink,
        *,
        enum_keys: Mapping[str, str] | None = None,
        on_object: ObjectHook | None = None,
    ) -> None:
        self.ns = ns
        self.sink = sink
        # JSON key -> enum type whose individuals replace the key's string values
        self.enum_keys = enum_keys or {}
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
            if (enum_type := self.enum_keys.get(key)) and isinstance(value, str):
                self.assert_value(ind, key, self.ns.enum_individual(enum_type, value))
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
