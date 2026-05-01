from collections.abc import Iterator
from typing import Any, cast

import cowl

from ._json import JSONObject, JSONValue
from ._owl import owl_data_property, owl_object_property

type IndividualOrLiteral = cowl.Individual | cowl.Literal


def process_object(
    onto: cowl.Ontology,
    obj: JSONObject,
    name: str | None = None,
) -> cowl.Individual:
    ind = onto.Individual(name) if name else onto.Individual()
    for key, value in obj.items():
        for v in process_value(onto, value):
            add_property_assertion(onto, ind, key, v)
    return ind


def process_value(onto: cowl.Ontology, value: JSONValue) -> Iterator[IndividualOrLiteral]:
    if isinstance(value, (str, int, float, bool)):
        yield cowl.Literal(value)
    elif isinstance(value, list):
        for v in value:
            yield from process_value(onto, v)
    elif isinstance(value, dict):
        yield process_object(onto, cast("JSONObject", value))


def add_property_assertion(
    onto: cowl.Ontology,
    subject: cowl.Individual,
    prop: str,
    obj: IndividualOrLiteral,
) -> None:
    if cowl.is_individual(obj):
        onto.add(owl_object_property(onto, prop)(subject, obj))
    else:
        onto.add(owl_data_property(onto, prop)(subject, obj))


def add_vulnerability(onto: cowl.Ontology, cve_id: str, data: dict[str, Any]) -> None:
    ind = process_object(onto, data, cve_id)
    onto.add(ind.is_a(onto.Class("Vulnerability")))
