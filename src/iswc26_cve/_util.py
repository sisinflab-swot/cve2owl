import cowl

type JSONObject = dict[str, AnyJSONValue]
type AnyJSONValue = JSONObject | list[AnyJSONValue] | str | int | float | bool | None


def cap_first(string: str) -> str:
    return string[0].upper() + string[1:] if string else string


def to_camel_case(string: str) -> str:
    return "".join(cap_first(x.lower() if x.isupper() else x) for x in string.split("_"))


def add_unique_axiom(onto: cowl.Ontology, axiom: cowl.Axiom) -> None:
    if axiom not in onto:
        onto.add(axiom)
