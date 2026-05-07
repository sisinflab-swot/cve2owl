from collections.abc import Callable
from typing import Any, overload

type JSONValue = dict[str, JSONValue] | list[JSONValue] | str | int | float | bool | None
JSONObject = dict[str, "JSONValue"]


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
