import json
from collections.abc import Callable, Generator, Iterator
from contextlib import contextmanager
from fnmatch import fnmatch
from pathlib import Path
from typing import Any, overload

from .log import logger as log

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


def walk(path: Path, pattern: str = "*") -> Iterator[Path]:
    for root, dirs, files in path.walk():
        dirs.sort()
        files.sort()
        for f in files:
            if fnmatch(f, pattern) if pattern else True:
                yield root / f


@contextmanager
def read_json_record(path: Path) -> Generator[Any]:
    with log.begin_record(path):
        with path.open(encoding="utf-8") as f:
            data = json.load(f)
        log.mark_json_parsed()
        yield data
