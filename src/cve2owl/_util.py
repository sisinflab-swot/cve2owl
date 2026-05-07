from collections.abc import Iterator
from fnmatch import fnmatch
from pathlib import Path

type JSONObject = dict[str, AnyJSONValue]
type AnyJSONValue = JSONObject | list[AnyJSONValue] | str | int | float | bool | None


def cap_first(string: str) -> str:
    return string[0].upper() + string[1:] if string else string


def to_camel_case(string: str) -> str:
    return "".join(cap_first(x.lower() if x.isupper() else x) for x in string.split("_"))


def walk(path: Path, pattern: str = "*") -> Iterator[Path]:
    for root, dirs, files in path.walk():
        dirs.sort()
        files.sort()
        for f in files:
            if fnmatch(f, pattern) if pattern else True:
                yield root / f
