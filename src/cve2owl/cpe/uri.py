from dataclasses import dataclass
from functools import cached_property

from cve2owl.core.utils import or_none

ANY = "ANY"  # "*"
NA = "NA"  # "-"

FIELD_NAMES = [
    "part",
    "vendor",
    "product",
    "version",
    "update",
    "edition",
    "language",
    "sw_edition",
    "target_sw",
    "target_hw",
    "other",
]

CPE22_FIELD_NAMES = [
    "part",
    "vendor",
    "product",
    "version",
    "update",
    "edition",
    "language",
]


class CpeParseError(Exception):
    pass


@dataclass
class CpeComponents:
    part: str
    vendor: str
    product: str
    version: str
    update: str
    edition: str
    language: str
    sw_edition: str
    target_sw: str
    target_hw: str
    other: str

    def as_dict(self) -> dict[str, str]:
        return {name: getattr(self, name) for name in FIELD_NAMES}

    @cached_property
    def individual_name(self) -> str:
        # Built from the parsed fields, so 2.2 and 2.3 names of the same product match. Example:
        # cpe:2.3:o:tenda:w9_firmware:1.0.0.7\(4456\)_cn:*:*:*:*:*:*:*
        # -> cpe~o~tenda~w9_firmware~1.0.0.7%284456%29_cn
        components = self.as_dict()
        values = [components[field_name] for field_name in FIELD_NAMES]

        while len(values) > 1 and values[-1] == ANY:
            values.pop()

        name = "cpe"
        for value in values:
            name = name + SEPARATOR + field_to_name(value)
        return name


def make_components(values: dict[str, str]) -> CpeComponents:
    return CpeComponents(
        part=values["part"],
        vendor=values["vendor"],
        product=values["product"],
        version=values["version"],
        update=values["update"],
        edition=values["edition"],
        language=values["language"],
        sw_edition=values["sw_edition"],
        target_sw=values["target_sw"],
        target_hw=values["target_hw"],
        other=values["other"],
    )


def split_cpe_string(cpe_string: str) -> list[str]:
    parts: list[str] = []
    current = ""
    i = 0
    while i < len(cpe_string):
        char = cpe_string[i]

        if char == "\\" and i + 1 < len(cpe_string):
            current = current + char + cpe_string[i + 1]
            i = i + 2
            continue

        if char == ":":
            parts.append(current)
            current = ""
            i += 1
            continue

        current = current + char
        i += 1

    parts.append(current)
    return parts


def remove_escaping(field: str) -> str:
    result = ""
    i = 0
    while i < len(field):
        char = field[i]
        if char == "\\" and i + 1 < len(field):
            result = result + field[i + 1]
            i = i + 2
        else:
            result = result + char
            i += 1
    return result


def decode_field(raw_value: str) -> str:
    if raw_value == "*":
        return ANY
    if raw_value == "-":
        return NA
    return remove_escaping(raw_value)


def parse_cpe23(cpe_string: str) -> CpeComponents:
    parts = split_cpe_string(cpe_string)

    if len(parts) != 13:  # "cpe" + "2.3" + 11 fields
        msg = f"expected 13 fields separated by ':', found {len(parts)}: {cpe_string}"
        raise CpeParseError(msg)

    if parts[0] != "cpe" or parts[1] != "2.3":
        msg = f"not a CPE 2.3 string (should start with 'cpe:2.3:'): {cpe_string}"
        raise CpeParseError(msg)

    values = {name: decode_field(parts[i + 2]) for i, name in enumerate(FIELD_NAMES)}

    return make_components(values)


def parse_cpe22(cpe_string: str) -> CpeComponents:
    # CPE 2.2 URIs, like "cpe:/a:redhat:acm:2", have at most seven fields: the missing ones are ANY.
    if "~" in cpe_string or "%" in cpe_string:
        # Packed editions ("~a~b~c~d~e") and percent-encoding are unused in the dataset.
        msg = f"CPE 2.2 URI written in a form we do not read: {cpe_string}"
        raise CpeParseError(msg)

    raw_values = cpe_string.removeprefix("cpe:/").split(":")

    values = dict.fromkeys(FIELD_NAMES, ANY)
    for i in range(len(CPE22_FIELD_NAMES)):
        if i < len(raw_values) and raw_values[i] != "":
            values[CPE22_FIELD_NAMES[i]] = decode_field(raw_values[i])

    if values["part"] not in ("a", "h", "o"):
        msg = f"not a CPE 2.2 URI (the part should be 'a', 'h' or 'o'): {cpe_string}"
        raise CpeParseError(msg)

    return make_components(values)


def parse_cpe(cpe_string: str) -> CpeComponents:
    # CVE records use both forms: ADP entries often use 2.2 URIs, match criteria use 2.3.
    if cpe_string.startswith("cpe:/"):
        return parse_cpe22(cpe_string)
    return parse_cpe23(cpe_string)


# For CPE strings from the data, which are not always valid.
try_parse_cpe = or_none(parse_cpe, CpeParseError)

# Characters kept as-is in individual names, the others are percent-encoded.
NAME_CHARACTERS = "abcdefghijklmnopqrstuvwxyz0123456789._-"

# Not in NAME_CHARACTERS, so it never occurs within a field and names cannot collide.
SEPARATOR = "~"


def field_to_name(value: str) -> str:
    # Lowercased so that e.g. "Apache" and "apache" map to the same individual.
    if value == ANY:
        return ""
    if value == NA:
        return "-"
    if value == "-":
        return "%2d"  # A literal "-" ("\-" in the CPE string), distinct from NA
    result = ""
    for char in value.lower():
        if char in NAME_CHARACTERS:
            result = result + char
        else:
            for byte in char.encode("utf-8"):
                result = result + f"%{byte:02x}"
    return result
