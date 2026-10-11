from collections.abc import Iterator
from pathlib import Path

import cowl

from cve2owl.core.abox import JsonAboxMapper
from cve2owl.core.jsonio import JSONObject, get_as, read_json_record
from cve2owl.core.sink import AxiomSink
from cve2owl.core.utils import unique

from .tbox import CPE, CPE_NAME_CLASS
from .uri import ANY, FIELD_NAMES, NA, CpeComponents, CpeParseError, parse_cpe

NAME_KEY = "cpeName"
DEPRECATED_BY_KEY = "deprecatedBy"
DEPRECATES_KEY = "deprecates"


class CpeWriter:
    def __init__(self, sink: AxiomSink) -> None:
        self.sink = sink
        self.mapper = JsonAboxMapper(CPE, sink)
        self.cpe_class = CPE.cls(CPE_NAME_CLASS)
        # Individual name -> CPE string, for CPEs mentioned by CVE records.
        self.described: dict[str, str] = {}

    def individual(self, cpe: CpeComponents) -> cowl.NamedIndividual:
        return CPE.individual(cpe.individual_name)

    def process_record(self, record: Path) -> None:
        with read_json_record(record) as data:
            cpe_string = data[NAME_KEY]
            cpe = parse_cpe(cpe_string)
            ind = self.individual(cpe)

            # No need to track: each dictionary record is read only once.
            self.describe(ind, cpe_string, cpe, track=False)
            self.mapper.assert_properties(ind, data, cpe.individual_name, exclude={NAME_KEY})
            for key in (DEPRECATED_BY_KEY, DEPRECATES_KEY):
                self._write_links(ind, key, get_as(data, key, list[JSONObject]) or [])

    def _write_links(self, ind: cowl.Individual, key: str, entries: list[JSONObject]) -> None:
        link = CPE.object_property(key, raw=True)
        for cpe in unique(_parse_names(entries), key=lambda cpe: cpe.individual_name):
            self.sink.write(link(ind, self.individual(cpe)))

    def describe(
        self,
        ind: cowl.Individual,
        cpe_string: str,
        cpe: CpeComponents,
        *,
        track: bool = True,
    ) -> None:
        # The same CPE can occur in the dictionary and in many CVE records: describe it once.
        name = cpe.individual_name
        if name in self.described:
            return
        if track:
            self.described[name] = cpe_string

        self._write_cpe_fields(ind, cpe)
        self.mapper.assert_value(ind, NAME_KEY, cowl.Literal(cpe_string))
        self.sink.write(ind.is_a(self.cpe_class))

    def _write_cpe_fields(self, ind: cowl.Individual, cpe: CpeComponents) -> None:
        values = cpe.as_dict()
        for field_name in FIELD_NAMES:
            value = values[field_name]
            if value in (ANY, NA):
                continue
            literal = cowl.Literal(value)
            self.sink.write(CPE.data_property(field_name)(ind, literal))


def _parse_names(entries: list[JSONObject]) -> Iterator[CpeComponents]:
    for entry in entries:
        if (cpe_string := get_as(entry, NAME_KEY, str)) is None:
            continue
        try:
            yield parse_cpe(cpe_string)
        except CpeParseError:
            continue


def extra_axioms() -> list[cowl.Axiom]:
    deprecated_by = CPE.object_property(DEPRECATED_BY_KEY, raw=True)
    deprecates = CPE.object_property(DEPRECATES_KEY, raw=True)
    return [
        *(cowl.Declaration(CPE.data_property(name)) for name in FIELD_NAMES),
        deprecated_by.declare(),
        deprecates.declare(),
        deprecated_by.is_inverse_of(deprecates),
    ]
