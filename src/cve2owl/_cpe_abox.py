import json
from pathlib import Path

import cowl

from ._cpe_uri import ANY, FIELD_NAMES, NA, cpe_individual_name, parse_cpe
from ._cve import CVEWriter
from ._log import logger as log
from ._owl import escape_literal, owl_data_property, owl_name


class CpeWriter(CVEWriter):
    def __init__(self, factory: cowl.PrimitiveFactory, writer: cowl.StreamWriter) -> None:
        super().__init__(factory, writer)
        self.cpe_class = factory.Class("CpeName")
        # Individual name -> CPE string, for CPEs mentioned by CVE records.
        self.described: dict[str, str] = {}

    def process_record(self, record: Path) -> None:
        with log.begin_record(record), record.open(encoding="utf-8") as f:
            data = json.load(f)
            log.mark_json_parsed()

            cpe_string = data["cpeName"]
            name = cpe_individual_name(cpe_string)
            ind = self.factory.NamedIndividual(name)

            # No need to track: each dictionary record is read only once.
            self.describe(ind, cpe_string, track=False)

            for key, value in data.items():
                if key == "cpeName":
                    continue
                for v in self._process_value(value, f"{name}_{owl_name(key, cowl.Individual)}"):
                    self._write_property_assertion(ind, key, v)

    def describe(self, ind: cowl.Individual, cpe_string: str, *, track: bool = True) -> None:
        # The same CPE can occur in the dictionary and in many CVE records: describe it once.
        name = cpe_individual_name(cpe_string)
        if name in self.described:
            return
        if track:
            self.described[name] = cpe_string

        self._write_cpe_fields(ind, cpe_string)
        self._write_property_assertion(ind, "cpeName", cowl.Literal(escape_literal(cpe_string)))
        self._write(ind.is_a(self.cpe_class))

    def _write_cpe_fields(self, ind: cowl.Individual, cpe_string: str) -> None:
        components = parse_cpe(cpe_string)
        values = components.as_dict()
        for field_name in FIELD_NAMES:
            value = values[field_name]
            if value in (ANY, NA):
                continue
            literal = cowl.Literal(escape_literal(value))
            self._write(owl_data_property(self.factory, field_name)(ind, literal))
