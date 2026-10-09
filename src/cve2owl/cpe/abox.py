from pathlib import Path

import cowl

from cve2owl.core.abox import JsonAboxMapper
from cve2owl.core.jsonio import read_json_record
from cve2owl.core.naming import owl_data_property
from cve2owl.core.sink import AxiomSink

from .tbox import CPE, CPE_NAME_CLASS
from .uri import ANY, FIELD_NAMES, NA, CpeComponents, parse_cpe

NAME_KEY = "cpeName"


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
            self.sink.write(owl_data_property(CPE, field_name)(ind, literal))


def component_declarations() -> list[cowl.Axiom]:
    # Not in the CPE schema, which has the CPE string only.
    return [cowl.Declaration(owl_data_property(CPE, name)) for name in FIELD_NAMES]
