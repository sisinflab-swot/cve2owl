from pathlib import Path

import cowl

from cve2owl.core.abox import JsonAboxMapper
from cve2owl.core.jsonio import read_json_record
from cve2owl.core.sink import AxiomSink

from .tbox import CWE

# Catalogue subfolder -> class of its entries
DIRECTORIES = [
    ("weaknesses", "Weakness"),
    ("categories", "Category"),
    ("views", "View"),
]


def cwe_individual_name(cwe_id: str) -> str:
    # The catalogue uses "79", CVE records "CWE-79": both map to the same individual.
    number = cwe_id.removeprefix("CWE-")
    return "Cwe" + number


class CweWriter:
    def __init__(self, sink: AxiomSink) -> None:
        self.sink = sink
        self.mapper = JsonAboxMapper(CWE, sink)

    def individual(self, cwe_id: str) -> cowl.NamedIndividual:
        return CWE.individual(cwe_individual_name(cwe_id))

    def process_record(self, record: Path, class_name: str) -> None:
        with read_json_record(record) as data:
            name = cwe_individual_name(data["ID"])
            ind = CWE.individual(name)
            self.mapper.assert_properties(ind, data, name)
            self.sink.write(ind.is_a(CWE.cls(class_name)))
