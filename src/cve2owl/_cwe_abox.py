import json
from pathlib import Path

import cowl

from ._cve import CVEWriter
from ._log import logger as log
from ._owl import owl_name

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


class CWEWriter(CVEWriter):
    def process_catalog_record(self, record: Path, class_name: str) -> None:
        with log.begin_record(record), record.open(encoding="utf-8") as f:
            data = json.load(f)
            log.mark_json_parsed()

            name = cwe_individual_name(data["ID"])
            ind = self.factory.NamedIndividual(name)

            for key, value in data.items():
                for v in self._process_value(value, f"{name}_{owl_name(key, cowl.Individual)}"):
                    self._write_property_assertion(ind, key, v)

            cwe_class = self.factory.Class(class_name)
            self._write(ind.is_a(cwe_class))
