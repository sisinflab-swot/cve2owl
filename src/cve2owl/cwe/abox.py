import re
from pathlib import Path

import cowl

from cve2owl.core.abox import IndividualMapper, JsonAboxMapper
from cve2owl.core.jsonio import JSONObject, get_as, read_json_record
from cve2owl.core.sink import AxiomSink
from cve2owl.core.utils import not_none, unique

from .tbox import CWE, REF_KEYS

# Catalogue subfolder -> class of its entries
DIRECTORIES = [
    ("weaknesses", "Weakness"),
    ("categories", "Category"),
    ("views", "View"),
]

CHILD_OF_LINK = "childOf"  # Direct parent links
DESCENDANT_OF_LINK = "descendantOf"  # Transitive super-property
HIERARCHY_VIEW = "1000"

OBSERVED_EXAMPLE_LINK = "observedExample"
CVE_ID_REGEX = re.compile(r"CVE-[0-9]{4}-[0-9]{4,19}")


def cwe_individual_name(cwe_id: str) -> str:
    # The catalogue uses "79", CVE records "CWE-79": both map to the same individual.
    number = cwe_id.removeprefix("CWE-")
    return "Cwe" + number


class CweWriter:
    def __init__(self, sink: AxiomSink, cve_mapper: IndividualMapper) -> None:
        self.sink = sink
        self.cve_mapper = cve_mapper
        key_mappers = dict.fromkeys(REF_KEYS, self.individual)
        self.mapper = JsonAboxMapper(CWE, sink, key_mappers=key_mappers)

    def individual(self, cwe_id: str) -> cowl.NamedIndividual:
        return CWE.individual(cwe_individual_name(cwe_id))

    def process_record(self, record: Path, class_name: str) -> None:
        with read_json_record(record) as data:
            name = cwe_individual_name(data["ID"])
            ind = CWE.individual(name)
            self.mapper.assert_properties(ind, data, name)
            self.sink.write(ind.is_a(CWE.cls(class_name)))
            self._write_parents(ind, data)
            self._write_observed_examples(ind, data)

    def _write_parents(self, ind: cowl.NamedIndividual, data: JSONObject) -> None:
        child_of = CWE.object_property(CHILD_OF_LINK, raw=True)
        for related in get_as(data, "RelatedWeaknesses", list[JSONObject]) or []:
            if related.get("Nature") == "ChildOf" and related.get("ViewID") == HIERARCHY_VIEW:
                parent = get_as(related, "CweID", str)
                if parent is not None:
                    self.sink.write(child_of(ind, self.individual(parent)))

    def _write_observed_examples(self, ind: cowl.NamedIndividual, data: JSONObject) -> None:
        observed_example = CWE.object_property(OBSERVED_EXAMPLE_LINK, raw=True)
        examples = get_as(data, "ObservedExamples", list[JSONObject]) or []
        references = (get_as(example, "Reference", str) for example in examples)
        for reference in unique(not_none(references)):
            if CVE_ID_REGEX.fullmatch(reference):
                self.sink.write(observed_example(ind, self.cve_mapper(reference)))


def extra_axioms() -> list[cowl.Axiom]:
    child_of = CWE.object_property(CHILD_OF_LINK, raw=True)
    descendant_of = CWE.object_property(DESCENDANT_OF_LINK, raw=True)
    return [
        child_of.declare(),
        descendant_of.declare(),
        child_of.is_subproperty_of(descendant_of),
        descendant_of.is_transitive(),
        CWE.object_property(OBSERVED_EXAMPLE_LINK, raw=True).declare(),
    ]
