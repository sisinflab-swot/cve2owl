from functools import partial
from pathlib import Path

from cve2owl.core.abox import JsonAboxMapper, ObjectHook
from cve2owl.core.jsonio import read_json_record
from cve2owl.core.sink import AxiomSink

from .vocab import CVE, ENUM_KEYS, RECORD_CLASS


class CveWriter:
    def __init__(
        self,
        sink: AxiomSink,
        *,
        on_object: ObjectHook | None = None,
    ) -> None:
        self.sink = sink
        ref_keys = {
            key: partial(CVE.enum_individual, enum_type) for key, enum_type in ENUM_KEYS.items()
        }
        self.mapper = JsonAboxMapper(CVE, sink, ref_keys=ref_keys, on_object=on_object)
        self.record_class = CVE.cls(RECORD_CLASS)

    def process_record(self, record: Path) -> None:
        with read_json_record(record) as data:
            ind = self.mapper.individual(data, record.stem)
            self.sink.write(ind.is_a(self.record_class))
