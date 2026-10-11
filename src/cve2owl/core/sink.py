from collections.abc import Iterable

import cowl

from .log import logger as log
from .naming import Namespace, prefix_map


class AxiomSink:
    def __init__(self, stream: cowl.StreamWriter) -> None:
        self.stream = stream

    def _write(self, construct: cowl.Axiom | cowl.Header) -> int:
        cur_written = self.stream.written_bytes
        self.stream.write(construct)
        return self.stream.written_bytes - cur_written

    def write(self, axiom: cowl.Axiom) -> None:
        log.mark_axiom_written(self._write(axiom))

    def write_header(self, iri: str, namespaces: Iterable[Namespace]) -> None:
        header = cowl.Header(prefix_map=prefix_map(*namespaces), iri=iri)
        log.mark_written(self._write(header))

    def write_axioms(self, onto: cowl.Ontology) -> None:
        for axiom in onto.axioms():
            self.write(axiom)

    def write_extra(self, axioms: Iterable[cowl.Axiom]) -> int:
        count = 0
        written = 0
        for axiom in axioms:
            written += self._write(axiom)
            count += 1
        log.mark_extra_axioms(count, written)
        return count
