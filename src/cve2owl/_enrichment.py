import cowl

from ._cpe_uri import FIELD_NAMES
from ._cve_links import CPE_LINK, CWE_LINK, PLATFORM_LINK
from ._log import logger as log
from ._owl import owl_data_property
from ._schema import write

LINK_PROPERTIES = [CPE_LINK, CWE_LINK, PLATFORM_LINK]


def write_enrichment(
    cve_onto: cowl.Ontology,
    cpe_onto: cowl.Ontology,
    stream: cowl.StreamWriter,
) -> None:
    count = 0
    written = 0

    for name in LINK_PROPERTIES:
        written += write(stream, cowl.Declaration(cve_onto.ObjectProperty(name)))
        count += 1

    for field_name in FIELD_NAMES:
        written += write(stream, cowl.Declaration(owl_data_property(cpe_onto, field_name)))
        count += 1

    # Not a record, as there is no input file, but the axioms still count towards the totals.
    log.mark_extra_axioms(count, written)
    log.info("  %d properties declared by the enrichment module", count)
