import cowl

from cve2owl.core.jsonio import JSONObject, JSONValue
from cve2owl.core.sink import AxiomSink
from cve2owl.cpe.abox import CpeWriter
from cve2owl.cpe.uri import CpeParseError, parse_cpe
from cve2owl.cwe.abox import CweWriter

from .vocab import CVE

# "criteria" holds a CPE string, "cpes" a list of them.
CPE_KEYS = {"criteria", "cpes"}

CWE_KEY = "cweId"

# No "has" prefix, so they cannot clash with properties derived from JSON keys
# (e.g. the "CWE" key in x_osv becomes hasCwe).
CPE_LINK = "vulnerableCpe"
CWE_LINK = "cwe"
# Criteria with "vulnerable": false denote the platform (e.g. the OS), not the vulnerable product.
PLATFORM_LINK = "platformCpe"

LINK_PROPERTIES = [CPE_LINK, CWE_LINK, PLATFORM_LINK]


def _cpe_strings(value: JSONValue) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, str)]
    return []


def link_declarations() -> list[cowl.Axiom]:
    return [cowl.Declaration(CVE.object_property(name, raw=True)) for name in LINK_PROPERTIES]


# Object hook that links CVE records to the CPE and CWE individuals they mention.
class CveLinker:
    def __init__(
        self,
        sink: AxiomSink,
        cpe: CpeWriter,
        cwe: CweWriter,
    ) -> None:
        self.sink = sink
        self.cpe = cpe
        self.cwe = cwe

    def __call__(self, obj: JSONObject, ind: cowl.NamedIndividual) -> None:
        for key, value in obj.items():
            if key in CPE_KEYS:
                link_name = CPE_LINK
                if obj.get("vulnerable") is False:
                    link_name = PLATFORM_LINK
                for cpe_string in _cpe_strings(value):
                    try:
                        cpe = parse_cpe(cpe_string)
                    except CpeParseError:
                        continue
                    cpe_ind = self.cpe.individual(cpe)
                    self._write_link(ind, link_name, cpe_ind)
                    self.cpe.describe(cpe_ind, cpe_string, cpe)

            elif key == CWE_KEY:
                # Not "weakness": the target can also be a category or a view.
                if isinstance(value, str) and value.startswith("CWE-"):
                    self._write_link(ind, CWE_LINK, self.cwe.individual(value))

    def _write_link(
        self,
        subject: cowl.Individual,
        link_name: str,
        target: cowl.Individual,
    ) -> None:
        link = CVE.object_property(link_name, raw=True)
        self.sink.write(link(subject, target))
