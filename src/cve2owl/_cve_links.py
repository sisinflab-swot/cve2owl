import cowl

from ._cpe_abox import CpeWriter
from ._cpe_uri import CpeParseError, cpe_individual_name
from ._cve import CVEWriter
from ._cwe_abox import CWEWriter, cwe_individual_name
from ._json import JSONObject, JSONValue

# "criteria" holds a CPE string, "cpes" a list of them.
CPE_KEYS = {"criteria", "cpes"}

CWE_KEY = "cweId"

# No "has" prefix, so they cannot clash with properties derived from JSON keys (e.g. the "CWE" key
# in x_osv becomes hasCwe).
CPE_LINK = "vulnerableCpe"
CWE_LINK = "cwe"
# Criteria with "vulnerable": false denote the platform (e.g. the OS), not the vulnerable product.
PLATFORM_LINK = "platformCpe"


def _cpe_strings(value: JSONValue) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, str)]
    return []


# Also links CVE records to the CPE and CWE individuals they mention.
class CveLinksWriter(CVEWriter):
    def __init__(
        self,
        factory: cowl.PrimitiveFactory,
        writer: cowl.StreamWriter,
        cpe_writer: CpeWriter,
        cwe_writer: CWEWriter,
    ) -> None:
        super().__init__(factory, writer)
        self.cpe_writer = cpe_writer
        self.cwe_writer = cwe_writer

    def _write_link(
        self,
        subject: cowl.Individual,
        link_name: str,
        target: cowl.Individual,
    ) -> None:
        # Not owl_name(), which would add the "has" prefix.
        link = self.factory.ObjectProperty(link_name)
        self._write(link(subject, target))

    def _process_object(self, obj: JSONObject, name: str) -> cowl.Individual:
        ind = super()._process_object(obj, name)
        for key, value in obj.items():
            if key in CPE_KEYS:
                link_name = CPE_LINK
                if obj.get("vulnerable") is False:
                    link_name = PLATFORM_LINK
                for cpe_string in _cpe_strings(value):
                    try:
                        cpe_name = cpe_individual_name(cpe_string)
                    except CpeParseError:
                        continue
                    # Created by the CPE factory, so the IRI matches the dictionary's.
                    cpe_ind = self.cpe_writer.factory.NamedIndividual(cpe_name)
                    self._write_link(ind, link_name, cpe_ind)
                    self.cpe_writer.describe(cpe_ind, cpe_string)

            elif key == CWE_KEY:
                # Not "weakness": the target can also be a category or a view.
                if isinstance(value, str) and value.startswith("CWE-"):
                    cwe_name = cwe_individual_name(value)
                    cwe_ind = self.cwe_writer.factory.NamedIndividual(cwe_name)
                    self._write_link(ind, CWE_LINK, cwe_ind)
        return ind
