import json
from collections.abc import Iterator
from pathlib import Path
from typing import cast

import cowl

from ._json import JSONObject, JSONValue
from ._owl import escape_literal, owl_data_property, owl_name, owl_object_property

type IndividualOrLiteral = cowl.Individual | cowl.Literal


_INDIVIDUAL_OVERRIDES: dict[str, str] = {
    "accessVector": "accessVectorType",
    "accessComplexity": "accessComplexityType",
    "attackComplexity": "attackComplexityType",
    "attackRequirements": "attackRequirementsType",
    "attackVector": "attackVectorType",
    "authentication": "authenticationType",
    "Automatable": "automatableType",
    "availabilityImpact": "ciaType",
    "availabilityRequirement": "ciaRequirementType",
    "baseSeverity": "severityType",
    "confidentialityImpact": "ciaType",
    "confidentialityRequirement": "ciaRequirementType",
    "environmentalSeverity": "severityType",
    "exploitability": "exploitabilityType",
    "collateralDamagePotential": "collateralDamagePotentialType",
    "targetDistribution": "targetDistributionType",
    "exploitCodeMaturity": "exploitCodeMaturityType",
    "exploitMaturity": "exploitMaturityType",
    "integrityImpact": "ciaType",
    "integrityRequirement": "ciaRequirementType",
    "modifiedAttackComplexity": "modifiedAttackComplexityType",
    "modifiedAttackRequirements": "modifiedAttackRequirementsType",
    "modifiedAttackVector": "modifiedAttackVectorType",
    "modifiedConfidentialityImpact": "modifiedCiaType",
    "modifiedIntegrityImpact": "modifiedCiaType",
    "modifiedAvailabilityImpact": "modifiedCiaType",
    "modifiedPrivilegesRequired": "modifiedPrivilegesRequiredType",
    "modifiedScope": "modifiedScopeType",
    "modifiedSubAvailabilityImpact": "modifiedSubIaType",
    "modifiedSubConfidentialityImpact": "modifiedSubCType",
    "modifiedSubIntegrityImpact": "modifiedSubIaType",
    "modifiedUserInteraction": "modifiedUserInteractionType",
    "modifiedVulnAvailabilityImpact": "modifiedVulnCiaType",
    "modifiedVulnConfidentialityImpact": "modifiedVulnCiaType",
    "modifiedVulnIntegrityImpact": "modifiedVulnCiaType",
    "privilegesRequired": "privilegesRequiredType",
    "providerUrgency": "providerUrgencyType",
    "remediationLevel": "remediationLevelType",
    "reportConfidence": "confidenceType",
    "Recovery": "recoveryType",
    "Safety": "safetyType",
    "scope": "scopeType",
    "subAvailabilityImpact": "subCiaType",
    "subConfidentialityImpact": "subCiaType",
    "subIntegrityImpact": "subCiaType",
    "temporalSeverity": "severityType",
    "userInteraction": "userInteractionType",
    "valueDensity": "valueDensityType",
    "vulnAvailabilityImpact": "vulnCiaType",
    "vulnConfidentialityImpact": "vulnCiaType",
    "vulnerabilityResponseEffort": "vulnerabilityResponseEffortType",
    "vulnIntegrityImpact": "vulnCiaType",
}


class CVEWriter:
    def __init__(self, factory: cowl.PrimitiveFactory, writer: cowl.StreamWriter) -> None:
        self.factory = factory
        self.writer = writer
        self.record_class = factory.Class("CveRecord")
        self.count = 0
        self.axiom_count = 0

    def process_record(self, record: Path) -> None:
        with record.open(encoding="utf-8") as f:
            name = record.stem
            ind = self._process_object(json.load(f), name)
            self._write(ind.is_a(self.record_class))
            self.count += 1

    def _write(self, axiom: cowl.Axiom) -> None:
        self.writer.write(axiom)
        self.axiom_count += 1

    def _process_object(self, obj: JSONObject, name: str) -> cowl.Individual:
        ind = self.factory.NamedIndividual(name)
        for key, value in obj.items():
            if (class_ := _INDIVIDUAL_OVERRIDES.get(key)) and isinstance(value, str):
                individual_value = self._value_to_individual_override(class_, value)
                self._write_property_assertion(ind, key, individual_value)
            else:
                for v in self._process_value(value, f"{name}_{owl_name(key, cowl.Individual)}"):
                    self._write_property_assertion(ind, key, v)
        return ind

    def _process_value(self, value: JSONValue, name: str) -> Iterator[IndividualOrLiteral]:
        if isinstance(value, str):
            yield cowl.Literal(escape_literal(value))
        elif isinstance(value, (int, bool)):
            yield cowl.Literal(value)
        elif isinstance(value, float):
            yield cowl.Literal(value, datatype=cowl.xsd.decimal)
        elif isinstance(value, list):
            if len(value) == 1:
                yield from self._process_value(value[0], name)
            else:
                for i, v in enumerate(value):
                    yield from self._process_value(v, f"{name}_{i}")
        elif isinstance(value, dict):
            yield self._process_object(cast("JSONObject", value), name)

    def _value_to_individual_override(self, class_: str, value: str) -> cowl.NamedIndividual:
        name = owl_name(class_, cowl.Class) + owl_name(value, cowl.Individual)
        return self.factory.NamedIndividual(name)

    def _write_property_assertion(
        self,
        subject: cowl.Individual,
        prop: str,
        obj: IndividualOrLiteral,
    ) -> None:
        if cowl.is_individual(obj):
            self._write(owl_object_property(self.factory, prop)(subject, obj))
        else:
            self._write(owl_data_property(self.factory, prop)(subject, obj))
