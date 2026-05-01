from collections.abc import Iterator
from typing import Any, cast

import cowl

from ._json import JSONObject, JSONValue
from ._owl import escape_literal, owl_data_property, owl_name, owl_object_property

type IndividualOrLiteral = cowl.Individual | cowl.Literal


INDIVIDUAL_OVERRIDES: dict[str, str] = {
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


def property_name_to_owl(prop: str, base: str) -> str:
    return f"{base}_{owl_name(prop, cowl.Individual)}"


def value_to_individual_override(
    onto: cowl.Ontology,
    class_: str,
    value: str,
) -> cowl.NamedIndividual:
    return onto.NamedIndividual(owl_name(class_, cowl.Class) + owl_name(value, cowl.Individual))


def process_object(
    onto: cowl.Ontology,
    obj: JSONObject,
    name: str,
) -> cowl.Individual:
    ind = onto.Individual(name)
    for key, value in obj.items():
        if (class_ := INDIVIDUAL_OVERRIDES.get(key)) and isinstance(value, str):
            individual_value = value_to_individual_override(onto, class_, value)
            add_property_assertion(onto, ind, key, individual_value)
        else:
            for v in process_value(onto, value, property_name_to_owl(key, name)):
                add_property_assertion(onto, ind, key, v)
    return ind


def process_value(
    onto: cowl.Ontology,
    value: JSONValue,
    name: str,
) -> Iterator[IndividualOrLiteral]:
    if isinstance(value, str):
        if value in INDIVIDUAL_OVERRIDES:
            yield onto.Individual(owl_name(value, cowl.Individual))
        yield cowl.Literal(escape_literal(value))
    elif isinstance(value, (int, bool)):
        yield cowl.Literal(value)
    elif isinstance(value, float):
        yield cowl.Literal(value, datatype=cowl.xsd.decimal)
    elif isinstance(value, list):
        if len(value) == 1:
            yield from process_value(onto, value[0], name)
        else:
            for i, v in enumerate(value):
                yield from process_value(onto, v, f"{name}_{i}")
    elif isinstance(value, dict):
        yield process_object(onto, cast("JSONObject", value), name)


def add_property_assertion(
    onto: cowl.Ontology,
    subject: cowl.Individual,
    prop: str,
    obj: IndividualOrLiteral,
) -> None:
    if cowl.is_individual(obj):
        onto.add(owl_object_property(onto, prop)(subject, obj))
    else:
        onto.add(owl_data_property(onto, prop)(subject, obj))


def add_vulnerability(onto: cowl.Ontology, cve_id: str, data: dict[str, Any]) -> None:
    ind = process_object(onto, data, cve_id)
    onto.add(ind.is_a(onto.Class("CveRecord")))
