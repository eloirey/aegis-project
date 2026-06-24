"""
engine.mapping.mapper
---------------------
Loads a scenario's `mapping.yaml` and attaches the ENS / NIS2 / CIS controls to a finding.
This is the layer that turns a raw event into compliance-aware context — the project's
signature feature.

SKELETON — implement the TODOs.
"""

from pathlib import Path

# When running inside a Lambda you'll bundle the relevant mapping.yaml with the function;
# locally you can resolve it from the scenario folder.
SCENARIOS_ROOT = Path(__file__).resolve().parents[2] / "scenarios"


def load_mapping(scenario: str) -> dict:
    """Load mapping.yaml for a given scenario folder name."""
    # TODO: read SCENARIOS_ROOT / scenario / "mapping.yaml" and parse it with PyYAML.
    #       Return the parsed dict. Cache it if you like.
    raise NotImplementedError("TODO: load and parse mapping.yaml")


def enrich(finding: dict, scenario: str) -> dict:
    """Return the finding with its compliance controls attached."""
    # TODO: mapping = load_mapping(scenario)
    #       finding["severity"] = mapping["severity"]
    #       finding["mitre_attack"] = mapping["mitre_attack"]
    #       finding["controls"] = mapping["controls"]
    #       return finding
    raise NotImplementedError("TODO: enrich finding with controls")
