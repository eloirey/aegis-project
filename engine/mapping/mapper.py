"""
engine.mapping.mapper
---------------------
Loads a scenario's mapping.yaml and attaches its ENS / NIS2 / CIS controls to a finding.
This is the layer that turns a raw event into compliance-aware context.
"""
import os
from functools import lru_cache
from pathlib import Path

import yaml

# Locally the mapping lives in the scenario folder; inside a Lambda the file is bundled
# with the function and pointed to by MAPPING_PATH.
SCENARIOS_ROOT = Path(__file__).resolve().parents[2] / "scenarios"


def _resolve_path(scenario):
    env = os.environ.get("MAPPING_PATH")
    if env:
        return Path(env)
    if scenario:
        return SCENARIOS_ROOT / scenario / "mapping.yaml"
    raise ValueError("set MAPPING_PATH or pass a scenario folder name")


@lru_cache(maxsize=None)
def load_mapping(scenario=None) -> dict:
    """Load and cache mapping.yaml for a scenario folder name (or MAPPING_PATH)."""
    with open(_resolve_path(scenario), encoding="utf-8") as f:
        return yaml.safe_load(f)


def _control_ids(compliance, framework):
    return [c["id"] for c in compliance.get(framework, [])]


def enrich(finding: dict, scenario=None) -> dict:
    """Attach severity, MITRE techniques and the control mapping to a finding."""
    mapping = load_mapping(scenario)
    compliance = mapping.get("compliance", {})
    finding["severity"] = mapping.get("severity")
    finding["mitre_attack"] = mapping.get("mitre_attack", [])
    finding["controls"] = {
        "ens": _control_ids(compliance, "ens"),
        "nis2": _control_ids(compliance, "nis2"),
        "cis_aws": _control_ids(compliance, "cis_aws"),
    }
    return finding