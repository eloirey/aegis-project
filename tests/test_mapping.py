"""Tests for the mapping engine."""
import pytest

from engine.mapping.mapper import enrich
from engine.notifier.notify import format_alert

CASES = [
    ("01-public-s3-bucket", "PUBLIC_S3_BUCKET"),
    ("02-overprivileged-iam", "PRIVILEGED_IAM"),
    ("03-exposed-ssh", "EXPOSED_SSH"),
]


@pytest.mark.parametrize("scenario,finding_id", CASES)
def test_enrich_attaches_controls(scenario, finding_id):
    finding = enrich({"finding_id": finding_id, "resource": "x"}, scenario=scenario)
    for framework in ("ens", "nis2", "cis_aws"):
        assert framework in finding["controls"]
        assert finding["controls"][framework], f"{framework} controls should not be empty"
    assert finding["severity"] == "HIGH"
    assert finding["mitre_attack"]


@pytest.mark.parametrize("scenario,finding_id", CASES)
def test_format_alert_carries_compliance(scenario, finding_id):
    finding = enrich(
        {"finding_id": finding_id, "resource": "r", "actor": "a", "action": "X"},
        scenario=scenario,
    )
    text = format_alert(finding)
    assert "ENS" in text and "NIS2" in text and "CIS AWS" in text
    assert "Severity: HIGH" in text