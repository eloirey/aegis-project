import boto3
import pytest
from moto import mock_aws

from engine.store import findings

TABLE = "aegis-project-findings-test"


@pytest.fixture
def table(monkeypatch):
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="eu-west-1")
        ddb.create_table(
            TableName=TABLE,
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        # Point the module at the mocked table and reset its lazy client.
        monkeypatch.setattr(findings, "TABLE_NAME", TABLE)
        monkeypatch.setattr(findings, "TABLE_REGION", "eu-west-1")
        monkeypatch.setattr(findings, "_table", None)
        yield ddb.Table(TABLE)


def _finding():
    return {
        "id": "evt-abc-123",
        "finding_id": "EXPOSED_SSH",
        "resource": "sg-0123456789",
        "actor": "arn:aws:iam::232261469288:user/aegis-lab-admin",
        "action": "AuthorizeSecurityGroupIngress",
        "severity": "HIGH",
        "controls": {"ens": ["mp.com.4"], "nis2": ["21.2.d"], "cis_aws": ["5.2"]},
        "mitre_attack": ["T1190"],
    }


def test_detection_writes_a_detected_row(table):
    findings.record_detection(_finding())

    item = table.get_item(Key={"id": "evt-abc-123"})["Item"]
    assert item["status"] == "detected"
    assert "detected_at" in item
    assert "expires_at" in item
    assert item["controls"]["ens"] == ["mp.com.4"]


def test_remediation_flips_status_and_keeps_detection(table):
    findings.record_detection(_finding())
    findings.record_remediation({"id": "evt-abc-123"})

    item = table.get_item(Key={"id": "evt-abc-123"})["Item"]
    assert item["status"] == "remediated"
    assert "remediated_at" in item
    assert "detected_at" in item  # detection data survives the update