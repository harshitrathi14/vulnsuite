"""Per-tenant cloud account bindings: a tenant can only scan or discover the
accounts bound to it, and every cloud subprocess runs under that account's
own credential rather than the worker's ambient identity."""
from __future__ import annotations

import asyncio
import json
from uuid import uuid4

import pytest
from pydantic import ValidationError

from vulnsuite.core.cloud_accounts import (
    CloudAccessError,
    CloudBinding,
    CloudProvider,
    authorize,
    azure_env,
    gcp_env,
    scoped_env,
)

AWS = CloudBinding(
    provider="aws", account_id="123456789012", display_name="payments-prod",
    credentials={"role_arn": "arn:aws:iam::123456789012:role/VulnSuiteAudit", "external_id": "tenant-a-7f3"},
)
AWS2 = CloudBinding(
    provider="aws", account_id="210987654321",
    credentials={"role_arn": "arn:aws:iam::210987654321:role/VulnSuiteAudit"},
)
GCP = CloudBinding(
    provider="gcp", account_id="payments-prod",
    credentials={"credentials_file": "/run/secrets/gcp/payments-prod.json"},
)
AZURE_SUB = "6f1d2c3b-4a5e-4f60-9b71-82c3d4e5f607"
AZ = CloudBinding(provider="azure", account_id=AZURE_SUB, credentials={"secret_env_prefix": "TENANT_A"})


# ---------- binding validation ----------

@pytest.mark.parametrize(
    "kwargs, reason",
    [
        (dict(provider="aws", account_id="123456789012", credentials={}), "role_arn"),
        (dict(provider="aws", account_id="123456789012",
              credentials={"role_arn": "arn:aws:iam::999999999999:role/X"}), "belong to account_id"),
        (dict(provider="aws", account_id="12345", credentials={"role_arn": "arn:aws:iam::123456789012:role/X"}), "12-digit"),
        (dict(provider="gcp", account_id="payments-prod", credentials={}), "credentials_file"),
        (dict(provider="gcp", account_id="payments-prod",
              credentials={"credentials_file": "../../etc/shadow"}), "parent-directory"),
        (dict(provider="azure", account_id="not-a-uuid", credentials={"secret_env_prefix": "T"}), "subscription UUID"),
        (dict(provider="azure", account_id=AZURE_SUB, credentials={"secret_env_prefix": "tenant a"}), "secret_env_prefix"),
    ],
)
def test_binding_rejects_malformed_references(kwargs, reason) -> None:
    with pytest.raises(ValidationError, match=reason):
        CloudBinding(**kwargs)


@pytest.mark.parametrize("key", ["client_secret", "secret_access_key", "private_key", "Password"])
def test_binding_refuses_to_store_secrets(key) -> None:
    with pytest.raises(ValidationError, match="not secrets"):
        CloudBinding(provider="azure", account_id=AZURE_SUB,
                     credentials={"secret_env_prefix": "T", key: "hunter2"})


# ---------- authorization ----------

def test_authorize_returns_requested_subset_in_order() -> None:
    out = authorize([GCP, AWS2, AWS], CloudProvider.AWS, ["210987654321", "123456789012"])
    assert [b.account_id for b in out] == ["210987654321", "123456789012"]


def test_authorize_rejects_unbound_account_by_name() -> None:
    with pytest.raises(CloudAccessError, match=r"\['999999999999'\]"):
        authorize([AWS], CloudProvider.AWS, ["123456789012", "999999999999"])


def test_authorize_never_widens_to_everything_on_empty_request() -> None:
    with pytest.raises(CloudAccessError, match="no account requested"):
        authorize([AWS], "aws", [])


def test_authorize_none_means_all_bound_for_that_provider_only() -> None:
    assert authorize([AWS, AZ, GCP], CloudProvider.AZURE, None) == [AZ]
    with pytest.raises(CloudAccessError, match="no azure accounts"):
        authorize([AWS, GCP], CloudProvider.AZURE, None)


def test_binding_for_another_provider_does_not_satisfy_request() -> None:
    with pytest.raises(CloudAccessError):
        authorize([AWS], CloudProvider.GCP, ["payments-prod"])


# ---------- credential materialisation ----------

def test_azure_env_reads_prefixed_variables() -> None:
    env = azure_env(AZ, {
        "TENANT_A_AZURE_CLIENT_ID": "cid", "TENANT_A_AZURE_CLIENT_SECRET": "s3cret",
        "TENANT_A_AZURE_TENANT_ID": "tid", "AZURE_CLIENT_ID": "ambient",
    })
    assert env == {
        "AZURE_CLIENT_ID": "cid", "AZURE_CLIENT_SECRET": "s3cret",
        "AZURE_TENANT_ID": "tid", "AZURE_SUBSCRIPTION_ID": AZURE_SUB,
    }


def test_azure_env_fails_closed_when_secret_missing() -> None:
    with pytest.raises(CloudAccessError, match="TENANT_A_AZURE_CLIENT_SECRET"):
        azure_env(AZ, {"TENANT_A_AZURE_CLIENT_ID": "cid", "TENANT_A_AZURE_TENANT_ID": "tid"})


def test_scoped_env_strips_ambient_credentials() -> None:
    base = {
        "PATH": "/usr/bin", "AZURE_CLIENT_ID": "ambient", "AZURE_SUBSCRIPTION_ID": "ambient-sub",
        "AZURE_STORAGE_KEY": "ambient", "AWS_ACCESS_KEY_ID": "aws-ambient",
    }
    env = scoped_env("azure", {"AZURE_CLIENT_ID": "tenant"}, base)
    assert env["PATH"] == "/usr/bin"
    assert env["AZURE_CLIENT_ID"] == "tenant"
    assert "AZURE_SUBSCRIPTION_ID" not in env and "AZURE_STORAGE_KEY" not in env
    assert env["AWS_ACCESS_KEY_ID"] == "aws-ambient"     # other providers untouched

    env = scoped_env("gcp", gcp_env(GCP), {"GOOGLE_APPLICATION_CREDENTIALS": "/worker/sa.json"})
    assert env["GOOGLE_APPLICATION_CREDENTIALS"] == "/run/secrets/gcp/payments-prod.json"
    assert env["CLOUDSDK_CORE_PROJECT"] == "payments-prod"


# ---------- collectors run under the binding's credential ----------

class _Captured(Exception):
    def __init__(self, cmd, kwargs):
        self.cmd, self.kwargs = cmd, kwargs


def _capture(monkeypatch, module):
    async def fake_exec(*cmd, **kwargs):
        raise _Captured(list(cmd), kwargs)
    monkeypatch.setattr(module.shutil, "which", lambda b: f"/usr/bin/{b}")
    monkeypatch.setattr(module.asyncio, "create_subprocess_exec", fake_exec)


def _run(coro):
    try:
        asyncio.run(coro)
    except _Captured as c:
        return c
    raise AssertionError("subprocess was not invoked")


def test_prowler_aws_assumes_tenant_role(monkeypatch) -> None:
    from vulnsuite.collectors.cloud import prowler_aws
    _capture(monkeypatch, prowler_aws)
    c = _run(prowler_aws.ProwlerAWSCollector()._run(["123456789012"], AWS.role_arn, AWS.external_id))
    assert c.cmd[c.cmd.index("--role") + 1] == AWS.role_arn
    assert c.cmd[c.cmd.index("--external-id") + 1] == "tenant-a-7f3"
    assert c.cmd[c.cmd.index("--aws-account-id") + 1] == "123456789012"


def test_prowler_gcp_uses_tenant_service_account(monkeypatch) -> None:
    from vulnsuite.collectors.cloud import prowler_gcp
    _capture(monkeypatch, prowler_gcp)
    c = _run(prowler_gcp.ProwlerGCPCollector()._run(["payments-prod"], GCP.credentials_file))
    assert c.cmd[c.cmd.index("--credentials-file") + 1] == GCP.credentials_file


def test_prowler_azure_runs_in_tenant_env_and_subscription(monkeypatch) -> None:
    from vulnsuite.collectors.cloud import prowler_azure
    _capture(monkeypatch, prowler_azure)
    env = {"AZURE_CLIENT_ID": "cid", "AZURE_CLIENT_SECRET": "s", "AZURE_TENANT_ID": "t"}
    c = _run(prowler_azure.ProwlerAzureCollector()._run([AZURE_SUB], env))
    assert c.kwargs["env"] is env
    assert c.cmd[c.cmd.index("--subscription-id") + 1] == AZURE_SUB


def test_prowler_azure_refuses_without_tenant_credentials(monkeypatch) -> None:
    from vulnsuite.collectors.cloud import prowler_azure
    _capture(monkeypatch, prowler_azure)
    result = asyncio.run(
        prowler_azure.ProwlerAzureCollector().scan(uuid4(), uuid4(), subscription_ids=[AZURE_SUB], env={})
    )
    assert result.errors and "missing Azure credentials" in result.errors[0]


def test_aws_inventory_assumes_role_then_uses_temporary_credentials(monkeypatch) -> None:
    from vulnsuite.collectors.discovery import aws_inventory

    calls: list[tuple[list[str], dict | None]] = []

    class _Proc:
        returncode = 0

        def __init__(self, stdout: bytes):
            self._stdout = stdout

        async def communicate(self):
            return self._stdout, b""

    async def fake_exec(*cmd, **kwargs):
        calls.append((list(cmd), kwargs.get("env")))
        if "assume-role" in cmd:
            return _Proc(json.dumps({"Credentials": {
                "AccessKeyId": "ASIATEMP", "SecretAccessKey": "tmpsecret", "SessionToken": "tmptoken",
            }}).encode())
        return _Proc(b'{"LoadBalancers": [], "Addresses": []}')

    monkeypatch.setattr(aws_inventory.shutil, "which", lambda b: "/usr/bin/aws")
    monkeypatch.setattr(aws_inventory.asyncio, "create_subprocess_exec", fake_exec)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "WORKER_BASE_KEY")

    collector = aws_inventory.AWSInventoryCollector(role_arn=AWS.role_arn, external_id=AWS.external_id)
    asyncio.run(collector.discover(uuid4(), ["123456789012"]))

    sts, *inventory = calls
    assert sts[0][1:3] == ["sts", "assume-role"] and AWS.role_arn in sts[0]
    assert sts[1] is None                       # base identity makes the sts call
    assert len(inventory) == 2
    for _, env in inventory:
        assert env["AWS_ACCESS_KEY_ID"] == "ASIATEMP"
        assert env["AWS_SESSION_TOKEN"] == "tmptoken"
        assert "WORKER_BASE_KEY" not in env.values()


# ---------- worker gate ----------

def test_worker_refuses_unbound_cloud_account(monkeypatch) -> None:
    from vulnsuite.workers import tasks

    async def fake_load(tenant_id, provider=None):
        return [AWS]

    monkeypatch.setattr(tasks, "load_cloud_bindings", fake_load)
    with pytest.raises(CloudAccessError, match="999999999999"):
        asyncio.run(tasks.authorized_cloud_bindings(uuid4(), CloudProvider.AWS, ["999999999999"]))
    assert asyncio.run(tasks.authorized_cloud_bindings(uuid4(), CloudProvider.AWS, ["123456789012"])) == [AWS]
