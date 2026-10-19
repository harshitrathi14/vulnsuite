"""
VulnSuite - Per-tenant cloud account bindings

Cloud collectors used to run with whatever ambient credentials the worker
had, scoped only by the account IDs the caller typed in. Any tenant's
analyst could therefore scan any AWS account, GCP project or Azure
subscription the worker could reach. A binding ties (tenant, provider,
account) to the credential the worker must use for it:

  aws    role_arn (+ external_id)  -> prowler --role / `aws sts assume-role`
  gcp    credentials_file          -> prowler --credentials-file / gcloud env
  azure  secret_env_prefix         -> <PREFIX>_AZURE_CLIENT_ID / _CLIENT_SECRET
                                      / _TENANT_ID read from the worker env

Only references are stored, never secrets: the worker's base identity
assumes the tenant's AWS role; Azure secrets live in the worker env
(injected from Key Vault by the init container, per the deploy docs).

`authorize` is a pure function so it is unit-testable without a database.
It runs in the API (fast 403) and again in the worker (defense in depth,
same pattern as the DAST allowlist).
"""
from __future__ import annotations

import os
import re
from enum import Enum
from typing import Iterable, Mapping
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from . import targets as _targets


class CloudProvider(str, Enum):
    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"


class CloudAccessError(PermissionError):
    """The tenant has no binding for the requested cloud account."""


_ROLE_ARN = re.compile(r"^arn:aws(?:-[a-z]+)?:iam::([0-9]{12}):role/[\w+=,.@/-]{1,512}$")
_EXTERNAL_ID = re.compile(r"^[\w+=,.@:/-]{2,1224}$")
_ENV_PREFIX = re.compile(r"^[A-Z][A-Z0-9_]{0,62}$")

# Keys that would mean someone pasted a secret into the binding.
_SECRET_KEYS = frozenset({
    "client_secret", "secret_access_key", "access_key_id", "session_token",
    "private_key", "password", "token", "api_key",
})

# Ambient credential variables a scoped subprocess must not inherit.
_AMBIENT_ENV = {
    CloudProvider.AWS.value: ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
                              "AWS_SESSION_TOKEN", "AWS_PROFILE", "AWS_ROLE_ARN",
                              "AWS_WEB_IDENTITY_TOKEN_FILE"),
    CloudProvider.GCP.value: ("GOOGLE_APPLICATION_CREDENTIALS",
                              "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE",
                              "CLOUDSDK_CORE_PROJECT", "CLOUDSDK_CORE_ACCOUNT"),
    CloudProvider.AZURE.value: ("AZURE_",),   # prefix match
}

AZURE_ENV_KEYS = ("AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID")


class CloudBinding(BaseModel):
    model_config = ConfigDict(use_enum_values=True, frozen=True)

    provider: CloudProvider
    account_id: str          # AWS account ID / GCP project ID / Azure subscription ID
    display_name: str = ""
    credentials: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _validate(self) -> "CloudBinding":
        leaked = _SECRET_KEYS & {k.lower() for k in self.credentials}
        if leaked:
            raise ValueError(
                f"credentials must hold references, not secrets: {sorted(leaked)}"
            )
        if self.provider == CloudProvider.AWS.value:
            _targets.safe_aws_account(self.account_id, "account_id")
            m = _ROLE_ARN.match(self.credentials.get("role_arn", ""))
            if not m:
                raise ValueError("aws binding requires a valid role_arn")
            if m.group(1) != self.account_id:
                raise ValueError("role_arn must belong to account_id")
            external_id = self.credentials.get("external_id")
            if external_id is not None and not _EXTERNAL_ID.match(external_id):
                raise ValueError("external_id has an invalid format")
        elif self.provider == CloudProvider.GCP.value:
            _targets.safe_gcp_project(self.account_id, "account_id")
            path = self.credentials.get("credentials_file")
            if not path:
                raise ValueError("gcp binding requires credentials_file")
            _targets.safe_path(path, "credentials_file")
        else:
            try:
                UUID(self.account_id)
            except ValueError as exc:
                raise ValueError("azure account_id must be a subscription UUID") from exc
            prefix = self.credentials.get("secret_env_prefix", "")
            if not _ENV_PREFIX.match(prefix):
                raise ValueError(
                    "azure binding requires secret_env_prefix (e.g. TENANT_A)"
                )
        return self

    # convenience accessors ------------------------------------------------
    @property
    def role_arn(self) -> str | None:
        return self.credentials.get("role_arn")

    @property
    def external_id(self) -> str | None:
        return self.credentials.get("external_id")

    @property
    def credentials_file(self) -> str | None:
        return self.credentials.get("credentials_file")

    @property
    def secret_env_prefix(self) -> str | None:
        return self.credentials.get("secret_env_prefix")


# ---------- authorization (pure) ----------

def authorize(
    bindings: Iterable[CloudBinding],
    provider: CloudProvider | str,
    requested: Iterable[str] | None,
) -> list[CloudBinding]:
    """Return the bindings a request may use, or raise CloudAccessError.

    requested=None means "every account bound for this provider" (used by
    the Azure boolean target and nightly discovery). A request never
    silently widens to whatever the credential can see.
    """
    provider = CloudProvider(provider).value
    bound = {b.account_id: b for b in bindings if b.provider == provider}
    if requested is None:
        if not bound:
            raise CloudAccessError(f"no {provider} accounts are bound to this tenant")
        return list(bound.values())
    wanted = list(dict.fromkeys(requested))
    if not wanted:
        raise CloudAccessError(f"{provider}: no account requested")
    missing = [a for a in wanted if a not in bound]
    if missing:
        raise CloudAccessError(
            f"{provider} account(s) not bound to this tenant: {missing}"
        )
    return [bound[a] for a in wanted]


# ---------- credential materialisation ----------

def azure_env(binding: CloudBinding, environ: Mapping[str, str] | None = None) -> dict[str, str]:
    """Service-principal variables for one subscription, read from the
    worker env under the binding's prefix. Never logged, never stored."""
    environ = os.environ if environ is None else environ
    prefix = binding.secret_env_prefix
    out: dict[str, str] = {}
    for key in AZURE_ENV_KEYS:
        value = environ.get(f"{prefix}_{key}")
        if not value:
            raise CloudAccessError(
                f"worker env is missing {prefix}_{key} for azure subscription "
                f"{binding.account_id}"
            )
        out[key] = value
    out["AZURE_SUBSCRIPTION_ID"] = binding.account_id
    return out


def gcp_env(binding: CloudBinding) -> dict[str, str]:
    path = binding.credentials_file or ""
    return {
        "GOOGLE_APPLICATION_CREDENTIALS": path,
        "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE": path,
        "CLOUDSDK_CORE_PROJECT": binding.account_id,
    }


def scoped_env(
    provider: CloudProvider | str,
    overrides: Mapping[str, str],
    base: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Subprocess environment with the provider's ambient credentials
    stripped and the tenant's overrides applied, so a scanner can never
    fall back to the worker's own identity."""
    provider = CloudProvider(provider).value
    env = dict(os.environ if base is None else base)
    for key in list(env):
        for pattern in _AMBIENT_ENV[provider]:
            if key == pattern or (pattern.endswith("_") and key.startswith(pattern)):
                env.pop(key, None)
    env.update(overrides)
    return env


# ---------- persistence ----------

async def load_cloud_bindings(
    tenant_id: UUID, provider: CloudProvider | str | None = None,
) -> list[CloudBinding]:
    """Bindings for one tenant, read through the RLS-scoped session."""
    from sqlalchemy import select

    from .db import CloudAccountRow, tenant_session

    stmt = select(CloudAccountRow)
    if provider is not None:
        stmt = stmt.where(CloudAccountRow.provider == CloudProvider(provider).value)
    async with tenant_session(tenant_id) as session:
        rows = (await session.execute(stmt)).scalars().all()
    return [
        CloudBinding(
            provider=row.provider,
            account_id=row.account_id,
            display_name=row.display_name or "",
            credentials=dict(row.credentials or {}),
        )
        for row in rows
    ]
