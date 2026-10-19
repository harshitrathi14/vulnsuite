from typing import Literal
from ipaddress import ip_address, ip_network
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra='forbid')


class HostPolicy(StrictModel):
    allow_response: bool = False
    addresses: list[str] = Field(default_factory=list, max_length=32)
    protected_networks: list[str] = Field(default_factory=list, max_length=100)
    permitted_networks: list[str] = Field(default_factory=list, max_length=100)
    desired_version: str | None = Field(default=None, max_length=64)
    asset_id: str | None = Field(default=None, max_length=64)

    @field_validator('addresses')
    @classmethod
    def addresses_valid(cls, values):
        return sorted({str(ip_address(v)) for v in values})

    @field_validator('protected_networks','permitted_networks')
    @classmethod
    def networks_valid(cls, values):
        return sorted({str(ip_network(v)) for v in values})

    @model_validator(mode='after')
    def protected_required(self):
        if self.allow_response and not self.protected_networks:
            raise ValueError('response needs protected networks')
        return self


class EnrollmentRequest(StrictModel):
    host: str = Field(pattern=r'^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$')
    policy: HostPolicy = Field(default_factory=HostPolicy)
    ttl_seconds: int = Field(default=600, ge=60, le=3600)


class EnrollmentRedeem(StrictModel):
    token: str = Field(min_length=32, max_length=256)


class IncidentCreate(StrictModel):
    title: str = Field(min_length=3, max_length=256)
    owner: str = Field(min_length=1, max_length=128)
    severity: Literal['critical','high','medium','low'] = 'high'
    alert_ids: list[int] = Field(min_length=1, max_length=100)


class IncidentUpdate(StrictModel):
    version: int = Field(ge=1)
    status: Literal['open','investigating','contained','resolved']
    owner: str = Field(min_length=1, max_length=128)
    note: str = Field(min_length=3, max_length=2000)


class ReviewRequest(StrictModel):
    status: Literal['open','triaged','resolved','false_positive']
    reason: str = Field(min_length=10, max_length=1000)


class SuppressionCreate(StrictModel):
    rule: str = Field(min_length=1, max_length=128)
    host: str = Field(min_length=1, max_length=128)
    ip: str | None = None
    duration_seconds: int = Field(ge=60, le=604800)
    reason: str = Field(min_length=10, max_length=1000)

    @field_validator('ip')
    @classmethod
    def valid_ip(cls, value):
        return str(ip_address(value)) if value else None


class PlaybookRequest(StrictModel):
    action: Literal['quarantine_file','restore_file','isolate_host','release_host','cloud_waf_block',
                    'terminate_process']
    alert_id: int = Field(gt=0)
    duration_seconds: int = Field(default=300, ge=60, le=3600)
    previous_job_id: str | None = Field(default=None, pattern=r'^[a-f0-9]{32}$')
    reason: str = Field(min_length=10, max_length=1000)


class PlaybookReceipt(StrictModel):
    detail: Literal['quarantined','restored','isolated','isolation_released','process_terminated',
                    'process_absent','policy_denied','execution_failed'] | None = None
    status: Literal['applied','failed','rolled_back']
    result: dict = Field(default_factory=dict)
