"""ReBIT v2.0+ Account Aggregator Consent Artefact Schema.

Implements the official Reserve Bank of India (RBI) / ReBIT v2.0+
data models for Account Aggregator consent artefacts using Pydantic.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, ConfigDict


class ConsentStatus(str, Enum):
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"
    PAUSED = "PAUSED"
    PENDING = "PENDING"
    REJECTED = "REJECTED"


class ConsentMode(str, Enum):
    VIEW = "VIEW"
    STORE = "STORE"
    QUERY = "QUERY"
    STREAM = "STREAM"


class FetchType(str, Enum):
    ONETIME = "ONETIME"
    PERIODIC = "PERIODIC"


class FIType(str, Enum):
    DEPOSIT = "DEPOSIT"
    TERM_DEPOSIT = "TERM_DEPOSIT"
    RECURRING_DEPOSIT = "RECURRING_DEPOSIT"
    MUTUAL_FUNDS = "MUTUAL_FUNDS"
    CREDIT_CARD = "CREDIT_CARD"
    INSURANCE_POLICIES = "INSURANCE_POLICIES"
    GSEC = "GSEC"
    EQUITIES = "EQUITIES"
    GSTN = "GSTN"
    NPS = "NPS"


class PurposeCategory(BaseModel):
    type: Optional[str] = None


class PurposeDetail(BaseModel):
    code: str = Field(description="Standard purpose code, e.g. '101' for Wealth Management / Loan Underwriting")
    refUri: Optional[str] = Field(default=None, description="Reference URI defining purpose specifications")
    text: str = Field(description="Human readable description of the consent purpose")
    Category: Optional[PurposeCategory] = Field(default=None, description="Purpose category details")


class ConsentFilter(BaseModel):
    type: str = Field(description="Filter type, e.g. 'TRANSACTION'")
    operator: str = Field(description="Filter operator, e.g. '=', '>=', '<='")
    value: str = Field(description="Filter threshold value")


class DataLife(BaseModel):
    unit: str = Field(default="MONTH", description="Unit of data life, e.g. 'MONTH', 'YEAR', 'DAY', 'INF'")
    value: int = Field(default=0, description="Duration value")


class Frequency(BaseModel):
    unit: str = Field(default="MONTH", description="Unit of fetch frequency")
    value: int = Field(default=1, description="Frequency value")


class PartyIdentifier(BaseModel):
    id: str = Field(description="Unique entity identifier (e.g. FIU or FIP handle)")
    type: Optional[str] = Field(default="FIU", description="Entity type: 'FIU', 'FIP', or 'AA'")


class CustomerIdentifier(BaseModel):
    id: str = Field(description="Unique customer AA handle (e.g. user@aa)")


class ConsentDetail(BaseModel):
    model_config = ConfigDict(extra="ignore")

    consentStart: datetime = Field(description="UTC timestamp for start of consent validity")
    consentExpiry: datetime = Field(description="UTC timestamp for expiry of consent validity")
    consentMode: ConsentMode = Field(description="Consent mode: VIEW, STORE, QUERY, STREAM")
    fetchType: FetchType = Field(description="Fetch type: ONETIME or PERIODIC")
    fiTypes: List[FIType] = Field(description="Permitted financial information types")
    purpose: PurposeDetail = Field(description="Consented purpose specification")
    filters: Optional[List[ConsentFilter]] = Field(default_factory=list, description="Filters on financial data")
    dataConsumer: Optional[PartyIdentifier] = Field(default=None, description="Data Consumer (FIU) identifier")
    dataProvider: Optional[PartyIdentifier] = Field(default=None, description="Data Provider (FIP) identifier")
    customer: Optional[CustomerIdentifier] = Field(default=None, description="Customer AA identifier")
    dataLife: Optional[DataLife] = Field(default=None, description="Data retention life")
    frequency: Optional[Frequency] = Field(default=None, description="Periodic fetch frequency")


class RebitConsentArtefact(BaseModel):
    model_config = ConfigDict(extra="ignore")

    ver: str = Field(default="2.0.0", description="ReBIT AA schema version")
    txnid: str = Field(description="Transaction UUID")
    consentId: str = Field(description="Globally unique consent UUID")
    status: ConsentStatus = Field(default=ConsentStatus.ACTIVE, description="Consent lifecycle status")
    createTimestamp: datetime = Field(description="Creation UTC timestamp")
    signedConsent: str = Field(description="RS256 compact JWS signature string")
    consentDetail: ConsentDetail = Field(description="Detailed consent terms and conditions")
