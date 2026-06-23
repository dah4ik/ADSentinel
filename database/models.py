from datetime import datetime

from sqlalchemy import Column
from sqlalchemy import DateTime
from sqlalchemy import Integer
from sqlalchemy import String
from sqlalchemy import Text
from sqlalchemy import ForeignKey

from sqlalchemy.orm import relationship

from database.db import Base


class Scan(Base):
    __tablename__ = "scans"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    started_at = Column(
        DateTime,
        default=datetime.utcnow
    )

    profile = Column(
        String(50),
        nullable=False
    )

    total_findings = Column(
        Integer,
        default=0
    )

    security_score = Column(
        Integer,
        default=100
    )

    overall_risk_level = Column(
        String(50),
        default="Low"
    )

    findings = relationship(
        "FindingRecord",
        back_populates="scan",
        cascade="all, delete-orphan"
    )


class FindingRecord(Base):
    __tablename__ = "findings"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    scan_id = Column(
        Integer,
        ForeignKey("scans.id")
    )

    category = Column(
        String(255)
    )

    username = Column(
        String(255)
    )

    finding = Column(
        Text
    )

    risk_level = Column(
        String(50)
    )

    risk_score = Column(
        Integer
    )

    recommendation = Column(
        Text
    )

    mitre_id = Column(
        String(100)
    )

    mitre_tactic = Column(
        Text
    )

    mitre_technique = Column(
        String(255)
    )

    cis_control = Column(
        Text
    )

    nist_csf = Column(
        Text
    )

    iso_27001 = Column(
        Text
    )

    scan = relationship(
        "Scan",
        back_populates="findings"
    )


class ScanStatistic(Base):
    __tablename__ = "scan_statistics"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    scan_id = Column(
        Integer,
        ForeignKey("scans.id")
    )

    critical_count = Column(
        Integer,
        default=0
    )

    high_count = Column(
        Integer,
        default=0
    )

    medium_count = Column(
        Integer,
        default=0
    )

    low_count = Column(
        Integer,
        default=0
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )