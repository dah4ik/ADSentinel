from dataclasses import dataclass
from typing import Optional, List


@dataclass
class ADUser:
    username: str
    display_name: Optional[str]
    distinguished_name: str
    user_account_control: int
    last_logon: Optional[str]
    pwd_last_set: Optional[str]
    member_of: List[str]
    description: Optional[str]


@dataclass
class Finding:
    category: str
    username: str
    finding: str
    risk_level: str
    risk_score: int
    recommendation: str

    def to_dict(self):
        return {
            "category": self.category,
            "username": self.username,
            "finding": self.finding,
            "risk_level": self.risk_level,
            "risk_score": self.risk_score,
            "recommendation": self.recommendation
        }