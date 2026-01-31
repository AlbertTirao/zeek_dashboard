from dataclasses import dataclass
from datetime import datetime

@dataclass
class Device:
    mac: str
    hostname: str
    first_seen: datetime
    last_seen: datetime
    events: int
    status: str
    risk_score: int = 0
    risk_level: str = "Low"
