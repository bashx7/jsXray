"""Schema definitions for secret detectors in JSXRay."""

from dataclasses import dataclass, field
from enum import Enum
import re
from typing import Callable, List, Optional, Pattern, Set


class SecretCategory(str, Enum):
    CLOUD = "Cloud Infrastructure"
    AI = "AI & Machine Learning"
    PAYMENT = "Payment & Billing"
    EMAIL = "Email & SMS"
    COMMUNICATION = "Communication & Messaging"
    DEVOPS = "DevOps & CI/CD"
    SOURCE_CONTROL = "Source Control & Registry"
    DATABASE = "Database & Storage"
    AUTH = "Identity & Authentication"
    MONITORING = "Monitoring & Analytics"
    MARKETING = "CRM & Marketing"
    SECURITY = "Security & Crypto"
    SAAS = "SaaS & Productivity"
    GENERIC = "Generic Credential"


@dataclass
class SecretDetector:
    detector_id: str
    provider: str
    secret_type: str
    category: SecretCategory
    pattern: Pattern
    prefixes: List[str] = field(default_factory=list)
    min_length: int = 8
    max_length: int = 512
    min_entropy: float = 0.0
    allowed_characters: Optional[str] = None
    context_keywords: List[str] = field(default_factory=list)
    required_context: bool = False
    negative_patterns: List[Pattern] = field(default_factory=list)
    validator: Optional[Callable[[str], bool]] = None
    confidence_base: str = "High"  # High, Medium, Low
    description: str = ""
