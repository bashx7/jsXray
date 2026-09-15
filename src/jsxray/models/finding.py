"""Finding model definitions for JSXRay."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid


class Confidence(str, Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class FindingStatus(str, Enum):
    DETECTED = "Detected"
    POTENTIAL = "Potential"
    VALIDATED = "Validated"
    INVALID = "Invalid"
    EXAMPLE = "Example"
    TEST_VALUE = "Test-value"


class FindingType(str, Enum):
    API_ENDPOINT = "api_endpoint"
    URL_ROUTE = "url_route"
    PARAMETER = "parameter"
    API_HOST = "api_host"
    SECRET = "secret"
    CREDENTIAL = "credential"
    AUTHENTICATION = "authentication"
    GRAPHQL = "graphql"
    WEBSOCKET = "websocket"
    SSE = "sse"
    INTERNAL_HOST = "internal_host"
    DANGEROUS_JS = "dangerous_js"
    TECHNOLOGY = "technology"
    SOURCE_MAP = "source_map"
    DYNAMIC_IMPORT = "dynamic_import"
    SECURITY_CANDIDATE = "security_candidate"
    STATIC_RESOURCE = "static_resource"
    EXTERNAL_URL = "external_url"


@dataclass
class SourceLocation:
    file_path: Optional[str] = None
    url: Optional[str] = None
    line: Optional[int] = None
    column: Optional[int] = None
    snippet: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_path": self.file_path,
            "url": self.url,
            "line": self.line,
            "column": self.column,
            "snippet": self.snippet,
        }


@dataclass
class Occurrence:
    source_file: Optional[str] = None
    source_url: Optional[str] = None
    line: Optional[int] = None
    column: Optional[int] = None
    snippet: Optional[str] = None
    raw_value: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_file": self.source_file,
            "source_url": self.source_url,
            "line": self.line,
            "column": self.column,
            "snippet": self.snippet,
            "raw_value": self.raw_value,
        }


@dataclass
class Finding:
    type: FindingType
    value: str
    normalized_value: str
    confidence: Confidence = Confidence.MEDIUM
    status: FindingStatus = FindingStatus.DETECTED
    source_file: Optional[str] = None
    source_url: Optional[str] = None
    line: Optional[int] = None
    column: Optional[int] = None
    snippet: Optional[str] = None
    original_source: Optional[str] = None
    reconstructed_source: Optional[str] = None
    discovery_method: str = "AST analysis"
    tags: List[str] = field(default_factory=list)
    related_findings: List[str] = field(default_factory=list)
    occurrences: List[Occurrence] = field(default_factory=list)
    extra_data: Dict[str, Any] = field(default_factory=dict)
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])

    def add_occurrence(
        self,
        source_file: Optional[str] = None,
        source_url: Optional[str] = None,
        line: Optional[int] = None,
        column: Optional[int] = None,
        snippet: Optional[str] = None,
        raw_value: Optional[str] = None,
    ) -> None:
        occ = Occurrence(
            source_file=source_file or self.source_file,
            source_url=source_url or self.source_url,
            line=line if line is not None else self.line,
            column=column if column is not None else self.column,
            snippet=snippet or self.snippet,
            raw_value=raw_value or self.value,
        )
        self.occurrences.append(occ)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "type": self.type.value if isinstance(self.type, FindingType) else str(self.type),
            "value": self.value,
            "normalized_value": self.normalized_value,
            "confidence": self.confidence.value if isinstance(self.confidence, Confidence) else str(self.confidence),
            "status": self.status.value if isinstance(self.status, FindingStatus) else str(self.status),
            "source_file": self.source_file,
            "source_url": self.source_url,
            "line": self.line,
            "column": self.column,
            "snippet": self.snippet,
            "original_source": self.original_source,
            "reconstructed_source": self.reconstructed_source,
            "discovery_method": self.discovery_method,
            "tags": self.tags,
            "related_findings": self.related_findings,
            "occurrences": [occ.to_dict() for occ in self.occurrences],
            "occurrence_count": max(1, len(self.occurrences)),
            "extra_data": self.extra_data,
        }
