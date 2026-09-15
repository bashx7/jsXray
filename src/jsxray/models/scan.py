"""Scan result models for JSXRay."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List
from jsxray.models.finding import Finding, FindingType
from jsxray.models.source import JavaScriptSource


@dataclass
class ScanMetadata:
    scan_id: str
    target_input: str
    input_mode: str
    target_domain: Optional[str] = None
    inferred_domain: bool = False
    start_time: str = field(default_factory=lambda: datetime.now().isoformat())
    end_time: str = ""
    duration_seconds: float = 0.0
    jsxray_version: str = "1.0.0"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "target_input": self.target_input,
            "input_mode": self.input_mode,
            "target_domain": self.target_domain,
            "inferred_domain": self.inferred_domain,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_seconds": round(self.duration_seconds, 2),
            "jsxray_version": self.jsxray_version,
        }


@dataclass
class ScanStatistics:
    total_sources: int = 0
    downloaded_sources: int = 0
    analyzed_sources: int = 0
    failed_sources: int = 0
    api_endpoints: int = 0
    url_routes: int = 0
    parameters: int = 0
    api_hosts: int = 0
    secrets: int = 0
    credentials: int = 0
    authentications: int = 0
    graphql_endpoints: int = 0
    websockets: int = 0
    sse_endpoints: int = 0
    internal_hosts: int = 0
    dangerous_js: int = 0
    technologies: int = 0
    source_maps: int = 0
    dynamic_imports: int = 0
    security_candidates: int = 0
    static_resources: int = 0
    external_urls: int = 0
    total_findings: int = 0

    def to_dict(self) -> Dict[str, int]:
        return {
            "total_sources": self.total_sources,
            "downloaded_sources": self.downloaded_sources,
            "analyzed_sources": self.analyzed_sources,
            "failed_sources": self.failed_sources,
            "api_endpoints": self.api_endpoints,
            "url_routes": self.url_routes,
            "parameters": self.parameters,
            "api_hosts": self.api_hosts,
            "secrets": self.secrets,
            "credentials": self.credentials,
            "authentications": self.authentications,
            "graphql_endpoints": self.graphql_endpoints,
            "websockets": self.websockets,
            "sse_endpoints": self.sse_endpoints,
            "internal_hosts": self.internal_hosts,
            "dangerous_js": self.dangerous_js,
            "technologies": self.technologies,
            "source_maps": self.source_maps,
            "dynamic_imports": self.dynamic_imports,
            "security_candidates": self.security_candidates,
            "static_resources": self.static_resources,
            "external_urls": self.external_urls,
            "total_findings": self.total_findings,
        }


@dataclass
class ScanResult:
    metadata: ScanMetadata
    sources: List[JavaScriptSource] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    errors: List[Dict[str, Any]] = field(default_factory=list)
    warnings: List[Dict[str, Any]] = field(default_factory=list)
    statistics: ScanStatistics = field(default_factory=ScanStatistics)

    def calculate_statistics(self) -> None:
        stats = ScanStatistics()
        stats.total_sources = len(self.sources)
        stats.analyzed_sources = sum(1 for s in self.sources if s.is_valid_js)
        stats.failed_sources = sum(1 for s in self.sources if not s.is_valid_js or s.errors)
        stats.downloaded_sources = sum(1 for s in self.sources if s.url)

        type_counts = {ft: 0 for ft in FindingType}
        for f in self.findings:
            if f.type in type_counts:
                type_counts[f.type] += 1

        stats.api_endpoints = type_counts[FindingType.API_ENDPOINT]
        stats.url_routes = type_counts[FindingType.URL_ROUTE]
        stats.parameters = type_counts[FindingType.PARAMETER]
        stats.api_hosts = type_counts[FindingType.API_HOST]
        stats.secrets = type_counts[FindingType.SECRET]
        stats.credentials = type_counts[FindingType.CREDENTIAL]
        stats.authentications = type_counts[FindingType.AUTHENTICATION]
        stats.graphql_endpoints = type_counts[FindingType.GRAPHQL]
        stats.websockets = type_counts[FindingType.WEBSOCKET]
        stats.sse_endpoints = type_counts[FindingType.SSE]
        stats.internal_hosts = type_counts[FindingType.INTERNAL_HOST]
        stats.dangerous_js = type_counts[FindingType.DANGEROUS_JS]
        stats.technologies = type_counts[FindingType.TECHNOLOGY]
        stats.source_maps = type_counts[FindingType.SOURCE_MAP]
        stats.dynamic_imports = type_counts[FindingType.DYNAMIC_IMPORT]
        stats.security_candidates = type_counts[FindingType.SECURITY_CANDIDATE]
        stats.static_resources = type_counts[FindingType.STATIC_RESOURCE]
        stats.external_urls = type_counts[FindingType.EXTERNAL_URL]
        stats.total_findings = len(self.findings)

        self.statistics = stats

    def to_dict(self) -> Dict[str, Any]:
        self.calculate_statistics()
        return {
            "metadata": self.metadata.to_dict(),
            "statistics": self.statistics.to_dict(),
            "sources": [s.to_dict() for s in self.sources],
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
            "warnings": self.warnings,
        }
