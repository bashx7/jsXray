"""Correlation engine linking hosts, endpoints, parameters, and auth mechanisms in JSXRay."""

from collections import defaultdict
from typing import Any, Dict, List
from urllib.parse import urlparse
from jsxray.models.finding import Finding, FindingType


class CorrelationEngine:
    """Builds relational intelligence graphs across extracted security findings."""

    @staticmethod
    def correlate(findings: List[Finding]) -> Dict[str, Any]:
        """Correlates endpoints to hosts, parameters to endpoints, and auth indicators."""
        host_to_endpoints: Dict[str, List[str]] = defaultdict(list)
        endpoint_details: Dict[str, Dict[str, Any]] = {}
        all_hosts = set()
        auth_types = set()

        for f in findings:
            if f.type == FindingType.API_HOST:
                all_hosts.add(f.normalized_value)

            elif f.type == FindingType.API_ENDPOINT:
                endpoint = f.normalized_value
                host = "default"
                if "://" in endpoint:
                    try:
                        parsed = urlparse(endpoint)
                        if parsed.hostname:
                            host = parsed.hostname.lower()
                    except Exception:
                        pass

                host_to_endpoints[host].append(endpoint)
                if endpoint not in endpoint_details:
                    endpoint_details[endpoint] = {
                        "method": f.extra_data.get("method", "GET"),
                        "tags": f.tags,
                        "source": f.source_file or f.source_url or "unknown",
                        "line": f.line,
                    }

            elif f.type == FindingType.AUTHENTICATION:
                auth_types.add(f.value)

        # Build clean relationships structure for report
        relationships = {
            "host_hierarchy": {h: list(set(eps)) for h, eps in host_to_endpoints.items()},
            "discovered_hosts": sorted(list(all_hosts)),
            "auth_indicators": sorted(list(auth_types)),
            "endpoint_count": len(endpoint_details),
        }

        return relationships
