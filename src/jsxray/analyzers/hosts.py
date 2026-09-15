"""Subdomain and API Host analyzer for JSXRay.

Accurately classifies extracted hostnames into In-Scope Subdomains, Application API Hosts,
Third-Party API Hosts, and External References based on target domain scoping.
"""

import re
from typing import List, Optional, Set, Tuple
from tree_sitter import Node
from jsxray.analyzers.base import BaseAnalyzer
from jsxray.javascript.ast_utils import (
    extract_string_literal,
    get_node_line_col,
    get_node_snippet,
    get_node_text,
    walk_tree,
)
from jsxray.javascript.reconstruction import StaticReconstructor
from jsxray.models.finding import Confidence, Finding, FindingStatus, FindingType
from jsxray.models.source import JavaScriptSource


class HostAnalyzer(BaseAnalyzer):
    """Classifies subdomains and hostnames, scoping target domain assets."""

    def __init__(self, target_domain: Optional[str] = None) -> None:
        self.target_domain: Optional[str] = None
        self.subdomain_regex: Optional[re.Pattern] = None
        if target_domain:
            cleaned = target_domain.lower().strip()
            if cleaned.startswith("http://"):
                cleaned = cleaned[7:]
            elif cleaned.startswith("https://"):
                cleaned = cleaned[8:]
            cleaned = cleaned.split("/")[0].split(":")[0].strip()
            if cleaned:
                self.target_domain = cleaned
                self.subdomain_regex = re.compile(
                    r"\b((?:[a-zA-Z0-9_\-]+\.)*" + re.escape(self.target_domain) + r")\b",
                    re.I,
                )

    @property
    def name(self) -> str:
        return "hosts"

    HOST_URL_REGEX = re.compile(r"^https?://([a-zA-Z0-9_\-\.]+)(?::\d+)?(?:/.*)?$")

    # Standard XML/SVG/schema namespaces (MUST NOT be API Hosts or Subdomains)
    STANDARD_NAMESPACE_HOSTS = {
        "www.w3.org", "w3.org", "schema.org", "xmlns.com", "openxmlformats.org",
    }

    # Framework and documentation sites (External References, not target API hosts)
    FRAMEWORK_AND_DOC_HOSTS = {
        "svelte.dev", "reactjs.org", "react.dev", "vuejs.org", "angular.io",
        "vitejs.dev", "nextjs.org", "nuxtjs.org", "tailwindcss.com",
        "youtube.com", "youtu.be", "twitter.com", "x.com", "github.com",
        "gitlab.com", "bitbucket.org", "npmjs.com", "npm.im", "yarnpkg.com",
        "developer.mozilla.org", "stackoverflow.com", "medium.com", "linkedin.com",
        "wikipedia.org", "google.com", "fonts.googleapis.com", "fonts.gstatic.com",
        "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com",
    }

    # Known Third-Party API services
    THIRD_PARTY_API_PATTERNS = [
        re.compile(r"api\.(?:stripe|github|gitlab|openai|anthropic|groq|cohere|perplexity|sendgrid|mailgun|twilio|segment|mixpanel|datadog|sentry|postman|algolia|mapbox|clerk|supabase|auth0|firebase)\.", re.I),
        re.compile(r"\.(?:supabase\.co|algolia\.net|algolianet\.com|firebaseio\.com|ingest\.sentry\.io|datadoghq\.com|auth0\.com|clerk\.dev|launchdarkly\.com)", re.I),
    ]

    def classify_hostname(self, hostname: str, full_url: str = "") -> Tuple[str, bool, Optional[bool]]:
        """
        Classifies hostname into:
        (category, is_api_host_or_subdomain, is_in_scope)
        """
        h_lower = hostname.lower().strip()

        # In-Scope Subdomain / Target Domain Check
        if self.target_domain:
            if h_lower == self.target_domain or h_lower.endswith("." + self.target_domain):
                if h_lower.startswith(("api.", "api-", "backend.", "graphql.", "gateway.", "service.", "rest.", "auth.")) or "/api" in full_url.lower():
                    return "In-Scope API Host", True, True
                return "In-Scope Subdomain", True, True

        if h_lower in self.STANDARD_NAMESPACE_HOSTS:
            return "Framework / Standard", False, False

        if h_lower in self.FRAMEWORK_AND_DOC_HOSTS:
            return "External Reference", False, False

        # Third-party API provider check
        if any(p.search(h_lower) for p in self.THIRD_PARTY_API_PATTERNS):
            return "Third-Party API Host", True, False

        # Application API Host indicators
        if h_lower.startswith(("api.", "api-", "backend.", "graphql.", "gateway.", "service.", "rest.", "auth.")) or "api" in h_lower:
            return "Application API Host", True, True if self.target_domain is None else False

        # Check full URL for API routing patterns
        url_lower = full_url.lower()
        if any(p in url_lower for p in ("/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rpc")):
            return "Application API Host", True, True if self.target_domain is None else False

        return "External Reference", False, False

    def analyze(self, source: JavaScriptSource, reconstructor: StaticReconstructor) -> List[Finding]:
        findings: List[Finding] = []
        if not source.ast_root:
            return findings

        code_bytes = source.effective_code.encode("utf-8", errors="replace")
        code_lines = source.effective_code.splitlines()
        seen_hosts: Set[str] = set()

        for node in walk_tree(source.ast_root):
            val: str = ""
            if node.type in ("string", "string_fragment"):
                val = extract_string_literal(node, code_bytes) or ""
            elif node.type == "template_string":
                resolved, _, _ = reconstructor.resolve_expression(node)
                val = resolved or ""

            if not val or len(val) < 4:
                continue

            extracted_hosts: List[str] = []

            # 1. Check URL patterns
            match = self.HOST_URL_REGEX.match(val.strip())
            if match:
                extracted_hosts.append(match.group(1).lower().strip())

            # 2. If target domain is known, check for naked subdomain occurrences
            if self.subdomain_regex:
                for sub_match in self.subdomain_regex.finditer(val):
                    sub_host = sub_match.group(1).lower().strip()
                    if sub_host and sub_host not in extracted_hosts:
                        extracted_hosts.append(sub_host)

            for hostname in extracted_hosts:
                if not hostname or "." not in hostname or hostname.startswith(".") or hostname.endswith("."):
                    continue

                category, is_reportable, is_in_scope = self.classify_hostname(hostname, full_url=val)

                if is_reportable:
                    if hostname not in seen_hosts:
                        seen_hosts.add(hostname)
                        line, col = get_node_line_col(node)
                        snippet = get_node_snippet(node, code_lines, code_bytes=code_bytes)

                        tags = ["subdomain" if "Subdomain" in category else "api-host", category.lower().replace(" ", "-")]
                        if is_in_scope:
                            tags.append("in-scope")

                        findings.append(
                            Finding(
                                type=FindingType.API_HOST,
                                value=hostname,
                                normalized_value=hostname,
                                confidence=Confidence.HIGH,
                                status=FindingStatus.DETECTED,
                                source_file=source.file_path,
                                source_url=source.url,
                                line=line,
                                column=col,
                                snippet=snippet,
                                original_source=get_node_text(node, code_bytes).strip(),
                                reconstructed_source=val,
                                discovery_method="AST analysis",
                                tags=tags,
                                extra_data={
                                    "hostname": hostname,
                                    "category": category,
                                    "is_in_scope": is_in_scope,
                                    "target_domain": self.target_domain,
                                    "full_url": val,
                                },
                            )
                        )
                elif category == "External Reference":
                    if hostname not in seen_hosts:
                        seen_hosts.add(hostname)
                        line, col = get_node_line_col(node)
                        snippet = get_node_snippet(node, code_lines, code_bytes=code_bytes)
                        findings.append(
                            Finding(
                                type=FindingType.EXTERNAL_URL,
                                value=hostname,
                                normalized_value=hostname,
                                confidence=Confidence.MEDIUM,
                                status=FindingStatus.DETECTED,
                                source_file=source.file_path,
                                source_url=source.url,
                                line=line,
                                column=col,
                                snippet=snippet,
                                original_source=get_node_text(node, code_bytes).strip(),
                                reconstructed_source=val,
                                discovery_method="AST analysis",
                                tags=["external-reference", "external-host"],
                                extra_data={
                                    "hostname": hostname,
                                    "category": "External Reference",
                                    "is_in_scope": False,
                                    "target_domain": self.target_domain,
                                    "full_url": val,
                                },
                            )
                        )

        return findings
