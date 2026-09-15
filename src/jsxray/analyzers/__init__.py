"""Analyzers registry for JSXRay."""

from typing import List
from jsxray.analyzers.api import ApiAnalyzer
from jsxray.analyzers.authentication import AuthenticationAnalyzer
from jsxray.analyzers.base import BaseAnalyzer
from jsxray.analyzers.candidates import SecurityCandidateAnalyzer
from jsxray.analyzers.chunks import ChunkAnalyzer
from jsxray.analyzers.credentials import CredentialAnalyzer
from jsxray.analyzers.dangerous_js import DangerousJsAnalyzer
from jsxray.analyzers.graphql import GraphQLAnalyzer
from jsxray.analyzers.hosts import HostAnalyzer
from jsxray.analyzers.internal_hosts import InternalHostAnalyzer
from jsxray.analyzers.parameters import ParameterAnalyzer
from jsxray.analyzers.secrets import SecretAnalyzer
from jsxray.analyzers.source_maps import SourceMapAnalyzer
from jsxray.analyzers.sse import SSEAnalyzer
from jsxray.analyzers.technologies import TechnologyAnalyzer
from jsxray.analyzers.urls import UrlAnalyzer
from jsxray.analyzers.websocket import WebSocketAnalyzer


def get_all_analyzers(target_domain: str = None) -> List[BaseAnalyzer]:
    """Returns an instantiated list of all primary static analyzers."""
    return [
        ApiAnalyzer(),
        UrlAnalyzer(),
        ParameterAnalyzer(),
        HostAnalyzer(target_domain=target_domain),
        SecretAnalyzer(),
        CredentialAnalyzer(),
        AuthenticationAnalyzer(),
        GraphQLAnalyzer(),
        WebSocketAnalyzer(),
        SSEAnalyzer(),
        InternalHostAnalyzer(),
        DangerousJsAnalyzer(),
        TechnologyAnalyzer(),
        SourceMapAnalyzer(),
        ChunkAnalyzer(),
    ]


__all__ = [
    "BaseAnalyzer",
    "ApiAnalyzer",
    "UrlAnalyzer",
    "ParameterAnalyzer",
    "HostAnalyzer",
    "SecretAnalyzer",
    "CredentialAnalyzer",
    "AuthenticationAnalyzer",
    "GraphQLAnalyzer",
    "WebSocketAnalyzer",
    "SSEAnalyzer",
    "InternalHostAnalyzer",
    "DangerousJsAnalyzer",
    "TechnologyAnalyzer",
    "SourceMapAnalyzer",
    "ChunkAnalyzer",
    "SecurityCandidateAnalyzer",
    "get_all_analyzers",
]
