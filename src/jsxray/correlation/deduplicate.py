"""Deduplication and occurrence aggregation engine for JSXRay."""

from collections import defaultdict
from typing import Dict, List
from jsxray.correlation.normalize import Normalizer
from jsxray.models.finding import Finding, FindingType, Occurrence


def deduplicate_findings(findings: List[Finding]) -> List[Finding]:
    """Deduplicates findings of the same type while aggregating all occurrence locations."""
    if not findings:
        return []

    grouped: Dict[str, List[Finding]] = defaultdict(list)

    for f in findings:
        # Apply normalization to normalized_value if it is an endpoint or host
        if f.type in (FindingType.API_ENDPOINT, FindingType.URL_ROUTE):
            f.normalized_value = Normalizer.normalize_endpoint(f.normalized_value)
        elif f.type == FindingType.API_HOST:
            f.normalized_value = Normalizer.normalize_host(f.normalized_value)

        key = f"{f.type.value}:{f.normalized_value}"
        grouped[key].append(f)

    deduped: List[Finding] = []

    for group in grouped.values():
        primary = group[0]
        all_occurrences: List[Occurrence] = []
        seen_occ = set()

        for item in group:
            items_to_check = item.occurrences if item.occurrences else [
                Occurrence(
                    source_file=item.source_file,
                    source_url=item.source_url,
                    line=item.line,
                    column=item.column,
                    snippet=item.snippet,
                    raw_value=item.value,
                )
            ]

            for occ in items_to_check:
                occ_key = (occ.source_file or "", occ.source_url or "", occ.line or 0, occ.column or 0)
                if occ_key not in seen_occ:
                    seen_occ.add(occ_key)
                    all_occurrences.append(occ)

            # Merge unique tags
            for tag in item.tags:
                if tag not in primary.tags:
                    primary.tags.append(tag)

        primary.occurrences = all_occurrences
        deduped.append(primary)

    return deduped
