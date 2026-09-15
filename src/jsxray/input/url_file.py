import re
from pathlib import Path
from typing import List
from jsxray.utils.helpers import normalize_url


def parse_url_file(file_path: str) -> List[str]:
    """Reads a file containing URLs, stripping comments, handling glued/multi-url lines, and deduplicating."""
    path = Path(file_path).expanduser().resolve()
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"URL file does not exist or is not a file: {file_path}")

    urls: List[str] = []
    seen = set()

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line_no_comment = line.split("#", 1)[0].strip()
            if not line_no_comment:
                continue

            # Split lines with multiple concatenated URLs (e.g. url1.jshttps://url2.js)
            raw_splits = re.split(r"(?<=.)(?=https?://)", line_no_comment)
            candidate_tokens = []
            for piece in raw_splits:
                candidate_tokens.extend(piece.split())

            for candidate in candidate_tokens:
                candidate = candidate.strip()
                if not candidate:
                    continue

                if candidate.startswith("//"):
                    candidate = f"https:{candidate}"
                elif not (candidate.startswith("http://") or candidate.startswith("https://")):
                    if "/" in candidate and "." in candidate.split("/")[0]:
                        candidate = f"https://{candidate}"
                    elif "." in candidate:
                        candidate = f"https://{candidate}"
                    else:
                        continue

                normalized = normalize_url(candidate)
                if normalized and normalized not in seen:
                    seen.add(normalized)
                    urls.append(candidate)

    return urls

