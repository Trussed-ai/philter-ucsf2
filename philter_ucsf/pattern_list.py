"""List filter patterns without importing philter (avoids heavy deps like ``regex``)."""

from __future__ import annotations

import json
import os
import re
import sys


def _slug_pattern_title(title: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9]+", "_", (title or "untitled").strip())
    s = s.strip("_")
    return s if s else "untitled"


def summarize_filter_patterns(filters_path: str, base_path: str | None = None) -> None:
    """Print exclude patterns with resolved phi_type (OTHER = no phi_type in JSON)."""
    if base_path is None:
        base_path = os.path.dirname(__file__)
    candidates = [
        os.path.join(base_path, filters_path),
        filters_path,
        os.path.join(os.getcwd(), filters_path),
    ]
    path = next((c for c in candidates if os.path.isfile(c)), None)
    if path is None:
        raise FileNotFoundError(
            f"Filter config not found. Tried: {', '.join(candidates)}"
        )
    with open(path, "r", encoding="utf-8") as fp:
        patterns = json.load(fp)
    rows = []
    for i, p in enumerate(patterns):
        title = p.get("title", "")
        slug = _slug_pattern_title(title)
        ex = bool(p.get("exclude", True))
        pt = p.get("phi_type")
        resolved = pt if pt else "OTHER"
        rows.append((i, title, slug, p.get("type", ""), ex, resolved, pt or ""))
    print("idx\ttitle\tslug\tpattern_type\texclude\tphi_type_resolved\tphi_type_raw")
    for r in rows:
        if not r[4]:
            continue
        print(f"{r[0]}\t{r[1]}\t{r[2]}\t{r[3]}\t{r[4]}\t{r[5]}\t{r[6]}")
    other_n = sum(1 for r in rows if r[4] and r[5] == "OTHER")
    typed_n = sum(1 for r in rows if r[4] and r[5] != "OTHER")
    print(
        f"# exclude patterns: {other_n + typed_n} (OTHER: {other_n}, explicit phi_type: {typed_n})",
        file=sys.stderr,
    )
