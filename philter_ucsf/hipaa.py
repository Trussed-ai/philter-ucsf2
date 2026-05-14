"""
HIPAA Safe Harbor / §164.514(b)(2) eighteen identifiers.

Used to annotate detections and to summarize which identifiers a filter config
may touch (heuristic; review for your deployment).
"""

from __future__ import annotations

import json
import os
import re
from typing import NamedTuple

# id 1..18 — short keys stable for APIs
HIPAA_18 = (
    {"id": 1, "key": "name", "label": "Names"},
    {
        "id": 2,
        "key": "geo_substate",
        "label": "Geographic subdivisions smaller than a state",
    },
    {"id": 3, "key": "dates", "label": "Dates related to an individual"},
    {"id": 4, "key": "phone", "label": "Telephone numbers"},
    {"id": 5, "key": "fax", "label": "Fax numbers"},
    {"id": 6, "key": "email", "label": "Email addresses"},
    {"id": 7, "key": "ssn", "label": "Social Security numbers"},
    {"id": 8, "key": "mrn", "label": "Medical record numbers"},
    {
        "id": 9,
        "key": "health_plan",
        "label": "Health plan beneficiary numbers",
    },
    {"id": 10, "key": "account", "label": "Account numbers"},
    {
        "id": 11,
        "key": "cert_license",
        "label": "Certificate / license numbers",
    },
    {"id": 12, "key": "vehicle", "label": "Vehicle identifiers"},
    {
        "id": 13,
        "key": "device_serial",
        "label": "Device identifiers and serial numbers",
    },
    {"id": 14, "key": "url", "label": "Web URLs"},
    {"id": 15, "key": "ip", "label": "IP addresses"},
    {"id": 16, "key": "biometric", "label": "Biometric identifiers"},
    {"id": 17, "key": "photo", "label": "Full-face photographs"},
    {
        "id": 18,
        "key": "other_unique",
        "label": "Any other unique identifying number, characteristic, or code",
    },
)


HIPAA_KEY_TO_ID = {row["key"]: row["id"] for row in HIPAA_18}

HIPAA_CLI_ALIASES = {
    "social_security_number": 7,
    "social_security": 7,
    "street_address": 2,
    "address": 2,
    "telephone": 4,
    "telephone_numbers": 4,
    "dates": 3,
    "date": 3,
}

KNOWN_PHI_TYPES = frozenset(
    {
        "DATE",
        "Patient_Social_Security_Number",
        "Email",
        "Provider_Address_or_Location",
        "Age",
        "Name",
        "OTHER",
    }
)


def normalize_config_phi_type(pattern: dict) -> str:
    """phi_type from filter JSON, coerced to a known bucket for HIPAA inference."""
    pt = pattern.get("phi_type") or "OTHER"
    if pt not in KNOWN_PHI_TYPES:
        return "OTHER"
    return pt


def parse_active_hipaa_identifiers(raw) -> frozenset[int] | None:
    """Parse config/CLI value into a set of HIPAA ids. Accepts 1–18 and/or keys (name, email, …)."""
    if raw is None:
        return None
    if isinstance(raw, str):
        parts = [x.strip() for x in raw.split(",") if x.strip()]
    elif isinstance(raw, (list, tuple, set)):
        parts = [str(x).strip() for x in raw if str(x).strip()]
    else:
        raise TypeError(
            "active_hipaa_identifiers must be str, list, tuple, set, or omitted"
        )
    if not parts:
        return None
    ids: set[int] = set()
    unknown: list[str] = []
    for token in parts:
        tl = token.lower().replace(" ", "_")
        if tl.isdigit():
            n = int(tl)
            if 1 <= n <= 18:
                ids.add(n)
            else:
                unknown.append(token)
        elif tl in HIPAA_KEY_TO_ID:
            ids.add(HIPAA_KEY_TO_ID[tl])
        elif tl in HIPAA_CLI_ALIASES:
            ids.add(HIPAA_CLI_ALIASES[tl])
        else:
            unknown.append(token)
    if unknown:
        raise ValueError(
            "Unknown HIPAA tokens (use 1–18 or keys like name,email,ssn): "
            + ", ".join(unknown)
        )
    if not ids:
        return None
    return frozenset(ids)


def _pb(phi_type: str, pattern_blob: str) -> tuple[str, str]:
    return (phi_type or "").upper(), (pattern_blob or "").lower()


def infer_hipaa_ids(phi_type: str, pattern_blob: str) -> list[int]:
    """Map a coarse phi_type plus matched pattern titles (lower) to HIPAA id(s)."""
    pt, pb = _pb(phi_type, pattern_blob)
    ids: set[int] = set()

    if pt == "AGE" or re.search(r"\bage\b", pb):
        ids.add(3)

    if pt == "NAME" or any(
        x in pb
        for x in (
            "firstname",
            "lastnames",
            "lastname",
            "find names",
            "names pattern",
            "name indicator",
            "name_age",
            "patient name",
            "provider name",
            "family member",
        )
    ):
        ids.add(1)

    if pt == "Provider_Address_or_Location" or any(
        x in pb
        for x in (
            "street",
            "address",
            "city",
            "zip",
            "county",
            "suite",
            "hospital name",
            "geographic",
            "location",
            "lives in",
            "admitted from",
            "admission to",
            "brought to",
        )
    ):
        ids.add(2)

    if pt == "DATE" or any(
        x in pb
        for x in (
            "month_name",
            "as of date",
            "admission",
            "discharge",
            "birth",
            "_date",
            "date",
        )
    ):
        ids.add(3)

    if re.search(r"\bphone\b|\btel\b|telephone", pb):
        ids.add(4)
    if "fax" in pb:
        ids.add(5)

    if pt == "EMAIL" or "email" in pb:
        ids.add(6)

    if pt == "Patient_Social_Security_Number" or "ssn" in pb or "social security" in pb:
        ids.add(7)

    if "mrn" in pb or "medical record" in pb:
        ids.add(8)

    if any(
        x in pb
        for x in (
            "health plan",
            "beneficiary",
            "subscriber id",
            "insurance id",
            "member id",
        )
    ):
        ids.add(9)

    if "account" in pb and ("#" in pb or "number" in pb or "patient" in pb):
        ids.add(10)

    if any(
        x in pb
        for x in (
            "certificate",
            "license number",
            "dea ",
            "npi",
            "license",
        )
    ):
        ids.add(11)

    if any(x in pb for x in ("vehicle", "vin", "license plate")):
        ids.add(12)

    if any(
        x in pb
        for x in (
            "device",
            "serial number",
            "serial",
            "model and serial",
        )
    ):
        ids.add(13)

    if "url" in pb or "http" in pb or "www." in pb:
        ids.add(14)

    if re.search(r"\bip address\b|\bipv4\b|\bipv6\b", pb) or re.search(
        r"\bip\b", pb
    ):
        ids.add(15)

    if any(x in pb for x in ("biometric", "fingerprint", "voice print")):
        ids.add(16)

    if any(x in pb for x in ("face photo", "photograph", "full-face")):
        ids.add(17)

    if not ids:
        ids.add(18)
    return sorted(ids)


def pattern_hipaa_ids_for_pattern(pattern: dict) -> frozenset[int]:
    """HIPAA identifier ids (1–18) this exclude rule is grouped under (heuristic)."""
    pt = normalize_config_phi_type(pattern)
    title = (pattern.get("title") or "").lower()
    return frozenset(infer_hipaa_ids(pt, title))


def _resolve_filter_path(filters_path: str, base_path: str | None = None) -> str:
    if base_path is None:
        base_path = os.path.dirname(__file__)
    candidates = [
        os.path.join(base_path, filters_path),
        filters_path,
        os.path.join(os.getcwd(), filters_path),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    raise FileNotFoundError(f"Filter config not found. Tried: {', '.join(candidates)}")


def hipaa_coverage_report(filters_path: str, base_path: str | None = None) -> None:
    """Print which of the 18 HIPAA identifiers get at least one exclude rule (heuristic)."""
    path = _resolve_filter_path(filters_path, base_path)
    patterns = json.loads(open(path, "r", encoding="utf-8").read())
    covered: dict[int, list[str]] = {i: [] for i in range(1, 19)}

    for p in patterns:
        if not p.get("exclude", True):
            continue
        title = p.get("title", "") or ""
        pt = normalize_config_phi_type(p)
        ids = infer_hipaa_ids(pt, title.lower())
        for hid in ids:
            if title and title not in covered[hid]:
                covered[hid].append(title[:80])

    print("hipaa_id\tkey\tlabel\tcovered\tsample_patterns")
    for row in HIPAA_18:
        hid = row["id"]
        titles = covered[hid]
        print(
            f"{hid}\t{row['key']}\t{row['label']}\t"
            f"{'yes' if titles else 'NO'}\t"
            f"{'; '.join(titles[:3])}{'…' if len(titles) > 3 else ''}"
        )

    missing = [row["id"] for row in HIPAA_18 if not covered[row["id"]]]
    print(
        f"\n# Heuristic: {18 - len(missing)}/18 identifiers have ≥1 matching exclude rule title/phi_type."
    )
    if missing:
        print(
            f"# Possible gaps (add exclude rules or extend infer_hipaa_ids()): {missing}"
        )
    print(
        "\n# Safe Harbor: rely on expert review; this report is not legal advice."
    )


def hipaa_pattern_groups_report(filters_path: str, base_path: str | None = None) -> None:
    """Print exclude patterns grouped by HIPAA identifier for the given filter JSON."""
    path = _resolve_filter_path(filters_path, base_path)
    patterns = json.loads(open(path, "r", encoding="utf-8").read())
    groups: dict[int, list[str]] = {i: [] for i in range(1, 19)}
    for p in patterns:
        if not p.get("exclude", True):
            continue
        title = p.get("title", "") or ""
        for hid in pattern_hipaa_ids_for_pattern(p):
            groups[hid].append(title)
    for row in HIPAA_18:
        hid = row["id"]
        titles = sorted(set(groups[hid]))
        print(f"=== {hid} {row['key']} — {row['label']} ({len(titles)} exclude rules) ===")
        for tt in titles:
            print(tt)
        if not titles:
            print("(none — add exclude rules or adjust infer_hipaa_ids() heuristics)")
        print()


def _slug_title(title: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9]+", "_", (title or "untitled").strip())
    s = s.strip("_")
    return s if s else "untitled"


class HipaaMinimalCoverResult(NamedTuple):
    tokens_for_active_patterns: frozenset[str]
    ordered_chosen_titles: list[str]
    still_uncovered_hipaa_ids: set[int]


def hipaa_minimal_cover_active_pattern_tokens(
    patterns: list[dict],
) -> HipaaMinimalCoverResult:
    """
    Greedy approximate set cover: pick exclude rules (in config order as tie-break)
    so each HIPAA id 1–18 that appears on at least one rule is hit at least once.

    Returns HipaaMinimalCoverResult (unpackable in field order).
    """
    excludes = [p for p in patterns if p.get("exclude", True)]
    uncovered: set[int] = set(range(1, 19))
    picked_titles: list[str] = []
    picked_set: set[str] = set()

    while uncovered:
        best_i = None
        best_new_count = -1
        for i, p in enumerate(excludes):
            title = (p.get("title"), "").strip()
            if not title or title in picked_set:
                continue
            ids = pattern_hipaa_ids_for_pattern(p)
            new_ids = ids & uncovered
            n = len(new_ids)
            if n == 0:
                continue
            if n > best_new_count or (
                n == best_new_count and best_i is not None and i < best_i
            ):
                best_new_count = n
                best_i = i
        if best_i is None or best_new_count <= 0:
            break
        p = excludes[best_i]
        title = (p.get("title"), "").strip()
        picked_set.add(title)
        picked_titles.append(title)
        uncovered -= pattern_hipaa_ids_for_pattern(p)

    expanded: set[str] = set()
    for t in picked_titles:
        expanded.add(t)
        expanded.add(_slug_title(t))
    return HipaaMinimalCoverResult(
        frozenset(expanded), picked_titles, uncovered
    )
