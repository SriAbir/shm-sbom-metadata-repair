#!/usr/bin/env python3
"""
Industrial SHM extension for Black Duck CycloneDX SBOMs.

Purpose
-------
1. Re-route components using the actual PURL semantics rather than treating all
   pkg:github components as workflow components.
2. Add an exact-version Cargo/crates.io evidence adapter.
3. Conservatively attempt PURL resolution for missing-PURL components only when
   the local SBOM evidence does not indicate a private/proprietary component.
4. Generate SHM-style field-level repair proposals for the five SHM target
   fields while preserving existing non-empty values.
5. Optionally apply accepted repairs to copies of the source CycloneDX SBOMs and
   recompute target-field completeness.

The script never guesses a public package identity for components that appear
private/proprietary. Such rows are routed to internal-source resolution and the
Black Duck component/version UUIDs are retained for follow-up.

Example
-------
python3 Anonymous_shm_cargo_extension.py \
  --candidates Anonymous_component_repair_candidates.csv \
  --sbom sbom_2026-09-08_093554.cdx.json \
  --sbom sbom_2026-09-09_093122.cdx.json \
  --out-dir Anonymous_cargo_extension \
  --try-cratesio-resolve \
  --apply

Offline audit only:
python3 Anonymous_shm_cargo_extension.py \
  --candidates Anonymous_component_repair_candidates.csv \
  --out-dir Anonymous_cargo_extension_offline \
  --offline
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import quote

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None


CRATES_IO_API = "https://crates.io/api/v1"
PLACEHOLDERS = {"", "null", "none", "unknown", "n/a", "na", "[]", "{}"}
TARGET_FIELDS = ("license", "supplier", "repository_url", "hash_values", "distribution_url")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def clean(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def is_missing(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, (list, dict)):
        return len(value) == 0
    return clean(value).lower() in PLACEHOLDERS


def parse_json_cell(value: str, default: Any) -> Any:
    if is_missing(value):
        return default
    try:
        return json.loads(value)
    except Exception:
        return default


def parse_purl(purl: str) -> Optional[Dict[str, str]]:
    """Minimal Package URL parser sufficient for the current Cargo/GitHub data."""
    purl = clean(purl)
    if not purl.startswith("pkg:"):
        return None
    body = purl[4:].split("?", 1)[0].split("#", 1)[0]
    if "/" not in body:
        return None
    ptype, rest = body.split("/", 1)
    version = ""
    if "@" in rest:
        rest, version = rest.rsplit("@", 1)
    segments = [s for s in rest.split("/") if s]
    if not segments:
        return None
    name = segments[-1]
    namespace = "/".join(segments[:-1])
    return {
        "type": ptype.lower(),
        "namespace": namespace,
        "name": name,
        "version": version,
    }


def github_repo_url(parsed: Dict[str, str]) -> str:
    if parsed.get("type") != "github" or not parsed.get("namespace") or not parsed.get("name"):
        return ""
    return f"https://github.com/{parsed['namespace']}/{parsed['name']}"


def properties_map(row: Dict[str, str]) -> Dict[str, str]:
    props = parse_json_cell(row.get("properties_raw", ""), [])
    out: Dict[str, str] = {}
    if isinstance(props, list):
        for item in props:
            if isinstance(item, dict) and item.get("name"):
                out[clean(item.get("name"))] = clean(item.get("value"))
    return out


def normalize_supplier(s: str) -> str:
    x = clean(s)
    if x.lower().startswith("organization:"):
        x = x.split(":", 1)[1].strip()
    return re.sub(r"[^a-z0-9]+", "", x.lower())


def normalize_name(s: str) -> str:
    x = clean(s).split("/")[-1]
    return re.sub(r"[^a-z0-9]+", "", x.lower())


def private_internal_signals(row: Dict[str, str]) -> Tuple[int, List[str]]:
    """
    Return a conservative score and explicit local signals that a missing-PURL
    component should NOT be searched by name in public registries.

    These signals do not prove ownership; they only justify avoiding unsafe
    public-registry guessing.
    """
    score = 0
    signals: List[str] = []
    name = clean(row.get("name"))
    supplier = clean(row.get("supplier"))
    license_text = clean(row.get("license")).lower()
    props = properties_map(row)

    if "proprietary" in license_text or "commercial license" in license_text:
        score += 3
        signals.append("proprietary_or_commercial_license")

    if supplier and normalize_supplier(supplier) == normalize_name(name):
        score += 2
        signals.append("supplier_matches_component_name")

    if name.lower().startswith("bb"):
        score += 1
        signals.append("bb_prefixed_component_name")

    if props.get("BlackDuck-Component") and props.get("BlackDuck-ComponentVersion"):
        score += 1
        signals.append("blackduck_component_and_version_ids")

    if not props.get("BlackDuck-ComponentOrigin"):
        score += 1
        signals.append("no_blackduck_origin_id")

    return score, signals


@dataclass
class ResolutionRecord:
    project_id: str
    sbom_path: str
    component_index: str
    name: str
    version: str
    original_purl: str
    original_ecosystem: str
    corrected_route: str
    resolved_ecosystem: str
    resolved_purl: str
    resolution_status: str
    resolution_reason: str
    blackduck_component_id: str
    blackduck_component_version_id: str
    blackduck_origin_id: str
    private_signal_score: int
    private_signals: str
    resolved_at: str


@dataclass
class EvidenceRecord:
    project_id: str
    sbom_path: str
    component_index: str
    name: str
    version: str
    resolved_purl: str
    ecosystem: str
    exact_version_match: str
    evidence_status: str
    license: str
    repository_url: str
    distribution_url: str
    hash_algorithm: str
    hash_value: str
    supporting_metadata_source: str
    source_url: str
    artifact_url: str
    retrieval_error: str
    retrieved_at: str


@dataclass
class ProposalRecord:
    project_id: str
    sbom_path: str
    component_index: str
    name: str
    version: str
    resolved_purl: str
    ecosystem: str
    field_name: str
    original_value: str
    proposed_value: str
    semantic_decision: str
    decision_reason: str
    supporting_metadata_source: str
    source_url: str
    artifact_url: str
    exact_version_match: str
    generated_at: str


class CratesIoClient:
    def __init__(self, timeout: float = 20.0, sleep_seconds: float = 0.15, user_agent: str = "SHM-FSE-industrial-study/1.0"):
        if requests is None:
            raise RuntimeError("The 'requests' package is required for online crates.io retrieval.")
        self.timeout = timeout
        self.sleep_seconds = sleep_seconds
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": user_agent,
            "Accept": "application/json",
        })
        self.cache: Dict[Tuple[str, str], Dict[str, Any]] = {}

    def exact_version(self, crate: str, version: str) -> Dict[str, Any]:
        key = (crate, version)
        if key in self.cache:
            return self.cache[key]
        url = f"{CRATES_IO_API}/crates/{quote(crate, safe='')}/{quote(version, safe='')}"
        try:
            r = self.session.get(url, timeout=self.timeout)
            if r.status_code == 404:
                result = {"ok": False, "status": 404, "url": url, "error": "not_found"}
            else:
                r.raise_for_status()
                payload = r.json()
                v = payload.get("version") or {}
                result = {"ok": True, "status": r.status_code, "url": url, "version": v}
        except Exception as exc:
            result = {"ok": False, "status": "", "url": url, "error": f"{type(exc).__name__}: {exc}"}
        self.cache[key] = result
        if self.sleep_seconds > 0:
            time.sleep(self.sleep_seconds)
        return result


def cargo_evidence(row: Dict[str, str], resolved_purl: str, client: CratesIoClient) -> EvidenceRecord:
    parsed = parse_purl(resolved_purl) or {}
    crate = parsed.get("name", "")
    version = parsed.get("version", "")
    result = client.exact_version(crate, version)
    common = dict(
        project_id=row.get("project_id", ""),
        sbom_path=row.get("sbom_path", ""),
        component_index=row.get("component_index", ""),
        name=row.get("name", ""),
        version=row.get("version", ""),
        resolved_purl=resolved_purl,
        ecosystem="cargo",
        retrieved_at=utc_now(),
    )
    if not result.get("ok"):
        return EvidenceRecord(
            **common,
            exact_version_match="false",
            evidence_status="retrieval_failed",
            license="",
            repository_url="",
            distribution_url="",
            hash_algorithm="",
            hash_value="",
            supporting_metadata_source="crates.io exact-version API",
            source_url=clean(result.get("url")),
            artifact_url="",
            retrieval_error=clean(result.get("error")),
        )

    v = result.get("version") or {}
    returned_crate = clean(v.get("crate"))
    returned_version = clean(v.get("num"))
    exact = returned_crate.lower() == crate.lower() and returned_version == version
    dl_path = clean(v.get("dl_path"))
    dist_url = f"https://crates.io{dl_path}" if dl_path.startswith("/") else dl_path

    return EvidenceRecord(
        **common,
        exact_version_match="true" if exact else "false",
        evidence_status="exact_version_found" if exact else "identity_mismatch",
        license=clean(v.get("license")),
        repository_url=clean(v.get("repository")),
        distribution_url=dist_url,
        hash_algorithm="SHA-256" if clean(v.get("checksum")) else "",
        hash_value=clean(v.get("checksum")),
        supporting_metadata_source="crates.io exact-version API",
        source_url=clean(result.get("url")),
        artifact_url=dist_url,
        retrieval_error="",
    )


def github_evidence(row: Dict[str, str], resolved_purl: str) -> EvidenceRecord:
    parsed = parse_purl(resolved_purl) or {}
    repo = github_repo_url(parsed)
    exact = bool(repo and parsed.get("version"))
    return EvidenceRecord(
        project_id=row.get("project_id", ""),
        sbom_path=row.get("sbom_path", ""),
        component_index=row.get("component_index", ""),
        name=row.get("name", ""),
        version=row.get("version", ""),
        resolved_purl=resolved_purl,
        ecosystem="github",
        exact_version_match="true" if exact else "false",
        evidence_status="purl_repository_identity" if exact else "insufficient_github_identity",
        license="",
        repository_url=repo,
        distribution_url="",
        hash_algorithm="",
        hash_value="",
        supporting_metadata_source="GitHub PURL identity",
        source_url=repo,
        artifact_url="",
        retrieval_error="",
        retrieved_at=utc_now(),
    )


def row_value(row: Dict[str, str], field: str) -> str:
    return clean(row.get(field, ""))


def generate_proposals(row: Dict[str, str], ev: EvidenceRecord) -> List[ProposalRecord]:
    """Generate at most one proposal per occurrence + target field."""
    out: List[ProposalRecord] = []
    if ev.exact_version_match != "true" or ev.evidence_status not in {"exact_version_found", "purl_repository_identity"}:
        return out

    def add(field: str, proposed: str, decision: str, reason: str, artifact_url: str = "") -> None:
        if not proposed or not is_missing(row_value(row, field)):
            return
        out.append(ProposalRecord(
            project_id=row.get("project_id", ""),
            sbom_path=row.get("sbom_path", ""),
            component_index=row.get("component_index", ""),
            name=row.get("name", ""),
            version=row.get("version", ""),
            resolved_purl=ev.resolved_purl,
            ecosystem=ev.ecosystem,
            field_name=field,
            original_value=row_value(row, field),
            proposed_value=proposed,
            semantic_decision=decision,
            decision_reason=reason,
            supporting_metadata_source=ev.supporting_metadata_source,
            source_url=ev.source_url,
            artifact_url=artifact_url or ev.artifact_url,
            exact_version_match=ev.exact_version_match,
            generated_at=utc_now(),
        ))

    # License: current Industrial components already contain a license. Keep the
    # branch for future industrial SBOMs but do not overwrite non-empty values.
    add(
        "license",
        ev.license,
        "accept",
        "exact-version Cargo license metadata",
    )

    # Supplier: intentionally no automatic mapping from crates.io owners or
    # publishers. The role is not equivalent to CycloneDX supplier.

    add(
        "repository_url",
        ev.repository_url,
        "accept",
        "explicit source repository associated with the identified component/version",
    )

    add(
        "distribution_url",
        ev.distribution_url,
        "accept",
        "exact-version registry download path",
        artifact_url=ev.distribution_url,
    )

    if ev.hash_value and ev.distribution_url and ev.artifact_url == ev.distribution_url:
        add(
            "hash_values",
            f"{ev.hash_algorithm}:{ev.hash_value}",
            "accept",
            "SHA-256 checksum is tied to the same exact-version crate artifact as the distribution URL",
            artifact_url=ev.distribution_url,
        )

    return out


def route_row(row: Dict[str, str], client: Optional[CratesIoClient], try_cratesio_resolve: bool) -> Tuple[ResolutionRecord, Optional[EvidenceRecord]]:
    purl = clean(row.get("purl"))
    parsed = parse_purl(purl)
    props = properties_map(row)
    score, signals = private_internal_signals(row)
    now = utc_now()

    base = dict(
        project_id=row.get("project_id", ""),
        sbom_path=row.get("sbom_path", ""),
        component_index=row.get("component_index", ""),
        name=row.get("name", ""),
        version=row.get("version", ""),
        original_purl=purl,
        original_ecosystem=row.get("ecosystem_normalized", row.get("ecosystem", "")),
        blackduck_component_id=props.get("BlackDuck-Component", ""),
        blackduck_component_version_id=props.get("BlackDuck-ComponentVersion", ""),
        blackduck_origin_id=props.get("BlackDuck-ComponentOrigin", ""),
        private_signal_score=score,
        private_signals=";".join(signals),
        resolved_at=now,
    )

    if parsed and parsed.get("type") == "cargo" and parsed.get("name") and parsed.get("version"):
        rr = ResolutionRecord(
            **base,
            corrected_route="cargo_adapter",
            resolved_ecosystem="cargo",
            resolved_purl=purl,
            resolution_status="resolved_from_existing_purl",
            resolution_reason="exact Cargo package and version are encoded in the existing PURL",
        )
        ev = cargo_evidence(row, purl, client) if client else None
        return rr, ev

    if parsed and parsed.get("type") == "github" and parsed.get("namespace") and parsed.get("name"):
        # Important: pkg:github does not imply a workflow component. The current
        # Industry rows are library components (ThreadX/wolfSSL), so route them
        # by identity rather than blanket-excluding them as workflows.
        rr = ResolutionRecord(
            **base,
            corrected_route="github_identity_adapter",
            resolved_ecosystem="github",
            resolved_purl=purl,
            resolution_status="resolved_from_existing_purl",
            resolution_reason="GitHub PURL identifies a repository; GitHub hosting alone is not evidence of a workflow component",
        )
        return rr, github_evidence(row, purl)

    if parsed:
        rr = ResolutionRecord(
            **base,
            corrected_route="manual_review",
            resolved_ecosystem=parsed.get("type", ""),
            resolved_purl=purl,
            resolution_status="unsupported_purl_type",
            resolution_reason=f"PURL type '{parsed.get('type', '')}' has no adapter in this industrial extension",
        )
        return rr, None

    # Missing PURL: do NOT search public registries when local evidence strongly
    # indicates a private/proprietary component. This prevents false matches.
    if score >= 4:
        rr = ResolutionRecord(
            **base,
            corrected_route="internal_source_resolution",
            resolved_ecosystem="private_or_internal",
            resolved_purl="",
            resolution_status="public_purl_not_safely_resolvable",
            resolution_reason="local evidence indicates private/proprietary component; use Black Duck/internal metadata rather than public registry guessing",
        )
        return rr, None

    # Optional conservative recovery for a public Cargo component whose PURL was
    # omitted: query EXACT name + EXACT version only. No fuzzy search, no latest.
    if try_cratesio_resolve and client and clean(row.get("name")) and clean(row.get("version")):
        candidate_name = clean(row.get("name")).split("/")[-1]
        candidate_version = clean(row.get("version"))
        result = client.exact_version(candidate_name, candidate_version)
        if result.get("ok"):
            v = result.get("version") or {}
            if clean(v.get("crate")).lower() == candidate_name.lower() and clean(v.get("num")) == candidate_version:
                resolved_purl = f"pkg:cargo/{candidate_name}@{candidate_version}"
                rr = ResolutionRecord(
                    **base,
                    corrected_route="cargo_adapter",
                    resolved_ecosystem="cargo",
                    resolved_purl=resolved_purl,
                    resolution_status="resolved_by_exact_name_version",
                    resolution_reason="exact crate name and exact version matched crates.io; no fuzzy/latest fallback used",
                )
                ev = cargo_evidence(row, resolved_purl, client)
                return rr, ev

    rr = ResolutionRecord(
        **base,
        corrected_route="manual_review",
        resolved_ecosystem="unknown",
        resolved_purl="",
        resolution_status="unresolved_identity",
        resolution_reason="insufficient evidence for a safe public package identity",
    )
    return rr, None


def write_dataclasses(path: Path, records: Iterable[Any], cls: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [f.name for f in cls.__dataclass_fields__.values()]
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in records:
            w.writerow(asdict(r))


def write_dict_rows(path: Path, rows: List[Dict[str, Any]], fieldnames: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in fieldnames})


def read_candidates(path: Path) -> List[Dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def build_summary(rows: List[Dict[str, str]], resolutions: List[ResolutionRecord], evidence: List[EvidenceRecord], proposals: List[ProposalRecord]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []

    def add(category: str, label: str, count: int, denominator: Optional[int] = None) -> None:
        denominator = len(rows) if denominator is None else denominator
        pct = (count / denominator * 100.0) if denominator else 0.0
        out.append({"category": category, "label": label, "count": count, "percentage": f"{pct:.2f}"})

    add("input", "component_occurrences", len(rows), len(rows))
    for k, v in sorted(Counter(r.original_ecosystem for r in resolutions).items()):
        add("original_ecosystem", k or "<empty>", v)
    for k, v in sorted(Counter(r.corrected_route for r in resolutions).items()):
        add("corrected_route", k, v)
    for k, v in sorted(Counter(r.resolution_status for r in resolutions).items()):
        add("resolution_status", k, v)
    for k, v in sorted(Counter(e.evidence_status for e in evidence).items()):
        add("evidence_status", k, v, len(evidence))
    for k, v in sorted(Counter(p.field_name for p in proposals).items()):
        add("proposal_field", k, v, len(proposals))
    for k, v in sorted(Counter(p.semantic_decision for p in proposals).items()):
        add("proposal_decision", k, v, len(proposals))
    return out


def target_field_present_component(component: Dict[str, Any], field: str) -> bool:
    if field == "license":
        licenses = component.get("licenses") or []
        if not licenses:
            return False
        for entry in licenses:
            if not isinstance(entry, dict):
                continue
            if not is_missing(entry.get("expression")):
                return True
            lic = entry.get("license") or {}
            if not is_missing(lic.get("id")) or not is_missing(lic.get("name")):
                return True
        return False
    if field == "supplier":
        return not is_missing((component.get("supplier") or {}).get("name"))
    if field == "hash_values":
        return bool(component.get("hashes"))
    refs = component.get("externalReferences") or []
    if field == "repository_url":
        return any(clean(r.get("type")).lower() == "vcs" and not is_missing(r.get("url")) for r in refs if isinstance(r, dict))
    if field == "distribution_url":
        return any(clean(r.get("type")).lower() == "distribution" and not is_missing(r.get("url")) for r in refs if isinstance(r, dict))
    raise KeyError(field)


def completeness_for_sboms(sboms: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    comps: List[Dict[str, Any]] = []
    for d in sboms.values():
        comps.extend(d.get("components") or [])
    n = len(comps)
    counts = {f: sum(target_field_present_component(c, f) for c in comps) for f in TARGET_FIELDS}
    total_present = sum(counts.values())
    total_cells = n * len(TARGET_FIELDS)
    result: Dict[str, Any] = {
        "component_occurrences": n,
        "target_field_cells": total_cells,
        "overall_present": total_present,
        "overall_completeness_pct": (total_present / total_cells * 100.0) if total_cells else 0.0,
    }
    for f, c in counts.items():
        result[f"{f}_present"] = c
        result[f"{f}_completeness_pct"] = (c / n * 100.0) if n else 0.0
    return result


def load_sboms(paths: List[Path]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for p in paths:
        with p.open(encoding="utf-8") as f:
            out[p.name] = json.load(f)
    return out


def add_external_reference(component: Dict[str, Any], ref_type: str, url: str) -> None:
    refs = component.setdefault("externalReferences", [])
    if any(clean(r.get("type")).lower() == ref_type.lower() and clean(r.get("url")) == url for r in refs if isinstance(r, dict)):
        return
    refs.append({"type": ref_type, "url": url})


def apply_proposals(sboms: Dict[str, Dict[str, Any]], proposals: List[ProposalRecord]) -> Tuple[int, List[str]]:
    applied = 0
    warnings: List[str] = []
    for p in proposals:
        if p.semantic_decision != "accept":
            continue
        basename = Path(p.sbom_path).name
        if basename not in sboms:
            warnings.append(f"SBOM not supplied for proposal: {basename}")
            continue
        try:
            idx = int(p.component_index)
            component = sboms[basename]["components"][idx]
        except Exception as exc:
            warnings.append(f"Cannot locate {basename} component_index={p.component_index}: {exc}")
            continue

        # Never overwrite populated target fields.
        if target_field_present_component(component, p.field_name):
            continue

        if p.field_name == "repository_url":
            add_external_reference(component, "vcs", p.proposed_value)
            applied += 1
        elif p.field_name == "distribution_url":
            add_external_reference(component, "distribution", p.proposed_value)
            applied += 1
        elif p.field_name == "hash_values":
            if ":" not in p.proposed_value:
                warnings.append(f"Malformed hash proposal: {p.proposed_value}")
                continue
            alg, digest = p.proposed_value.split(":", 1)
            component.setdefault("hashes", []).append({"alg": alg, "content": digest})
            applied += 1
        elif p.field_name == "license":
            # Safe generic representation for an SPDX expression; only used if
            # the original license field is actually empty.
            component.setdefault("licenses", []).append({"expression": p.proposed_value})
            applied += 1
        elif p.field_name == "supplier":
            # SHM does not infer Cargo owner/publisher as supplier.
            continue
    return applied, warnings


def main() -> int:
    ap = argparse.ArgumentParser(description="SHM industrial extension with Cargo/crates.io evidence adapter")
    ap.add_argument("--candidates", required=True, type=Path, help="Anonymous_component_repair_candidates.csv")
    ap.add_argument("--sbom", action="append", default=[], type=Path, help="Source CycloneDX SBOM; repeat for multiple files")
    ap.add_argument("--out-dir", type=Path, default=Path("Anonymous_shm_extension_output"))
    ap.add_argument("--offline", action="store_true", help="Do not call crates.io; produce routing diagnostics only")
    ap.add_argument("--try-cratesio-resolve", action="store_true", help="For non-private missing-PURL rows, try exact name+version on crates.io")
    ap.add_argument("--apply", action="store_true", help="Apply accepted repairs to copies of supplied SBOM files")
    ap.add_argument("--timeout", type=float, default=20.0)
    ap.add_argument("--sleep", type=float, default=0.15, help="Delay between crates.io requests")
    ap.add_argument("--user-agent", default="SHM-FSE-industrial-study/1.0")
    args = ap.parse_args()

    rows = read_candidates(args.candidates)
    args.out_dir.mkdir(parents=True, exist_ok=True)

    client: Optional[CratesIoClient] = None
    if not args.offline:
        client = CratesIoClient(timeout=args.timeout, sleep_seconds=args.sleep, user_agent=args.user_agent)

    resolutions: List[ResolutionRecord] = []
    evidence: List[EvidenceRecord] = []
    proposals: List[ProposalRecord] = []

    for row in rows:
        rr, ev = route_row(row, client, args.try_cratesio_resolve)
        resolutions.append(rr)
        if ev is not None:
            evidence.append(ev)
            proposals.extend(generate_proposals(row, ev))

    # Duplicate proposal guard: one occurrence + field must map to one semantic value.
    seen: Dict[Tuple[str, str, str, str], ProposalRecord] = {}
    for p in proposals:
        key = (Path(p.sbom_path).name, p.project_id, p.component_index, p.field_name)
        old = seen.get(key)
        if old and (old.proposed_value != p.proposed_value or old.semantic_decision != p.semantic_decision):
            raise RuntimeError(f"Conflicting duplicate proposal for {key}: {old.proposed_value!r} vs {p.proposed_value!r}")
        seen[key] = p
    proposals = list(seen.values())

    write_dataclasses(args.out_dir / "industrial_identity_resolution.csv", resolutions, ResolutionRecord)
    write_dataclasses(args.out_dir / "industrial_registry_evidence.csv", evidence, EvidenceRecord)
    write_dataclasses(args.out_dir / "industrial_repair_proposals.csv", proposals, ProposalRecord)

    summary = build_summary(rows, resolutions, evidence, proposals)
    write_dict_rows(args.out_dir / "industrial_extension_summary.csv", summary, ["category", "label", "count", "percentage"])

    # Additional unresolved/private list specifically for internal Black Duck follow-up.
    unresolved = [asdict(r) for r in resolutions if r.corrected_route in {"internal_source_resolution", "manual_review"}]
    write_dict_rows(
        args.out_dir / "industrial_internal_or_unresolved_components.csv",
        unresolved,
        [f.name for f in ResolutionRecord.__dataclass_fields__.values()],
    )

    if args.sbom:
        sboms = load_sboms(args.sbom)
        before = completeness_for_sboms(sboms)
        after = dict(before)
        applied = 0
        warnings: List[str] = []
        if args.apply:
            # Deep copy via JSON serialization to keep source data untouched.
            repaired = json.loads(json.dumps(sboms))
            applied, warnings = apply_proposals(repaired, proposals)
            after = completeness_for_sboms(repaired)
            for name, payload in repaired.items():
                out = args.out_dir / f"repaired_{name}"
                with out.open("w", encoding="utf-8") as f:
                    json.dump(payload, f, indent=2, ensure_ascii=False)
        comp_rows = []
        for metric in sorted(set(before) | set(after)):
            b = before.get(metric, "")
            a = after.get(metric, "")
            delta = ""
            if isinstance(b, (int, float)) and isinstance(a, (int, float)):
                delta = a - b
            comp_rows.append({"metric": metric, "before": b, "after": a, "delta": delta})
        comp_rows.append({"metric": "accepted_repairs_applied", "before": 0, "after": applied, "delta": applied})
        write_dict_rows(args.out_dir / "industrial_completeness_before_after.csv", comp_rows, ["metric", "before", "after", "delta"])
        if warnings:
            (args.out_dir / "application_warnings.txt").write_text("\n".join(warnings) + "\n", encoding="utf-8")

    print(f"Input components: {len(rows)}")
    print("Corrected routes:")
    for k, v in Counter(r.corrected_route for r in resolutions).most_common():
        print(f"  {k}: {v}")
    print("Resolution statuses:")
    for k, v in Counter(r.resolution_status for r in resolutions).most_common():
        print(f"  {k}: {v}")
    print(f"Evidence records: {len(evidence)}")
    print(f"Repair proposals: {len(proposals)}")
    print(f"Output directory: {args.out_dir}")
    if args.offline:
        print("NOTE: offline mode did not retrieve crates.io metadata; Cargo proposals require an online run.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
