#!/usr/bin/env python3
"""
Phase 18B.2.3: Deterministic semantic-rule validation.

This script applies conservative, reproducible semantic rules to repair proposals
that were previously classified as outside the scope of structural/static
validation.

It is NOT human validation and it is NOT an LLM evaluation. It is a second,
rule-based validation layer.

Recommended input:
    data/human_validation_sample_with_evidence.csv
or, for the full queue:
    a CSV containing the same proposal and evidence columns.

Outputs:
    data/semantic_rule_validation_results.csv
    data/semantic_rule_human_review_queue.csv
    data/semantic_rule_validation_summary.csv
    data/semantic_rule_validation_summary_by_field.csv
"""

from __future__ import annotations

import argparse
import csv
import re
import urllib.parse
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


MISSING_VALUES = {
    "",
    "null",
    "none",
    "unknown",
    "n/a",
    "na",
    "[]",
    "{}",
}

COMMON_SPDX_IDS = {
    "0BSD",
    "AFL-3.0",
    "AGPL-3.0-only",
    "AGPL-3.0-or-later",
    "Apache-1.1",
    "Apache-2.0",
    "Artistic-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "BSD-4-Clause",
    "BSL-1.0",
    "CC0-1.0",
    "CDDL-1.0",
    "CDDL-1.1",
    "EPL-1.0",
    "EPL-2.0",
    "GPL-1.0-only",
    "GPL-1.0-or-later",
    "GPL-2.0-only",
    "GPL-2.0-or-later",
    "GPL-3.0-only",
    "GPL-3.0-or-later",
    "ISC",
    "LGPL-2.0-only",
    "LGPL-2.0-or-later",
    "LGPL-2.1-only",
    "LGPL-2.1-or-later",
    "LGPL-3.0-only",
    "LGPL-3.0-or-later",
    "MIT",
    "MPL-1.1",
    "MPL-2.0",
    "MS-PL",
    "OFL-1.1",
    "OSL-3.0",
    "PostgreSQL",
    "Python-2.0",
    "Unlicense",
    "WTFPL",
    "Zlib",
}

# Conservative aliases used only when the equivalence is straightforward.
LICENSE_ALIASES = {
    "apache 2": "Apache-2.0",
    "apache 2.0": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "apache software license": "Apache-2.0",
    "mit license": "MIT",
    "bsd 2-clause": "BSD-2-Clause",
    "bsd 3-clause": "BSD-3-Clause",
    "isc license": "ISC",
    "mozilla public license 2.0": "MPL-2.0",
    "eclipse public license 2.0": "EPL-2.0",
    "the unlicense": "Unlicense",
}

KNOWN_REPOSITORY_HOSTS = {
    "github.com",
    "www.github.com",
    "gitlab.com",
    "www.gitlab.com",
    "bitbucket.org",
    "www.bitbucket.org",
    "codeberg.org",
    "www.codeberg.org",
    "sourceforge.net",
    "www.sourceforge.net",
    "gitbox.apache.org",
    "git-wip-us.apache.org",
}


Result = Dict[str, str]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def clean(value: object) -> str:
    if value is None:
        return ""
    return str(value).strip()


def lower(value: object) -> str:
    return clean(value).lower()


def casefold(value: object) -> str:
    return clean(value).casefold()


def is_missing(value: object) -> bool:
    text = clean(value)
    return text == "" or text.lower() in MISSING_VALUES


def truthy(value: object) -> bool:
    return lower(value) in {"true", "1", "yes", "y"}


def load_csv(path: Path) -> Tuple[List[Dict[str, str]], List[str]]:
    if not path.exists():
        raise FileNotFoundError(f"Missing input file: {path}")

    with path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        rows = list(reader)
        return rows, list(reader.fieldnames or [])


def write_csv(path: Path, rows: Iterable[Dict[str, str]], fieldnames: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def parse_http_url(value: object) -> Optional[urllib.parse.ParseResult]:
    text = clean(value)
    if not text:
        return None

    try:
        parsed = urllib.parse.urlparse(text)
    except Exception:
        return None

    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        return None

    return parsed


def normalize_repository_url(value):
    value = clean(value)

    if not value:
        return ""

    if value.startswith("scm:git:"):
        value = value[len("scm:git:"):]

    if value.startswith("git+"):
        value = value[len("git+"):]

    if value.startswith("git://"):
        value = "https://" + value[len("git://"):]

    if value.startswith("ssh://git@"):
        value = "https://" + value[len("ssh://git@"):]

    if value.startswith("git@") and ":" in value:
        host_path = value[len("git@"):]
        host, path = host_path.split(":", 1)
        value = f"https://{host}/{path}"

    value = value.rstrip("/")

    if value.endswith(".git"):
        value = value[:-4]

    return value.casefold()


def canonical_license(value: object) -> str:
    text = clean(value)
    if not text:
        return ""

    if text in COMMON_SPDX_IDS:
        return text

    alias = LICENSE_ALIASES.get(text.casefold())
    if alias:
        return alias

    return text


def base_evidence_check(row: Dict[str, str]) -> Optional[Result]:
    if lower(row.get("evidence_status")) != "success":
        return make_result(
            label="uncertain",
            relation="insufficient_evidence",
            confidence="high",
            decision="manual_review",
            reason="Registry evidence retrieval was not successful.",
            human_review="yes",
            rule="SEM-BASE-01",
        )

    if not truthy(row.get("evidence_exact_version_match")):
        return make_result(
            label="uncertain",
            relation="insufficient_evidence",
            confidence="high",
            decision="manual_review",
            reason="The evidence does not confirm the exact component version.",
            human_review="yes",
            rule="SEM-BASE-02",
        )

    if is_missing(row.get("new_value")):
        return make_result(
            label="incorrect",
            relation="semantic_mismatch",
            confidence="high",
            decision="reject",
            reason="The proposed repair value is empty.",
            human_review="no",
            rule="SEM-BASE-03",
        )

    return None


def make_result(
    *,
    label: str,
    relation: str,
    confidence: str,
    decision: str,
    reason: str,
    human_review: str,
    rule: str,
) -> Result:
    return {
        "semantic_rule_label": label,
        "semantic_evidence_relation": relation,
        "semantic_rule_confidence": confidence,
        "semantic_rule_decision": decision,
        "semantic_rule_reason": reason,
        "semantic_requires_human_review": human_review,
        "semantic_rule_id": rule,
    }


def validate_supplier(row: Dict[str, str]) -> Result:
    """Validate whether the preserved party role supports CycloneDX supplier."""
    proposed = clean(row.get("new_value"))
    evidence_value = clean(
        row.get("evidence_party_value")
        or row.get("evidence_supplier")
    )
    role = lower(
        row.get("evidence_party_role")
        or row.get("evidence_supplier_role")
        or row.get("evidence_role")
    )
    source_field = clean(
        row.get("evidence_party_source_field")
        or row.get("evidence_supplier_source_field")
    )

    if not evidence_value:
        return make_result(
            label="uncertain",
            relation="insufficient_evidence",
            confidence="high",
            decision="manual_review",
            reason="No party value with preserved provenance is available for supplier validation.",
            human_review="yes",
            rule="SEM-SUP-01",
        )

    if casefold(proposed) != casefold(evidence_value):
        return make_result(
            label="incorrect",
            relation="semantic_mismatch",
            confidence="high",
            decision="reject",
            reason="The proposed supplier does not match the preserved party value from retrieval.",
            human_review="no",
            rule="SEM-SUP-02",
        )

    # Only roles that explicitly denote a supplying/vendor party are accepted.
    # Publisher, author, maintainer, developer, organization and package scope
    # are deliberately NOT treated as equivalent to CycloneDX supplier.
    explicit_supplier_roles = {
        "supplier",
        "vendor",
        "producer",
        "distributor",
        "manufacturer",
    }
    ambiguous_roles = {
        "author",
        "author_email",
        "maintainer",
        "maintainer_email",
        "developer",
        "developer_organization",
        "organization",
        "owner",
        "publisher",
        "publisher_account",
        "npm_scope",
        "scope",
        "namespace",
        "contact",
        "email",
    }

    if role in explicit_supplier_roles:
        return make_result(
            label="correct",
            relation="explicit_role_match",
            confidence="high",
            decision="accept",
            reason=(
                f"The retrieved party is explicitly identified with the role '{role}', "
                "which is suitable for the CycloneDX supplier field."
            ),
            human_review="sample_only",
            rule="SEM-SUP-03",
        )

    if role in ambiguous_roles:
        return make_result(
            label="uncertain",
            relation="role_not_equivalent",
            confidence="high",
            decision="manual_review",
            reason=(
                f"The retrieved party has role '{role}', which does not by itself establish "
                "that the party is the CycloneDX supplier."
            ),
            human_review="yes",
            rule="SEM-SUP-04",
        )

    details = f" Source field: {source_field}." if source_field else ""
    return make_result(
        label="uncertain",
        relation="insufficient_role_provenance",
        confidence="high",
        decision="manual_review",
        reason=(
            "The retrieved party matches the proposed value, but its role does not "
            "establish supplier semantics." + details
        ),
        human_review="yes",
        rule="SEM-SUP-05",
    )

def validate_license(row: Dict[str, str]) -> Result:
    proposed = canonical_license(row.get("new_value"))
    evidence = canonical_license(row.get("evidence_license"))

    if not evidence:
        return make_result(
            label="uncertain",
            relation="insufficient_evidence",
            confidence="high",
            decision="manual_review",
            reason="No registry license value is available for semantic comparison.",
            human_review="yes",
            rule="SEM-LIC-01",
        )

    if casefold(proposed) == casefold(evidence):
        relation = "explicit_match"
        decision = "accept"
        human_review = "sample_only"
        confidence = "high"
        label = "correct"
        reason = "The proposed license exactly matches the exact-version registry license evidence."

        if proposed not in COMMON_SPDX_IDS:
            label = "partially_correct"
            relation = "strong_inference"
            decision = "accept_with_caution"
            human_review = "yes"
            confidence = "medium"
            reason = (
                "The proposed license matches the registry value, but the value is "
                "not recognized by this script as a canonical SPDX identifier."
            )

        return make_result(
            label=label,
            relation=relation,
            confidence=confidence,
            decision=decision,
            reason=reason,
            human_review=human_review,
            rule="SEM-LIC-02",
        )

    proposed_original = clean(row.get("new_value"))
    evidence_original = clean(row.get("evidence_license"))

    if proposed in COMMON_SPDX_IDS and evidence in COMMON_SPDX_IDS:
        return make_result(
            label="incorrect",
            relation="semantic_mismatch",
            confidence="high",
            decision="reject",
            reason=(
                f"The proposed SPDX identifier ({proposed_original}) differs from "
                f"the registry-supported identifier ({evidence_original})."
            ),
            human_review="yes",
            rule="SEM-LIC-03",
        )

    # Compound/free-text cases are not safely resolvable without a stronger parser.
    proposed_tokens = set(re.findall(r"[A-Za-z0-9.+-]+", proposed.casefold()))
    evidence_tokens = set(re.findall(r"[A-Za-z0-9.+-]+", evidence.casefold()))
    overlap = len(proposed_tokens & evidence_tokens)

    if overlap > 0:
        return make_result(
            label="partially_correct",
            relation="weak_inference",
            confidence="medium",
            decision="manual_review",
            reason=(
                "The proposed and registry license values are related, but they are "
                "not an exact normalized match and may require SPDX normalization."
            ),
            human_review="yes",
            rule="SEM-LIC-04",
        )

    return make_result(
        label="uncertain",
        relation="insufficient_evidence",
        confidence="medium",
        decision="manual_review",
        reason=(
            "The proposed license does not exactly match the registry value, and the "
            "current deterministic rules cannot establish semantic equivalence."
        ),
        human_review="yes",
        rule="SEM-LIC-05",
    )


def validate_repository(row: Dict[str, str]) -> Result:
    """Accept repository repairs only when the value is a clear source-repository URL."""
    proposed_raw = clean(row.get("normalized_repository_url")) or clean(row.get("new_value"))
    evidence_raw = clean(row.get("evidence_repository_url"))

    proposed = normalize_repository_url(proposed_raw)
    evidence = normalize_repository_url(evidence_raw)

    if not evidence_raw:
        return make_result(
            label="uncertain",
            relation="insufficient_evidence",
            confidence="high",
            decision="manual_review",
            reason="No registry repository value is available for comparison.",
            human_review="yes",
            rule="SEM-REP-01",
        )

    if not proposed or not evidence:
        return make_result(
            label="uncertain",
            relation="insufficient_evidence",
            confidence="medium",
            decision="manual_review",
            reason="The repository reference could not be normalized reliably.",
            human_review="yes",
            rule="SEM-REP-02",
        )

    # The proposal is derived from the retrieved repository field, so equality
    # alone is not semantic validation.  First protect against accidental drift.
    if proposed.casefold() != evidence.casefold():
        return make_result(
            label="incorrect",
            relation="semantic_mismatch",
            confidence="high",
            decision="reject",
            reason="The proposed repository differs from the retrieved repository metadata.",
            human_review="no",
            rule="SEM-REP-03",
        )

    parsed = parse_http_url(proposed)
    if parsed is None:
        return make_result(
            label="uncertain",
            relation="repository_type_unresolved",
            confidence="medium",
            decision="manual_review",
            reason="The retrieved repository reference is not a normalized HTTP(S) source-repository URL.",
            human_review="yes",
            rule="SEM-REP-04",
        )

    host = (parsed.hostname or "").lower()
    path_parts = [part for part in parsed.path.split("/") if part]
    static_result = lower(row.get("static_validation_result"))

    # A static pass on a recognized VCS host with a project path is sufficient
    # for an automatic repository repair.  It establishes repository type, not
    # merely that the URL exists in package metadata.
    if static_result == "pass" and host in KNOWN_REPOSITORY_HOSTS and len(path_parts) >= 2:
        return make_result(
            label="correct",
            relation="source_repository_supported",
            confidence="high",
            decision="accept",
            reason=(
                "The retrieved value is a structurally valid project path on a recognized "
                "source-control host."
            ),
            human_review="sample_only",
            rule="SEM-REP-05",
        )

    # General project/homepage hosts are deliberately not accepted merely
    # because a registry labels them as a URL.  Example: a project website can
    # be valid package metadata without being the source repository.
    return make_result(
        label="uncertain",
        relation="repository_type_unresolved",
        confidence="high",
        decision="manual_review",
        reason=(
            "The retrieved URL may be valid project metadata, but the available provenance "
            "does not establish that it is the component's source-code repository."
        ),
        human_review="yes",
        rule="SEM-REP-06",
    )

def validate_hash(row: Dict[str, str]) -> Result:
    """Require exact-artifact identity in addition to hash-value agreement."""
    proposed_values = clean(row.get("new_value"))
    evidence_values = clean(row.get("evidence_hash_values"))
    evidence_algorithms = clean(row.get("evidence_hash_algorithms"))

    usable = truthy(row.get("evidence_hash_usable_for_auto_repair"))
    artifact_match = truthy(row.get("evidence_artifact_match"))
    match_method = clean(row.get("evidence_artifact_match_method"))
    hash_status = lower(row.get("evidence_hash_status"))

    if not usable or not artifact_match:
        return make_result(
            label="uncertain",
            relation="artifact_identity_not_established",
            confidence="high",
            decision="manual_review",
            reason="The hash is not supported by an exact, uniquely identified artifact match.",
            human_review="yes",
            rule="SEM-HASH-01",
        )

    if hash_status and hash_status != "exact_artifact_hash_available":
        return make_result(
            label="uncertain",
            relation="artifact_identity_not_established",
            confidence="high",
            decision="manual_review",
            reason=f"The retrieval hash status is '{hash_status}', not exact_artifact_hash_available.",
            human_review="yes",
            rule="SEM-HASH-02",
        )

    if not evidence_values:
        return make_result(
            label="uncertain",
            relation="insufficient_evidence",
            confidence="high",
            decision="manual_review",
            reason="No exact-artifact hash value is available for comparison.",
            human_review="yes",
            rule="SEM-HASH-03",
        )

    if casefold(proposed_values) != casefold(evidence_values):
        return make_result(
            label="incorrect",
            relation="semantic_mismatch",
            confidence="high",
            decision="reject",
            reason="The proposed hash differs from the hash retrieved for the matched artifact.",
            human_review="no",
            rule="SEM-HASH-04",
        )

    if lower(row.get("static_validation_result")) != "pass":
        return make_result(
            label="uncertain",
            relation="hash_representation_unresolved",
            confidence="high",
            decision="manual_review",
            reason=(
                "Exact-artifact identity is established, but static validation did not fully "
                "validate the hash representation or algorithm."
            ),
            human_review="yes",
            rule="SEM-HASH-05",
        )

    return make_result(
        label="correct",
        relation="exact_artifact_match",
        confidence="high",
        decision="accept",
        reason=(
            "The proposed hash matches the retrieved hash for the exact artifact "
            f"({match_method or 'exact match'}; {evidence_algorithms or 'algorithm metadata available'})."
        ),
        human_review="sample_only",
        rule="SEM-HASH-06",
    )

def validate_distribution(row: Dict[str, str]) -> Result:
    proposed = clean(row.get("new_value"))
    evidence = clean(row.get("evidence_distribution_url"))

    if not evidence:
        return make_result(
            label="uncertain",
            relation="insufficient_evidence",
            confidence="high",
            decision="manual_review",
            reason="No exact-version distribution URL metadata is available.",
            human_review="yes",
            rule="SEM-DIST-01",
        )

    if proposed.rstrip("/").casefold() != evidence.rstrip("/").casefold():
        return make_result(
            label="incorrect",
            relation="semantic_mismatch",
            confidence="high",
            decision="reject",
            reason="The proposed distribution URL differs from the retrieved exact-version metadata.",
            human_review="no",
            rule="SEM-DIST-02",
        )

    if lower(row.get("static_validation_result")) == "pass":
        return make_result(
            label="correct",
            relation="package_version_distribution_supported",
            confidence="high",
            decision="accept",
            reason=(
                "The distribution URL matches the retrieved exact-version metadata and passed "
                "ecosystem-specific package/version/artifact checks."
            ),
            human_review="sample_only",
            rule="SEM-DIST-03",
        )

    return make_result(
        label="uncertain",
        relation="distribution_semantics_unresolved",
        confidence="medium",
        decision="manual_review",
        reason="Static validation did not establish that the distribution reference is suitable for automatic repair.",
        human_review="yes",
        rule="SEM-DIST-04",
    )

def validate_row(row: Dict[str, str]) -> Result:
    # Semantic validation is sequential: deterministic static failures are final.
    static_result = lower(row.get("static_validation_result"))

    if not static_result:
        return make_result(
            label="uncertain",
            relation="static_validation_missing",
            confidence="high",
            decision="manual_review",
            reason="No static-validation result is available for this proposal.",
            human_review="yes",
            rule="SEM-STATIC-00",
        )

    if static_result == "fail":
        return make_result(
            label="incorrect",
            relation="static_validation_failure",
            confidence="high",
            decision="reject",
            reason=(
                "The proposal failed deterministic static validation and is not reconsidered "
                "as an automatic repair by the semantic layer."
            ),
            human_review="no",
            rule="SEM-STATIC-01",
        )

    if static_result not in {"pass", "out_of_scope"}:
        return make_result(
            label="uncertain",
            relation="static_validation_unknown",
            confidence="high",
            decision="manual_review",
            reason=f"Unexpected static-validation result: '{static_result}'.",
            human_review="yes",
            rule="SEM-STATIC-02",
        )

    base_result = base_evidence_check(row)
    if base_result is not None:
        return base_result

    field = lower(row.get("field_name"))

    if field == "supplier":
        return validate_supplier(row)
    if field == "license":
        return validate_license(row)
    if field == "repository_url":
        return validate_repository(row)
    if field == "hash_values":
        return validate_hash(row)
    if field == "distribution_url":
        return validate_distribution(row)

    return make_result(
        label="uncertain",
        relation="insufficient_evidence",
        confidence="low",
        decision="manual_review",
        reason=f"No semantic rule is implemented for field '{field}'.",
        human_review="yes",
        rule="SEM-OTHER-01",
    )

def create_summary(rows: List[Dict[str, str]]) -> List[Dict[str, str]]:
    total = len(rows)
    counts = Counter(row["semantic_rule_label"] for row in rows)
    return [
        {
            "semantic_rule_label": label,
            "count": str(count),
            "percentage": f"{(count / total * 100) if total else 0:.2f}",
        }
        for label, count in sorted(counts.items())
    ]


def create_field_summary(rows: List[Dict[str, str]]) -> List[Dict[str, str]]:
    totals = Counter(clean(row.get("field_name")) for row in rows)
    counts = Counter(
        (clean(row.get("field_name")), row["semantic_rule_label"])
        for row in rows
    )

    output = []
    for (field, label), count in sorted(counts.items()):
        output.append(
            {
                "field_name": field,
                "semantic_rule_label": label,
                "count": str(count),
                "percentage_within_field": f"{count / totals[field] * 100:.2f}",
            }
        )
    return output


def create_decision_summary(rows: List[Dict[str, str]]) -> List[Dict[str, str]]:
    total = len(rows)
    counts = Counter(row["semantic_rule_decision"] for row in rows)
    return [
        {
            "semantic_rule_decision": decision,
            "count": str(count),
            "percentage": f"{(count / total * 100) if total else 0:.2f}",
        }
        for decision, count in sorted(counts.items())
    ]


def create_field_decision_summary(rows: List[Dict[str, str]]) -> List[Dict[str, str]]:
    totals = Counter(clean(row.get("field_name")) for row in rows)
    counts = Counter(
        (clean(row.get("field_name")), row["semantic_rule_decision"])
        for row in rows
    )
    output = []
    for (field, decision), count in sorted(counts.items()):
        output.append(
            {
                "field_name": field,
                "semantic_rule_decision": decision,
                "count": str(count),
                "percentage_within_field": f"{count / totals[field] * 100:.2f}",
            }
        )
    return output


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run deterministic semantic-rule validation.")
    parser.add_argument(
        "--input",
        type=Path,
        default=Path("data/static_validation_all_repairs.csv"),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data/full_semantic_rule_validation_results.csv"),
    )
    parser.add_argument(
        "--review-queue",
        type=Path,
        default=Path("data/full_semantic_rule_human_review_queue.csv"),
    )
    parser.add_argument(
        "--summary",
        type=Path,
        default=Path("data/full_semantic_rule_validation_summary.csv"),
    )
    parser.add_argument(
        "--summary-by-field",
        type=Path,
        default=Path("data/full_semantic_rule_validation_summary_by_field.csv"),
    )
    parser.add_argument(
        "--decision-summary",
        type=Path,
        default=Path("data/full_semantic_rule_decision_summary.csv"),
    )
    parser.add_argument(
        "--decision-summary-by-field",
        type=Path,
        default=Path("data/full_semantic_rule_decision_summary_by_field.csv"),
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    rows, original_fields = load_csv(args.input)

    result_fields = [
        "semantic_rule_label",
        "semantic_evidence_relation",
        "semantic_rule_confidence",
        "semantic_rule_decision",
        "semantic_rule_reason",
        "semantic_requires_human_review",
        "semantic_rule_id",
        "semantic_validated_at",
    ]

    output_rows: List[Dict[str, str]] = []
    for row in rows:
        output = dict(row)
        output.update(validate_row(row))
        output["semantic_validated_at"] = utc_now()
        output_rows.append(output)

    output_fields = list(original_fields)
    for field in result_fields:
        if field not in output_fields:
            output_fields.append(field)

    write_csv(args.output, output_rows, output_fields)

    review_rows = [
        row
        for row in output_rows
        if row["semantic_requires_human_review"] == "yes"
    ]
    write_csv(args.review_queue, review_rows, output_fields)

    summary_rows = create_summary(output_rows)
    write_csv(
        args.summary,
        summary_rows,
        ["semantic_rule_label", "count", "percentage"],
    )

    field_summary_rows = create_field_summary(output_rows)
    write_csv(
        args.summary_by_field,
        field_summary_rows,
        ["field_name", "semantic_rule_label", "count", "percentage_within_field"],
    )

    decision_summary_rows = create_decision_summary(output_rows)
    write_csv(
        args.decision_summary,
        decision_summary_rows,
        ["semantic_rule_decision", "count", "percentage"],
    )

    field_decision_rows = create_field_decision_summary(output_rows)
    write_csv(
        args.decision_summary_by_field,
        field_decision_rows,
        ["field_name", "semantic_rule_decision", "count", "percentage_within_field"],
    )

    print(f"Input rows: {len(rows)}")
    print(f"Results: {args.output}")
    print(f"Human-review queue: {args.review_queue} ({len(review_rows)} rows)")
    print(f"Summary: {args.summary}")
    print(f"Summary by field: {args.summary_by_field}")
    print(f"Decision summary: {args.decision_summary}")
    print(f"Decision summary by field: {args.decision_summary_by_field}")

    print("\nSemantic rule results:")
    for item in summary_rows:
        print(
            f"{item['semantic_rule_label']}: "
            f"{item['count']} ({item['percentage']}%)"
        )

    print("\nSemantic decisions:")
    for item in decision_summary_rows:
        print(
            f"{item['semantic_rule_decision']}: "
            f"{item['count']} ({item['percentage']}%)"
        )

    print("\nSemantic decisions by field:")
    for item in field_decision_rows:
        print(
            f"{item['field_name']} | {item['semantic_rule_decision']}: "
            f"{item['count']} ({item['percentage_within_field']}%)"
        )


if __name__ == "__main__":
    main()
