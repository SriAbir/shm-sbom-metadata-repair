#!/usr/bin/env python3
"""
Final SHM metadata-completeness evaluator.

Primary evaluation scope
------------------------
SHM repairs five enrichment fields:
    license, supplier, repository_url, hash_values, distribution_url

The BEFORE state is read from the original component inventory.
The AFTER state is constructed by applying ONLY semantic_rule_decision='accept'
repairs from the final semantic-validation output.

accept_with_caution, manual_review, and reject are never applied.
Existing non-empty metadata is never overwritten.

Primary outputs (default: data/final_completeness_results/)
----------------------------------------------------------
    final_completeness_overall.csv
    final_completeness_by_field.csv
    final_completeness_by_ecosystem.csv
    final_completeness_by_tool.csv
    final_completeness_by_ecosystem_tool.csv
    final_completeness_context_8_fields.csv
    final_completeness_sanity_checks.csv

Occurrence matching is exact at:
    SBOM basename + generator tool + component_index

Project IDs are additionally checked for consistency when present in both files.
The component ecosystem is derived from PURL first, then falls back to the
normalized/raw ecosystem columns.
"""

from __future__ import annotations

import argparse
import csv
import math
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Tuple


BASE_DIR = Path(__file__).resolve().parent

TARGET_FIELDS = [
    "license",
    "supplier",
    "repository_url",
    "hash_values",
    "distribution_url",
]

CONTEXT_FIELDS = [
    "name",
    "version",
    "purl",
    "license",
    "supplier",
    "repository_url",
    "hash_values",
    "distribution_url",
]

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


# ---------------------------------------------------------------------------
# Basic helpers
# ---------------------------------------------------------------------------


def clean(value) -> str:
    if value is None:
        return ""
    if isinstance(value, float) and math.isnan(value):
        return ""
    return str(value).strip()


def lower(value) -> str:
    return clean(value).casefold()


def is_missing(value) -> bool:
    return lower(value) in MISSING_VALUES


def is_present(value) -> bool:
    return not is_missing(value)


def pct(num: int | float, den: int | float) -> float:
    return (100.0 * num / den) if den else 0.0


def normalize_component_index(value) -> str:
    text = clean(value)
    if re.fullmatch(r"\d+\.0", text):
        return text[:-2]
    return text


def sbom_basename(value) -> str:
    return Path(clean(value)).name.casefold()


def normalize_tool(value) -> str:
    return lower(value)


def occurrence_key(row: Dict[str, str]) -> Tuple[str, str, str]:
    return (
        normalize_tool(row.get("tool")),
        sbom_basename(row.get("sbom_path")),
        normalize_component_index(row.get("component_index")),
    )


def project_id(row: Dict[str, str]) -> str:
    return clean(row.get("project_id")).upper()


def field_repair_key(row: Dict[str, str]) -> Tuple[str, str, str, str]:
    return occurrence_key(row) + (lower(row.get("field_name")),)


def ecosystem_from_purl(purl) -> str:
    text = lower(purl)
    if not text.startswith("pkg:"):
        return ""

    package_type = text[4:].split("/", 1)[0]
    package_type = package_type.split("?", 1)[0]

    aliases = {
        "python": "pypi",
        "pypi": "pypi",
        "npm": "npm",
        "maven": "maven",
        "github": "github",
    }
    return aliases.get(package_type, package_type)


def normalized_ecosystem(row: Dict[str, str]) -> str:
    # PURL is the strongest component-level ecosystem indicator.
    by_purl = ecosystem_from_purl(row.get("purl"))
    if by_purl:
        return by_purl

    for column in (
        "ecosystem_normalized",
        "ecosystem",
        "project_ecosystem_label",
    ):
        value = lower(row.get(column))
        if value:
            return value

    return "unknown"


def normalized_value_for_duplicate_check(field: str, value) -> str:
    # We only need a stable comparison for duplicate accepted rows. We do not
    # reinterpret field semantics here; the semantic validator already did that.
    return clean(value)


# ---------------------------------------------------------------------------
# I/O
# ---------------------------------------------------------------------------


def load_csv(path: Path) -> Tuple[List[Dict[str, str]], List[str]]:
    if not path.exists():
        raise FileNotFoundError(f"Missing input file: {path}")

    with path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        rows = [dict(row) for row in reader]
        headers = reader.fieldnames or []

    return rows, headers


def write_csv(
    path: Path,
    rows: Iterable[Dict[str, object]],
    fieldnames: List[str] | None = None,
) -> None:
    rows = list(rows)
    path.parent.mkdir(parents=True, exist_ok=True)

    if fieldnames is None:
        fieldnames = list(rows[0].keys()) if rows else []

    with path.open("w", newline="", encoding="utf-8") as handle:
        if not fieldnames:
            return
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


# ---------------------------------------------------------------------------
# Input validation and after-state construction
# ---------------------------------------------------------------------------


def validate_raw_schema(headers: Sequence[str]) -> None:
    required = {"tool", "sbom_path", "component_index", *CONTEXT_FIELDS}
    missing = sorted(required - set(headers))
    if missing:
        raise ValueError(
            "Raw component CSV is missing required columns: " + ", ".join(missing)
        )


def validate_semantic_schema(headers: Sequence[str]) -> None:
    required = {
        "tool",
        "sbom_path",
        "component_index",
        "field_name",
        "new_value",
        "semantic_rule_decision",
    }
    missing = sorted(required - set(headers))
    if missing:
        raise ValueError(
            "Semantic-validation CSV is missing required columns: "
            + ", ".join(missing)
        )


def build_after_state(
    raw_rows: Sequence[Dict[str, str]],
    semantic_rows: Sequence[Dict[str, str]],
) -> Tuple[List[Dict[str, str]], Dict[str, int]]:
    """Return raw rows with only strict semantic accepts applied."""

    raw_index: Dict[Tuple[str, str, str], int] = {}
    duplicate_raw_keys = 0

    for i, row in enumerate(raw_rows):
        key = occurrence_key(row)
        if key in raw_index:
            duplicate_raw_keys += 1
        else:
            raw_index[key] = i

    if duplicate_raw_keys:
        raise ValueError(
            f"Found {duplicate_raw_keys} duplicate raw occurrence keys. "
            "Occurrence matching is not unique; inspect tool/sbom_path/component_index."
        )

    after_rows = [dict(row) for row in raw_rows]

    decision_counts = Counter(lower(row.get("semantic_rule_decision")) for row in semantic_rows)

    accepted_rows = [
        row
        for row in semantic_rows
        if lower(row.get("semantic_rule_decision")) == "accept"
        and lower(row.get("field_name")) in TARGET_FIELDS
    ]

    accepted_unique: Dict[Tuple[str, str, str, str], Dict[str, str]] = {}
    duplicate_identical_accepts = 0
    conflicting_duplicate_accepts = 0

    for row in accepted_rows:
        key = field_repair_key(row)
        previous = accepted_unique.get(key)
        if previous is None:
            accepted_unique[key] = row
            continue

        field = key[-1]
        old_value = normalized_value_for_duplicate_check(field, previous.get("new_value"))
        new_value = normalized_value_for_duplicate_check(field, row.get("new_value"))

        if old_value == new_value:
            duplicate_identical_accepts += 1
        else:
            conflicting_duplicate_accepts += 1

    if conflicting_duplicate_accepts:
        raise ValueError(
            f"Found {conflicting_duplicate_accepts} conflicting duplicate accepted repairs. "
            "Fix the semantic result file before completeness evaluation."
        )

    unmatched_accepted = 0
    project_mismatch = 0
    accepted_on_existing_value = 0
    accepted_blank_value = 0
    applied_repairs = 0

    for repair_key, semantic_row in accepted_unique.items():
        occ_key = repair_key[:3]
        field = repair_key[3]
        raw_pos = raw_index.get(occ_key)

        if raw_pos is None:
            unmatched_accepted += 1
            continue

        raw_row = raw_rows[raw_pos]
        after_row = after_rows[raw_pos]

        raw_project = project_id(raw_row)
        semantic_project = project_id(semantic_row)
        if raw_project and semantic_project and raw_project != semantic_project:
            project_mismatch += 1
            continue

        if is_present(raw_row.get(field)):
            accepted_on_existing_value += 1
            continue

        new_value = clean(semantic_row.get("new_value"))
        if is_missing(new_value):
            accepted_blank_value += 1
            continue

        after_row[field] = new_value
        applied_repairs += 1

    diagnostics = {
        "raw_component_rows": len(raw_rows),
        "semantic_result_rows": len(semantic_rows),
        "semantic_accept_rows_target_fields": len(accepted_rows),
        "unique_accepted_repair_keys": len(accepted_unique),
        "duplicate_identical_accept_rows": duplicate_identical_accepts,
        "conflicting_duplicate_accept_rows": conflicting_duplicate_accepts,
        "unmatched_accepted_repairs": unmatched_accepted,
        "accepted_repairs_project_mismatch": project_mismatch,
        "accepted_repairs_targeting_existing_value": accepted_on_existing_value,
        "accepted_repairs_with_blank_new_value": accepted_blank_value,
        "applied_accepted_repairs": applied_repairs,
        "semantic_accept_decision_count_all_fields": decision_counts.get("accept", 0),
        "semantic_accept_with_caution_count": decision_counts.get("accept_with_caution", 0),
        "semantic_manual_review_count": decision_counts.get("manual_review", 0),
        "semantic_reject_count": decision_counts.get("reject", 0),
    }

    return after_rows, diagnostics


# ---------------------------------------------------------------------------
# Completeness calculations
# ---------------------------------------------------------------------------


def calculate_field_statistics(
    raw_rows: Sequence[Dict[str, str]],
    after_rows: Sequence[Dict[str, str]],
    fields: Sequence[str] = TARGET_FIELDS,
) -> List[Dict[str, object]]:
    if len(raw_rows) != len(after_rows):
        raise ValueError("Raw and after-state row counts differ")

    total = len(raw_rows)
    results: List[Dict[str, object]] = []

    for field in fields:
        before_present = sum(is_present(row.get(field)) for row in raw_rows)
        after_present = sum(is_present(row.get(field)) for row in after_rows)

        before_missing = total - before_present
        after_missing = total - after_present
        repaired_count = after_present - before_present

        if repaired_count < 0:
            raise ValueError(f"Completeness decreased for field {field}")

        before_pct = pct(before_present, total)
        after_pct = pct(after_present, total)

        results.append(
            {
                "field": field,
                "total_components": total,
                "present_before": before_present,
                "missing_before": before_missing,
                "completeness_before_pct": f"{before_pct:.2f}",
                "accepted_repairs_applied": repaired_count,
                "present_after": after_present,
                "missing_after": after_missing,
                "completeness_after_pct": f"{after_pct:.2f}",
                "absolute_gain_percentage_points": f"{after_pct - before_pct:.2f}",
                "missing_value_recovery_pct": f"{pct(repaired_count, before_missing):.2f}",
            }
        )

    return results


def calculate_overall_statistics(
    raw_rows: Sequence[Dict[str, str]],
    after_rows: Sequence[Dict[str, str]],
    fields: Sequence[str],
    scope_name: str,
) -> Dict[str, object]:
    total_components = len(raw_rows)
    total_cells = total_components * len(fields)

    present_before = sum(
        is_present(row.get(field))
        for row in raw_rows
        for field in fields
    )
    present_after = sum(
        is_present(row.get(field))
        for row in after_rows
        for field in fields
    )

    missing_before = total_cells - present_before
    missing_after = total_cells - present_after
    repairs = present_after - present_before

    before_pct = pct(present_before, total_cells)
    after_pct = pct(present_after, total_cells)

    improved_components = 0
    unchanged_components = 0
    decreased_components = 0

    for raw_row, after_row in zip(raw_rows, after_rows):
        before_count = sum(is_present(raw_row.get(field)) for field in fields)
        after_count = sum(is_present(after_row.get(field)) for field in fields)

        if after_count > before_count:
            improved_components += 1
        elif after_count < before_count:
            decreased_components += 1
        else:
            unchanged_components += 1

    return {
        "scope": scope_name,
        "fields": ";".join(fields),
        "field_count": len(fields),
        "total_components": total_components,
        "total_component_field_cells": total_cells,
        "present_before": present_before,
        "missing_before": missing_before,
        "completeness_before_pct": f"{before_pct:.2f}",
        "accepted_repairs_applied": repairs,
        "present_after": present_after,
        "missing_after": missing_after,
        "completeness_after_pct": f"{after_pct:.2f}",
        "absolute_gain_percentage_points": f"{after_pct - before_pct:.2f}",
        "missing_value_recovery_pct": f"{pct(repairs, missing_before):.2f}",
        "components_improved": improved_components,
        "components_unchanged": unchanged_components,
        "components_decreased": decreased_components,
    }


def grouped_field_statistics(
    raw_rows: Sequence[Dict[str, str]],
    after_rows: Sequence[Dict[str, str]],
    group_func,
    group_columns: Sequence[str],
) -> List[Dict[str, object]]:
    grouped: Dict[Tuple[str, ...], List[int]] = defaultdict(list)

    for i, raw_row in enumerate(raw_rows):
        key = group_func(raw_row)
        if not isinstance(key, tuple):
            key = (key,)
        grouped[key].append(i)

    output: List[Dict[str, object]] = []

    for key in sorted(grouped):
        indices = grouped[key]
        raw_subset = [raw_rows[i] for i in indices]
        after_subset = [after_rows[i] for i in indices]

        for row in calculate_field_statistics(raw_subset, after_subset, TARGET_FIELDS):
            prefix = {column: value for column, value in zip(group_columns, key)}
            prefix.update(row)
            output.append(prefix)

    return output


# ---------------------------------------------------------------------------
# Sanity checks
# ---------------------------------------------------------------------------


def build_sanity_checks(
    raw_rows: Sequence[Dict[str, str]],
    after_rows: Sequence[Dict[str, str]],
    diagnostics: Dict[str, int],
) -> List[Dict[str, object]]:
    changed_existing_fields = 0
    target_field_delta = 0

    for raw_row, after_row in zip(raw_rows, after_rows):
        for field in TARGET_FIELDS:
            before_present = is_present(raw_row.get(field))
            after_present = is_present(after_row.get(field))

            if before_present and clean(raw_row.get(field)) != clean(after_row.get(field)):
                changed_existing_fields += 1

            if not before_present and after_present:
                target_field_delta += 1

    checks = [
        {
            "check": "raw_component_rows",
            "value": diagnostics["raw_component_rows"],
            "expected": ">0",
            "status": "PASS" if diagnostics["raw_component_rows"] > 0 else "FAIL",
        },
        {
            "check": "duplicate_raw_occurrence_keys",
            "value": 0,
            "expected": "0",
            "status": "PASS",
        },
        {
            "check": "conflicting_duplicate_accept_rows",
            "value": diagnostics["conflicting_duplicate_accept_rows"],
            "expected": "0",
            "status": "PASS" if diagnostics["conflicting_duplicate_accept_rows"] == 0 else "FAIL",
        },
        {
            "check": "unmatched_accepted_repairs",
            "value": diagnostics["unmatched_accepted_repairs"],
            "expected": "0",
            "status": "PASS" if diagnostics["unmatched_accepted_repairs"] == 0 else "FAIL",
        },
        {
            "check": "accepted_repairs_project_mismatch",
            "value": diagnostics["accepted_repairs_project_mismatch"],
            "expected": "0",
            "status": "PASS" if diagnostics["accepted_repairs_project_mismatch"] == 0 else "FAIL",
        },
        {
            "check": "accepted_repairs_targeting_existing_value",
            "value": diagnostics["accepted_repairs_targeting_existing_value"],
            "expected": "0",
            "status": "PASS" if diagnostics["accepted_repairs_targeting_existing_value"] == 0 else "FAIL",
        },
        {
            "check": "accepted_repairs_with_blank_new_value",
            "value": diagnostics["accepted_repairs_with_blank_new_value"],
            "expected": "0",
            "status": "PASS" if diagnostics["accepted_repairs_with_blank_new_value"] == 0 else "FAIL",
        },
        {
            "check": "existing_nonempty_target_fields_overwritten",
            "value": changed_existing_fields,
            "expected": "0",
            "status": "PASS" if changed_existing_fields == 0 else "FAIL",
        },
        {
            "check": "after_state_repairs_equal_applied_accepts",
            "value": target_field_delta,
            "expected": str(diagnostics["applied_accepted_repairs"]),
            "status": (
                "PASS"
                if target_field_delta == diagnostics["applied_accepted_repairs"]
                else "FAIL"
            ),
        },
    ]

    return checks


# ---------------------------------------------------------------------------
# CLI / main
# ---------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Evaluate SHM metadata completeness before and after applying only "
            "strict semantic accept decisions."
        )
    )
    parser.add_argument(
        "--raw",
        type=Path,
        default=Path("data/component_metadata_raw.csv"),
        help="Original component metadata CSV",
    )
    parser.add_argument(
        "--semantic",
        type=Path,
        default=Path("data/full_semantic_rule_validation_results.csv"),
        help="Final semantic-validation CSV",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("data/final_completeness_results"),
        help="Directory for completeness outputs",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    raw_rows, raw_headers = load_csv(args.raw)
    semantic_rows, semantic_headers = load_csv(args.semantic)

    validate_raw_schema(raw_headers)
    validate_semantic_schema(semantic_headers)

    after_rows, diagnostics = build_after_state(raw_rows, semantic_rows)
    sanity_rows = build_sanity_checks(raw_rows, after_rows, diagnostics)

    failed_checks = [row for row in sanity_rows if row["status"] == "FAIL"]
    if failed_checks:
        details = ", ".join(row["check"] for row in failed_checks)
        raise ValueError(
            "Completeness sanity checks failed: " + details
            + ". Fix these before reporting final results."
        )

    output_dir = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    by_field = calculate_field_statistics(raw_rows, after_rows, TARGET_FIELDS)
    by_ecosystem = grouped_field_statistics(
        raw_rows,
        after_rows,
        lambda row: normalized_ecosystem(row),
        ["ecosystem"],
    )
    by_tool = grouped_field_statistics(
        raw_rows,
        after_rows,
        lambda row: normalize_tool(row.get("tool")) or "unknown",
        ["tool"],
    )
    by_ecosystem_tool = grouped_field_statistics(
        raw_rows,
        after_rows,
        lambda row: (
            normalized_ecosystem(row),
            normalize_tool(row.get("tool")) or "unknown",
        ),
        ["ecosystem", "tool"],
    )

    primary_overall = calculate_overall_statistics(
        raw_rows,
        after_rows,
        TARGET_FIELDS,
        "primary_5_repair_fields",
    )

    context_overall = calculate_overall_statistics(
        raw_rows,
        after_rows,
        CONTEXT_FIELDS,
        "context_8_metadata_fields",
    )

    context_by_field = calculate_field_statistics(
        raw_rows,
        after_rows,
        CONTEXT_FIELDS,
    )

    write_csv(output_dir / "final_completeness_overall.csv", [primary_overall])
    write_csv(output_dir / "final_completeness_by_field.csv", by_field)
    write_csv(output_dir / "final_completeness_by_ecosystem.csv", by_ecosystem)
    write_csv(output_dir / "final_completeness_by_tool.csv", by_tool)
    write_csv(
        output_dir / "final_completeness_by_ecosystem_tool.csv",
        by_ecosystem_tool,
    )
    write_csv(
        output_dir / "final_completeness_context_8_fields.csv",
        [context_overall, *context_by_field],
    )
    write_csv(
        output_dir / "final_completeness_sanity_checks.csv",
        sanity_rows,
    )

    print("=" * 78)
    print("SHM Final Metadata Completeness Evaluation")
    print("=" * 78)
    print(f"Raw component rows:               {len(raw_rows)}")
    print(f"Semantic result rows:             {len(semantic_rows)}")
    print(f"Strict accepted repairs applied:  {diagnostics['applied_accepted_repairs']}")
    print()

    print("PRIMARY COMPLETENESS: FIVE SHM REPAIR FIELDS")
    print("---------------------------------------------")
    print(
        f"Before: {primary_overall['completeness_before_pct']}%  "
        f"({primary_overall['present_before']}/{primary_overall['total_component_field_cells']})"
    )
    print(
        f"After:  {primary_overall['completeness_after_pct']}%  "
        f"({primary_overall['present_after']}/{primary_overall['total_component_field_cells']})"
    )
    print(
        f"Gain:   +{primary_overall['absolute_gain_percentage_points']} percentage points"
    )
    print(
        f"Missing-value recovery: {primary_overall['missing_value_recovery_pct']}%"
    )

    print("\nBY FIELD")
    print("--------")
    for row in by_field:
        print(
            f"{row['field']:20} "
            f"{row['completeness_before_pct']:>6}% -> "
            f"{row['completeness_after_pct']:>6}%  "
            f"gain +{row['absolute_gain_percentage_points']:>6} pp  "
            f"repairs={row['accepted_repairs_applied']}  "
            f"recovery={row['missing_value_recovery_pct']}%"
        )

    print("\nSANITY CHECKS")
    print("-------------")
    for row in sanity_rows:
        print(
            f"{row['status']:4}  {row['check']}: "
            f"value={row['value']} expected={row['expected']}"
        )

    print("\nSECONDARY CONTEXT: EIGHT METADATA FIELDS")
    print("----------------------------------------")
    print(
        f"{context_overall['completeness_before_pct']}% -> "
        f"{context_overall['completeness_after_pct']}% "
        f"(+{context_overall['absolute_gain_percentage_points']} pp)"
    )

    print("\nSaved outputs:")
    for filename in [
        "final_completeness_overall.csv",
        "final_completeness_by_field.csv",
        "final_completeness_by_ecosystem.csv",
        "final_completeness_by_tool.csv",
        "final_completeness_by_ecosystem_tool.csv",
        "final_completeness_context_8_fields.csv",
        "final_completeness_sanity_checks.csv",
    ]:
        print(f"  {output_dir / filename}")

    print("\nInterpretation:")
    print("  - Only semantic_rule_decision='accept' contributes to AFTER completeness.")
    print("  - accept_with_caution, manual_review, and reject remain unfilled.")
    print("  - Existing non-empty target fields are never overwritten.")
    print("  - Primary completeness is over the five SHM repair fields.")
    print("  - The eight-field result is secondary context only.")


if __name__ == "__main__":
    main()
