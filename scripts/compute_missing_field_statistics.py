#!/usr/bin/env python3

import csv
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

INPUT_FILE = Path("data/component_metadata_raw.csv")

OUTPUT_OVERALL = Path("data/missing_field_summary_overall.csv")
OUTPUT_BY_TOOL = Path("data/missing_field_summary_by_tool.csv")
OUTPUT_BY_ECOSYSTEM_TOOL = Path("data/missing_field_summary_by_ecosystem_tool.csv")

FIELDS_TO_CHECK = [
    "name",
    "version",
    "purl",
    "license",
    "supplier",
    "repository_url",
    "hash_values",
    "distribution_url",
]


def is_present(value):
    if value is None:
        return False

    value = str(value).strip()

    if value == "":
        return False

    lowered = value.lower()

    if lowered in ["null", "none", "unknown", "n/a", "na", "[]", "{}"]:
        return False

    return True


def empty_counter():
    return {
        "total_components": 0,
        **{f"{field}_present": 0 for field in FIELDS_TO_CHECK},
        **{f"{field}_missing": 0 for field in FIELDS_TO_CHECK},
    }


def update_counter(counter, row):
    counter["total_components"] += 1

    for field in FIELDS_TO_CHECK:
        if is_present(row.get(field, "")):
            counter[f"{field}_present"] += 1
        else:
            counter[f"{field}_missing"] += 1


def make_summary_rows(grouped_counts, group_columns):
    checked_at = datetime.now(timezone.utc).isoformat()
    rows = []

    for group_key, counts in sorted(grouped_counts.items()):
        total = counts["total_components"]

        if not isinstance(group_key, tuple):
            group_key = (group_key,)

        group_data = {
            column: value for column, value in zip(group_columns, group_key)
        }

        for field in FIELDS_TO_CHECK:
            present = counts[f"{field}_present"]
            missing = counts[f"{field}_missing"]

            present_pct = (present / total * 100) if total else 0
            missing_pct = (missing / total * 100) if total else 0

            row = {
                **group_data,
                "field": field,
                "total_components": total,
                "present": present,
                "missing": missing,
                "present_pct": f"{present_pct:.2f}",
                "missing_pct": f"{missing_pct:.2f}",
                "checked_at": checked_at,
            }

            rows.append(row)

    return rows


def write_csv(path, rows, fieldnames):
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main():
    overall_counts = {("ALL",): empty_counter()}
    by_tool_counts = defaultdict(empty_counter)
    by_ecosystem_tool_counts = defaultdict(empty_counter)

    with INPUT_FILE.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)

        for row in reader:
            tool = row.get("tool", "")
            ecosystem = row.get("ecosystem", "")

            update_counter(overall_counts[("ALL",)], row)
            update_counter(by_tool_counts[(tool,)], row)
            update_counter(by_ecosystem_tool_counts[(ecosystem, tool)], row)

    overall_rows = make_summary_rows(overall_counts, ["scope"])
    by_tool_rows = make_summary_rows(by_tool_counts, ["tool"])
    by_ecosystem_tool_rows = make_summary_rows(
        by_ecosystem_tool_counts,
        ["ecosystem", "tool"],
    )

    write_csv(
        OUTPUT_OVERALL,
        overall_rows,
        [
            "scope",
            "field",
            "total_components",
            "present",
            "missing",
            "present_pct",
            "missing_pct",
            "checked_at",
        ],
    )

    write_csv(
        OUTPUT_BY_TOOL,
        by_tool_rows,
        [
            "tool",
            "field",
            "total_components",
            "present",
            "missing",
            "present_pct",
            "missing_pct",
            "checked_at",
        ],
    )

    write_csv(
        OUTPUT_BY_ECOSYSTEM_TOOL,
        by_ecosystem_tool_rows,
        [
            "ecosystem",
            "tool",
            "field",
            "total_components",
            "present",
            "missing",
            "present_pct",
            "missing_pct",
            "checked_at",
        ],
    )

    print("Saved:")
    print(f"  {OUTPUT_OVERALL}")
    print(f"  {OUTPUT_BY_TOOL}")
    print(f"  {OUTPUT_BY_ECOSYSTEM_TOOL}")


if __name__ == "__main__":
    main()
