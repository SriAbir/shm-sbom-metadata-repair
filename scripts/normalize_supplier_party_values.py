#!/usr/bin/env python3

import csv
import re
from pathlib import Path


INPUT_FILE = Path(
    "data/component_evidence_summary.csv"
)

BACKUP_FILE = Path(
    "data/component_evidence_summary_before_supplier_normalization.csv"
)

OUTPUT_FILE = Path(
    "data/component_evidence_summary.csv"
)


def clean(value):
    if value is None:
        return ""
    return str(value).strip()


def remove_trailing_email(value):
    """
    Convert:

        Julian Gruber <mail@example.com>

    into:

        Julian Gruber

    A standalone email address is preserved because it has no
    separate display name.
    """

    value = clean(value)

    if not value:
        return ""

    match = re.fullmatch(
        r"\s*(.*?)\s*<([^<>]+)>\s*",
        value,
    )

    if not match:
        return value

    name = clean(match.group(1))
    email = clean(match.group(2))

    return name or email


def main():
    if not INPUT_FILE.exists():
        raise FileNotFoundError(
            f"Missing input file: {INPUT_FILE}"
        )

    with INPUT_FILE.open(
        newline="",
        encoding="utf-8-sig",
    ) as file:
        reader = csv.DictReader(file)
        rows = list(reader)
        fieldnames = reader.fieldnames or []

    if not BACKUP_FILE.exists():
        with BACKUP_FILE.open(
            "w",
            newline="",
            encoding="utf-8",
        ) as file:
            writer = csv.DictWriter(
                file,
                fieldnames=fieldnames,
            )
            writer.writeheader()
            writer.writerows(rows)

    changed_supplier = 0
    changed_party = 0

    for row in rows:
        old_supplier = clean(
            row.get("evidence_supplier")
        )

        new_supplier = remove_trailing_email(
            old_supplier
        )

        if new_supplier != old_supplier:
            row["evidence_supplier"] = new_supplier
            changed_supplier += 1

        old_party = clean(
            row.get("evidence_party_value")
        )

        new_party = remove_trailing_email(
            old_party
        )

        if new_party != old_party:
            row["evidence_party_value"] = new_party
            changed_party += 1

    with OUTPUT_FILE.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
        )
        writer.writeheader()
        writer.writerows(rows)

    print(f"Evidence rows processed: {len(rows)}")
    print(
        "evidence_supplier values normalized:",
        changed_supplier,
    )
    print(
        "evidence_party_value values normalized:",
        changed_party,
    )
    print(f"Backup: {BACKUP_FILE}")
    print(f"Updated file: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
