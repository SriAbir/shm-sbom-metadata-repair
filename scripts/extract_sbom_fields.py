#!/usr/bin/env python3

import csv
import json
from datetime import datetime, timezone
from pathlib import Path

VALIDATION_LOG = Path("data/sbom_validation_log.csv")
OUTPUT_FILE = Path("data/component_metadata_raw.csv")


def safe_get(d, key, default=""):
    value = d.get(key, default)
    if value is None:
        return ""
    return value


def stringify(value):
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False)


def extract_license(component):
    licenses = component.get("licenses", [])

    if not licenses:
        return ""

    extracted = []

    for item in licenses:
        if not isinstance(item, dict):
            continue

        license_obj = item.get("license")
        expression = item.get("expression")

        if expression:
            extracted.append(expression)
            continue

        if isinstance(license_obj, dict):
            lic_id = license_obj.get("id")
            lic_name = license_obj.get("name")

            if lic_id:
                extracted.append(lic_id)
            elif lic_name:
                extracted.append(lic_name)

    return ";".join(extracted)


def extract_hashes(component):
    hashes = component.get("hashes", [])

    if not hashes:
        return "", ""

    algorithms = []
    values = []

    for h in hashes:
        if not isinstance(h, dict):
            continue

        alg = h.get("alg", "")
        content = h.get("content", "")

        if alg:
            algorithms.append(alg)
        if content:
            values.append(content)

    return ";".join(algorithms), ";".join(values)


def extract_external_reference(component, wanted_type):
    refs = component.get("externalReferences", [])

    if not refs:
        return ""

    matches = []

    for ref in refs:
        if not isinstance(ref, dict):
            continue

        ref_type = ref.get("type", "")
        url = ref.get("url", "")

        if ref_type == wanted_type and url:
            matches.append(url)

    return ";".join(matches)


def extract_all_external_references(component):
    refs = component.get("externalReferences", [])

    if not refs:
        return ""

    compact_refs = []

    for ref in refs:
        if not isinstance(ref, dict):
            continue

        ref_type = ref.get("type", "")
        url = ref.get("url", "")

        if ref_type or url:
            compact_refs.append(f"{ref_type}:{url}")

    return "|".join(compact_refs)


def main():
    extracted_at = datetime.now(timezone.utc).isoformat()
    rows = []

    with VALIDATION_LOG.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)

        for sbom_row in reader:
            if sbom_row["is_valid_json"] != "true":
                continue

            project_id = sbom_row["project_id"]
            ecosystem = sbom_row["ecosystem"]
            tool = sbom_row["tool"]
            sbom_path = Path(sbom_row["sbom_path"])

            print(f"Extracting components from {project_id} {tool}: {sbom_path}")

            with sbom_path.open("r", encoding="utf-8") as sf:
                sbom_data = json.load(sf)

            components = sbom_data.get("components", [])

            if not isinstance(components, list):
                components = []

            for index, component in enumerate(components):
                if not isinstance(component, dict):
                    continue

                hash_algorithms, hash_values = extract_hashes(component)

                repository_url = extract_external_reference(component, "vcs")
                website_url = extract_external_reference(component, "website")
                distribution_url = extract_external_reference(component, "distribution")
                issue_tracker_url = extract_external_reference(component, "issue-tracker")

                row = {
                    "project_id": project_id,
                    "ecosystem": ecosystem,
                    "tool": tool,
                    "sbom_path": str(sbom_path),
                    "component_index": index,
                    "component_type": safe_get(component, "type"),
                    "bom_ref": safe_get(component, "bom-ref"),
                    "group": safe_get(component, "group"),
                    "name": safe_get(component, "name"),
                    "version": safe_get(component, "version"),
                    "purl": safe_get(component, "purl"),
                    "license": extract_license(component),
                    "supplier": stringify(component.get("supplier", "")),
                    "publisher": safe_get(component, "publisher"),
                    "scope": safe_get(component, "scope"),
                    "hash_algorithms": hash_algorithms,
                    "hash_values": hash_values,
                    "repository_url": repository_url,
                    "website_url": website_url,
                    "distribution_url": distribution_url,
                    "issue_tracker_url": issue_tracker_url,
                    "external_references_raw": extract_all_external_references(component),
                    "component_raw_json": stringify(component),
                    "extracted_at": extracted_at,
                }

                rows.append(row)

    fieldnames = [
        "project_id",
        "ecosystem",
        "tool",
        "sbom_path",
        "component_index",
        "component_type",
        "bom_ref",
        "group",
        "name",
        "version",
        "purl",
        "license",
        "supplier",
        "publisher",
        "scope",
        "hash_algorithms",
        "hash_values",
        "repository_url",
        "website_url",
        "distribution_url",
        "issue_tracker_url",
        "external_references_raw",
        "component_raw_json",
        "extracted_at",
    ]

    with OUTPUT_FILE.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nSaved extracted component metadata to {OUTPUT_FILE}")
    print(f"Total component rows: {len(rows)}")


if __name__ == "__main__":
    main()
