#!/usr/bin/env python3

import csv
import json
from datetime import datetime, timezone
from pathlib import Path

GENERATION_LOG = Path("data/sbom_generation_log.csv")
VALIDATION_LOG = Path("data/sbom_validation_log.csv")


def count_components(sbom_data):
    components = sbom_data.get("components", [])
    if isinstance(components, list):
        return len(components)
    return 0


def validate_json_file(path):
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)

        component_count = count_components(data)

        return {
            "is_valid_json": "true",
            "component_count": component_count,
            "validation_error": "",
        }

    except FileNotFoundError:
        return {
            "is_valid_json": "false",
            "component_count": "",
            "validation_error": "file_not_found",
        }

    except json.JSONDecodeError as e:
        return {
            "is_valid_json": "false",
            "component_count": "",
            "validation_error": f"json_decode_error: {e}",
        }

    except Exception as e:
        return {
            "is_valid_json": "false",
            "component_count": "",
            "validation_error": f"unexpected_error: {e}",
        }


def main():
    validated_at = datetime.now(timezone.utc).isoformat()
    rows = []

    with GENERATION_LOG.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)

        for row in reader:
            project_id = row["project_id"]
            ecosystem = row["ecosystem"]
            tool = row["tool"]
            sbom_path = Path(row["output_path"])
            generation_status = row["status"]

            print(f"Validating {project_id} {tool}: {sbom_path}")

            if generation_status != "success":
                rows.append({
                    "project_id": project_id,
                    "ecosystem": ecosystem,
                    "tool": tool,
                    "sbom_path": str(sbom_path),
                    "generation_status": generation_status,
                    "is_valid_json": "false",
                    "component_count": "",
                    "validation_error": "generation_failed",
                    "validated_at": validated_at,
                })
                continue

            result = validate_json_file(sbom_path)

            rows.append({
                "project_id": project_id,
                "ecosystem": ecosystem,
                "tool": tool,
                "sbom_path": str(sbom_path),
                "generation_status": generation_status,
                "is_valid_json": result["is_valid_json"],
                "component_count": result["component_count"],
                "validation_error": result["validation_error"],
                "validated_at": validated_at,
            })

    with VALIDATION_LOG.open("w", newline="", encoding="utf-8") as f:
        fieldnames = [
            "project_id",
            "ecosystem",
            "tool",
            "sbom_path",
            "generation_status",
            "is_valid_json",
            "component_count",
            "validation_error",
            "validated_at",
        ]

        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nSaved validation log to {VALIDATION_LOG}")


if __name__ == "__main__":
    main()
