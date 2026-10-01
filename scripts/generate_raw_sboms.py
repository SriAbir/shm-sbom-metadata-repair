#!/usr/bin/env python3

import csv
import subprocess
from datetime import datetime, timezone
from pathlib import Path

INPUT_FILE = Path("data/repository_commits.csv")
OUTPUT_LOG = Path("data/sbom_generation_log.csv")

SYFT_OUTPUT_DIR = Path("sboms_raw/syft")
CDXGEN_OUTPUT_DIR = Path("sboms_raw/cdxgen")

SYFT_BIN = Path("./bin/syft")


def run_command(command):
    result = subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return result.returncode, result.stdout, result.stderr


def safe_repo_name(owner_repo):
    return owner_repo.split("/")[-1].replace("-", "_")


def generate_syft(local_path, output_path):
    command = [
        str(SYFT_BIN),
        local_path,
        "-o",
        "cyclonedx-json",
    ]

    code, stdout, stderr = run_command(command)

    if code == 0:
        output_path.write_text(stdout, encoding="utf-8")

    return code, stderr.strip()


def generate_cdxgen(local_path, output_path):
    command = [
        "cdxgen",
        "-o",
        str(output_path),
        local_path,
    ]

    code, stdout, stderr = run_command(command)

    return code, stderr.strip()


def main():
    SYFT_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    CDXGEN_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    collected_at = datetime.now(timezone.utc).isoformat()
    rows = []

    with INPUT_FILE.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)

        for repo in reader:
            if repo.get("status") != "success":
                continue

            project_id = repo["project_id"]
            owner_repo = repo["owner_repo"]
            local_path = repo["local_path"]
            ecosystem = project_id.split("-")[0]

            repo_name = safe_repo_name(owner_repo)

            print(f"\nGenerating SBOMs for {project_id}: {owner_repo}")

            syft_output = SYFT_OUTPUT_DIR / f"{project_id}_{repo_name}_cyclonedx.json"
            cdxgen_output = CDXGEN_OUTPUT_DIR / f"{project_id}_{repo_name}_cyclonedx.json"

            print(f"  Syft -> {syft_output}")
            code, error = generate_syft(local_path, syft_output)

            rows.append({
                "project_id": project_id,
                "owner_repo": owner_repo,
                "ecosystem": repo.get("ecosystem", ""),
                "tool": "syft",
                "input_path": local_path,
                "output_path": str(syft_output),
                "status": "success" if code == 0 else "failed",
                "error_message": error,
                "generated_at": collected_at,
            })

            if code != 0:
                print(f"  Syft failed: {error[:300]}")
            else:
                print("  Syft success")

            print(f"  cdxgen -> {cdxgen_output}")
            code, error = generate_cdxgen(local_path, cdxgen_output)

            rows.append({
                "project_id": project_id,
                "owner_repo": owner_repo,
                "ecosystem": repo.get("ecosystem", ""),
                "tool": "cdxgen",
                "input_path": local_path,
                "output_path": str(cdxgen_output),
                "status": "success" if code == 0 else "failed",
                "error_message": error,
                "generated_at": collected_at,
            })

            if code != 0:
                print(f"  cdxgen failed: {error[:300]}")
            else:
                print("  cdxgen success")

    with OUTPUT_LOG.open("w", newline="", encoding="utf-8") as f:
        fieldnames = [
            "project_id",
            "owner_repo",
            "ecosystem",
            "tool",
            "input_path",
            "output_path",
            "status",
            "error_message",
            "generated_at",
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nSaved generation log to {OUTPUT_LOG}")


if __name__ == "__main__":
    main()
