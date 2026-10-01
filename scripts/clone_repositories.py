#!/usr/bin/env python3

import csv
import subprocess
from datetime import datetime, timezone
from pathlib import Path

INPUT_FILE = Path("data/repositories.csv")
OUTPUT_FILE = Path("data/repository_commits.csv")

BASE_DIRS = {
    "npm": Path("repos/npm"),
    "pypi": Path("repos/pypi"),
    "maven": Path("repos/maven"),
}


def run_command(command, cwd=None):
    result = subprocess.run(
        command,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return result.returncode, result.stdout.strip(), result.stderr.strip()


def repo_folder_name(owner_repo):
    return owner_repo.split("/")[-1]


def main():
    collected_at = datetime.now(timezone.utc).isoformat()
    rows = []

    with INPUT_FILE.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)

        for repo in reader:
            project_id = repo["project_id"]
            ecosystem = repo["ecosystem"]
            repository_url = repo["repository_url"]
            owner_repo = repo["owner_repo"]

            base_dir = BASE_DIRS[ecosystem]
            base_dir.mkdir(parents=True, exist_ok=True)

            local_path = base_dir / repo_folder_name(owner_repo)

            print(f"\nProcessing {project_id}: {owner_repo}")

            if local_path.exists():
                print(f"Already exists: {local_path}")
            else:
                print(f"Cloning into: {local_path}")
                code, out, err = run_command(
                    ["git", "clone", repository_url, str(local_path)]
                )
                if code != 0:
                    print(f"Clone failed for {owner_repo}: {err}")
                    rows.append({
                        "project_id": project_id,
                        "owner_repo": owner_repo,
                        "local_path": str(local_path),
                        "commit_hash": "",
                        "branch": "",
                        "collected_at": collected_at,
                        "status": "clone_failed",
                    })
                    continue

            code_hash, commit_hash, err_hash = run_command(
                ["git", "rev-parse", "HEAD"],
                cwd=local_path,
            )

            code_branch, branch, err_branch = run_command(
                ["git", "branch", "--show-current"],
                cwd=local_path,
            )

            status = "success"
            if code_hash != 0 or code_branch != 0:
                status = "metadata_failed"

            rows.append({
                "project_id": project_id,
                "owner_repo": owner_repo,
                "local_path": str(local_path),
                "commit_hash": commit_hash if code_hash == 0 else "",
                "branch": branch if code_branch == 0 else "",
                "collected_at": collected_at,
                "status": status,
            })

    with OUTPUT_FILE.open("w", newline="", encoding="utf-8") as f:
        fieldnames = [
            "project_id",
            "owner_repo",
            "local_path",
            "commit_hash",
            "branch",
            "collected_at",
            "status",
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nSaved commit metadata to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
