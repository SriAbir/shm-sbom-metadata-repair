#!/usr/bin/env python3

import csv
import json
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

INPUT_FILE = Path("data/repositories.csv")
OUTPUT_FILE = Path("data/repository_metadata.csv")


def github_api_get(url):
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "sbom-sha-study"
        }
    )

    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        print(f"HTTP error for {url}: {e.code} {e.reason}")
        return None
    except urllib.error.URLError as e:
        print(f"URL error for {url}: {e.reason}")
        return None


def main():
    collected_at = datetime.now(timezone.utc).isoformat()

    rows = []

    with INPUT_FILE.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)

        for repo in reader:
            project_id = repo["project_id"]
            owner_repo = repo["owner_repo"]
            api_url = f"https://api.github.com/repos/{owner_repo}"

            print(f"Collecting metadata for {project_id}: {owner_repo}")

            data = github_api_get(api_url)

            if data is None:
                rows.append({
                    "project_id": project_id,
                    "owner_repo": owner_repo,
                    "stars": "",
                    "forks": "",
                    "open_issues": "",
                    "default_branch": "",
                    "license": "",
                    "last_pushed_at": "",
                    "collected_at": collected_at,
                    "status": "failed"
                })
                continue

            license_info = data.get("license")
            license_name = ""
            if license_info:
                license_name = license_info.get("spdx_id") or license_info.get("name") or ""

            rows.append({
                "project_id": project_id,
                "owner_repo": owner_repo,
                "stars": data.get("stargazers_count", ""),
                "forks": data.get("forks_count", ""),
                "open_issues": data.get("open_issues_count", ""),
                "default_branch": data.get("default_branch", ""),
                "license": license_name,
                "last_pushed_at": data.get("pushed_at", ""),
                "collected_at": collected_at,
                "status": "success"
            })

            time.sleep(1)

    with OUTPUT_FILE.open("w", newline="", encoding="utf-8") as f:
        fieldnames = [
            "project_id",
            "owner_repo",
            "stars",
            "forks",
            "open_issues",
            "default_branch",
            "license",
            "last_pushed_at",
            "collected_at",
            "status"
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nSaved metadata to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
