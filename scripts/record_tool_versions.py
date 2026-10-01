#!/usr/bin/env python3

import csv
import subprocess
from datetime import datetime, timezone
from pathlib import Path

OUTPUT_FILE = Path("data/tool_versions.csv")


def run_command(command):
    result = subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    output = result.stdout.strip()
    error = result.stderr.strip()
    return result.returncode, output, error


def main():
    collected_at = datetime.now(timezone.utc).isoformat()

    tools = [
        {
            "tool": "syft",
            "command": ["./bin/syft", "version"],
            "notes": "Installed locally in ./bin",
        },
        {
            "tool": "cdxgen",
            "command": ["cdxgen", "--version"],
            "notes": "Installed globally via npm",
        },
        {
            "tool": "node",
            "command": ["node", "--version"],
            "notes": "Required for cdxgen",
        },
        {
            "tool": "npm",
            "command": ["npm", "--version"],
            "notes": "Required for cdxgen",
        },
    ]

    rows = []

    for item in tools:
        code, output, error = run_command(item["command"])

        rows.append({
            "tool": item["tool"],
            "version_output": output if code == 0 else "",
            "error": error if code != 0 else "",
            "collected_at": collected_at,
            "status": "success" if code == 0 else "failed",
            "notes": item["notes"],
        })

    with OUTPUT_FILE.open("w", newline="", encoding="utf-8") as f:
        fieldnames = [
            "tool",
            "version_output",
            "error",
            "collected_at",
            "status",
            "notes",
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Saved tool versions to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
