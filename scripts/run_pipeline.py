#!/usr/bin/env python3
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


HELP_TEXT = """Usage: python3 scripts/run_pipeline.py

Runs the key validator and optionally publishes the generated list if
PUBLISH_TARGET_REPO is set in the environment.
"""


def run(*args: str) -> int:
    proc = subprocess.run(args, check=False)
    return proc.returncode


def split_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def derive_sized_path(path_value: str, limit: str) -> str:
    path = Path(path_value)
    if path.suffix:
        return str(path.with_name(f"{path.stem}-{limit}{path.suffix}"))
    return str(path.with_name(f"{path.name}-{limit}"))


def normalize_limit_strings(values: list[str]) -> list[str]:
    normalized = sorted({int(value) for value in values}, reverse=True)
    if any(value <= 0 for value in normalized):
        raise SystemExit("all limits must be positive integers")
    return [str(value) for value in normalized]


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] in {"-h", "--help"}:
        print(HELP_TEXT)
        return 0

    output_path = os.getenv("OUTPUT_PATH", "artifacts/short-key-list.txt")
    target_file = os.getenv("PUBLISH_TARGET_FILE", "data/short-key-list.txt")
    extra_limits = normalize_limit_strings(split_csv(os.getenv("EXTRA_KEY_LIST_LIMITS", "100,50")))

    checker_cmd = [
        sys.executable,
        "scripts/check_key_list.py",
        "--output",
        output_path,
        "--report",
        os.getenv("REPORT_PATH", "artifacts/check-report.json"),
        "--limit",
        os.getenv("KEY_LIST_LIMIT", os.getenv("WHITELIST_LIMIT", "200")),
        "--workers",
        os.getenv("WORKERS", "4"),
        "--port-base",
        os.getenv("PORT_BASE", "21080"),
    ]
    for limit in extra_limits:
        checker_cmd.extend(["--extra-limit", limit])
    if os.getenv("TCP_PRECHECK", "").lower() in {"1", "true", "yes"}:
        checker_cmd.append("--tcp-precheck")

    check_exit = run(*checker_cmd)
    if check_exit != 0:
        return check_exit

    target_repo = os.getenv("PUBLISH_TARGET_REPO", "").strip()
    if not target_repo:
        return 0

    publish_cmd = [
        sys.executable,
        "scripts/publish_key_list.py",
        "--source",
        output_path,
        "--target-repo",
        target_repo,
        "--target-file",
        target_file,
        "--commit-message",
        os.getenv("PUBLISH_COMMIT_MESSAGE", "Update short key list"),
    ]
    for limit in extra_limits:
        publish_cmd.extend([
            "--extra-file",
            f"{derive_sized_path(output_path, limit)}:{derive_sized_path(target_file, limit)}",
        ])
    if os.getenv("PUSH_AFTER_PUBLISH", "").lower() in {"1", "true", "yes"}:
        publish_cmd.append("--push")
    return run(*publish_cmd)


if __name__ == "__main__":
    raise SystemExit(main())
