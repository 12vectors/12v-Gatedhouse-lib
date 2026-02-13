#!/usr/bin/env python3
"""
Gatedhouse Conformance Test Runner

Runs shared test vectors against an SDK's conformance harness.
Each SDK must expose a CLI conformance endpoint that accepts
test vectors on stdin and returns results on stdout.

Usage:
    python tools/conformance_runner.py --sdk typescript
    python tools/conformance_runner.py --sdk python
    python tools/conformance_runner.py --sdk all
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
VECTORS_DIR = REPO_ROOT / "spec" / "test-vectors"

SDK_COMMANDS = {
    "typescript": ["node", str(REPO_ROOT / "sdk-typescript" / "dist" / "conformance.js")],
    "python": [sys.executable, str(REPO_ROOT / "sdk-python" / "conformance.py")],
    "rust": [str(REPO_ROOT / "sdk-rust" / "target" / "release" / "gatedhouse-conformance")],
}


def load_test_vectors() -> list[dict]:
    vectors = []
    for path in sorted(VECTORS_DIR.glob("*.json")):
        with open(path) as f:
            vectors.append(json.load(f))
    return vectors


def run_conformance(sdk: str, vectors: list[dict]) -> tuple[int, int, list[str]]:
    """Run test vectors against an SDK. Returns (passed, failed, errors)."""
    cmd = SDK_COMMANDS.get(sdk)
    if not cmd:
        print(f"Unknown SDK: {sdk}")
        return 0, 0, [f"Unknown SDK: {sdk}"]

    cwd = REPO_ROOT / f"sdk-{sdk}" if sdk != "python" else REPO_ROOT / "sdk-python"

    try:
        result = subprocess.run(
            cmd,
            input=json.dumps(vectors),
            capture_output=True,
            text=True,
            timeout=60,
            cwd=str(cwd),
        )
    except FileNotFoundError:
        return 0, 0, [f"SDK harness not found: {' '.join(cmd)}"]
    except subprocess.TimeoutExpired:
        return 0, 0, ["Conformance harness timed out"]

    if result.returncode != 0:
        return 0, 0, [f"Harness exited with code {result.returncode}: {result.stderr}"]

    try:
        output = json.loads(result.stdout)
    except json.JSONDecodeError:
        return 0, 0, [f"Invalid JSON output: {result.stdout[:500]}"]

    passed = output.get("passed", 0)
    failed = output.get("failed", 0)
    errors = output.get("errors", [])
    return passed, failed, errors


def main():
    parser = argparse.ArgumentParser(description="Gatedhouse conformance runner")
    parser.add_argument(
        "--sdk",
        choices=list(SDK_COMMANDS.keys()) + ["all"],
        default="all",
    )
    args = parser.parse_args()

    vectors = load_test_vectors()
    total_cases = sum(len(v.get("cases", [])) for v in vectors)
    print(f"Loaded {len(vectors)} test suites with {total_cases} total cases")
    print()

    sdks = list(SDK_COMMANDS.keys()) if args.sdk == "all" else [args.sdk]
    all_passed = True

    for sdk in sdks:
        print(f"--- {sdk} ---")
        passed, failed, errors = run_conformance(sdk, vectors)

        if errors:
            print(f"  ERRORS: {len(errors)}")
            for err in errors[:10]:
                print(f"    {err}")
            all_passed = False
        else:
            print(f"  Passed: {passed}  Failed: {failed}")
            if failed > 0:
                all_passed = False
        print()

    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    main()
