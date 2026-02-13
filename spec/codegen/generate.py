#!/usr/bin/env python3
"""
Gatedhouse Code Generator

Generates language-specific type definitions, event constants, and
boilerplate from the shared specification (JSON Schema, event catalog).

Usage:
    python generate.py --target typescript --output ../sdk-typescript/src/generated/
    python generate.py --target python --output ../sdk-python/gatedhouse/generated/
    python generate.py --target all
"""

import argparse
import json
import os
import sys
from pathlib import Path

SPEC_DIR = Path(__file__).parent.parent
SCHEMAS_DIR = SPEC_DIR / "schemas"
SQL_DIR = SPEC_DIR / "sql"


def load_json(path: Path) -> dict:
    with open(path) as f:
        return json.load(f)


def load_events_catalog() -> dict:
    return load_json(SCHEMAS_DIR / "events_catalog.json")


# ─── TypeScript Generator ────────────────────────────────────────

def generate_typescript(output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)

    events = load_events_catalog()

    lines = [
        "// AUTO-GENERATED from spec/schemas/events_catalog.json",
        "// Do not edit manually. Run: python spec/codegen/generate.py --target typescript",
        "",
        "// Citadel events",
    ]
    for evt in events["citadel_events"]:
        const_name = evt["type"].upper().replace(".", "_")
        lines.append(f"export const {const_name} = '{evt['type']}';")

    lines.append("")
    lines.append("// Sphinx events")
    for evt in events["sphinx_events"]:
        const_name = evt["type"].upper().replace(".", "_")
        lines.append(f"export const {const_name} = '{evt['type']}';")

    lines.append("")
    lines.append("// Audit events")
    for evt in events["audit_events"]:
        const_name = evt["type"].upper().replace(".", "_")
        lines.append(f"export const {const_name} = '{evt['type']}';")

    lines.append("")
    lines.append("export const ALL_CITADEL_EVENTS = [")
    for evt in events["citadel_events"]:
        lines.append(f"  '{evt['type']}',")
    lines.append("] as const;")

    lines.append("")
    lines.append("export const ALL_SPHINX_EVENTS = [")
    for evt in events["sphinx_events"]:
        lines.append(f"  '{evt['type']}',")
    lines.append("] as const;")

    lines.append("")

    (output_dir / "events.ts").write_text("\n".join(lines) + "\n")

    # Generate base roles constant
    role_lines = [
        "// AUTO-GENERATED from spec/schemas/",
        "// Do not edit manually.",
        "",
        "export const BASE_ROLES = [",
        "  { key: 'owner', name: 'Owner', description: 'Organization owner with full access', permissions: ['*:*:*'], isSystem: true },",
        "  { key: 'admin', name: 'Administrator', description: 'Organization administrator', permissions: ['*:*:*'], isSystem: true },",
        "  { key: 'member', name: 'Member', description: 'Regular organization member', permissions: [], isSystem: true },",
        "  { key: 'viewer', name: 'Viewer', description: 'Read-only access', permissions: [], isSystem: true },",
        "] as const;",
        "",
    ]
    (output_dir / "base_roles.ts").write_text("\n".join(role_lines) + "\n")
    print(f"  TypeScript generated -> {output_dir}")


# ─── Python Generator ────────────────────────────────────────────

def generate_python(output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)

    events = load_events_catalog()

    lines = [
        '"""',
        "AUTO-GENERATED from spec/schemas/events_catalog.json",
        "Do not edit manually. Run: python spec/codegen/generate.py --target python",
        '"""',
        "",
        "# Citadel events",
    ]
    for evt in events["citadel_events"]:
        const_name = evt["type"].upper().replace(".", "_")
        lines.append(f'{const_name} = "{evt["type"]}"')

    lines.append("")
    lines.append("# Sphinx events")
    for evt in events["sphinx_events"]:
        const_name = evt["type"].upper().replace(".", "_")
        lines.append(f'{const_name} = "{evt["type"]}"')

    lines.append("")
    lines.append("# Audit events")
    for evt in events["audit_events"]:
        const_name = evt["type"].upper().replace(".", "_")
        lines.append(f'{const_name} = "{evt["type"]}"')

    lines.append("")
    lines.append("ALL_CITADEL_EVENTS = [")
    for evt in events["citadel_events"]:
        lines.append(f'    "{evt["type"]}",')
    lines.append("]")

    lines.append("")
    lines.append("ALL_SPHINX_EVENTS = [")
    for evt in events["sphinx_events"]:
        lines.append(f'    "{evt["type"]}",')
    lines.append("]")
    lines.append("")

    (output_dir / "events.py").write_text("\n".join(lines) + "\n")

    # Generate base roles
    role_lines = [
        '"""',
        "AUTO-GENERATED from spec/schemas/",
        "Do not edit manually.",
        '"""',
        "",
        "from typing import TypedDict",
        "",
        "",
        "class BaseRole(TypedDict):",
        '    key: str',
        '    name: str',
        '    description: str',
        '    permissions: list[str]',
        '    is_system: bool',
        "",
        "",
        "BASE_ROLES: list[BaseRole] = [",
        '    {"key": "owner", "name": "Owner", "description": "Organization owner with full access", "permissions": ["*:*:*"], "is_system": True},',
        '    {"key": "admin", "name": "Administrator", "description": "Organization administrator", "permissions": ["*:*:*"], "is_system": True},',
        '    {"key": "member", "name": "Member", "description": "Regular organization member", "permissions": [], "is_system": True},',
        '    {"key": "viewer", "name": "Viewer", "description": "Read-only access", "permissions": [], "is_system": True},',
        "]",
        "",
    ]
    (output_dir / "base_roles.py").write_text("\n".join(role_lines) + "\n")

    # __init__.py
    (output_dir / "__init__.py").write_text(
        "from .events import *  # noqa: F401,F403\n"
        "from .base_roles import BASE_ROLES, BaseRole  # noqa: F401\n"
    )

    print(f"  Python generated -> {output_dir}")


# ─── SQL Distribution ────────────────────────────────────────────

def distribute_sql(sdk_dir: Path, target: str) -> None:
    """Copy shared SQL into an SDK's directory."""
    sql_dest = sdk_dir / "sql"
    sql_dest.mkdir(parents=True, exist_ok=True)

    # Copy migrations
    migrations_dest = sql_dest / "migrations"
    migrations_dest.mkdir(exist_ok=True)
    for sql_file in sorted((SQL_DIR / "migrations").glob("*.sql")):
        dest = migrations_dest / sql_file.name
        dest.write_text(sql_file.read_text())

    # Copy queries
    queries_dest = sql_dest / "queries"
    queries_dest.mkdir(exist_ok=True)
    for sql_file in sorted((SQL_DIR / "queries").glob("*.sql")):
        dest = queries_dest / sql_file.name
        dest.write_text(sql_file.read_text())

    print(f"  SQL distributed -> {sql_dest}")


# ─── Main ────────────────────────────────────────────────────────

GENERATORS = {
    "typescript": lambda: (
        generate_typescript(SPEC_DIR.parent / "sdk-typescript" / "src" / "generated"),
        distribute_sql(SPEC_DIR.parent / "sdk-typescript", "typescript"),
    ),
    "python": lambda: (
        generate_python(SPEC_DIR.parent / "sdk-python" / "gatedhouse" / "generated"),
        distribute_sql(SPEC_DIR.parent / "sdk-python", "python"),
    ),
}


def main():
    parser = argparse.ArgumentParser(description="Gatedhouse code generator")
    parser.add_argument(
        "--target",
        choices=list(GENERATORS.keys()) + ["all"],
        default="all",
        help="Target language (or 'all')",
    )
    args = parser.parse_args()

    targets = list(GENERATORS.keys()) if args.target == "all" else [args.target]

    print("Gatedhouse Code Generator")
    print(f"Spec dir: {SPEC_DIR}")
    print()

    for target in targets:
        print(f"Generating {target}...")
        GENERATORS[target]()
        print()

    print("Done.")


if __name__ == "__main__":
    main()
