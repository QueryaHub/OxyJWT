#!/usr/bin/env python3
"""Update benchmark table in README.md from benchmark-results JSON."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

DEFAULT_TARGET_ROWS = [
    ("HS256", "encode", "Encode"),
    ("HS256", "decode", "Decode"),
    ("EdDSA", "encode", "Encode"),
    ("EdDSA", "decode", "Decode"),
    ("RS256", "decode", "Decode"),
    ("ES256", "encode", "Encode"),
]

LIBRARIES = ["OxyJWT", "PyJWT", "Authlib", "python-jose"]

START_MARKER = "<!-- BENCHMARK_TABLE_START -->"
END_MARKER = "<!-- BENCHMARK_TABLE_END -->"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--json",
        type=Path,
        required=True,
        help="Path to the benchmark results JSON file.",
    )
    parser.add_argument(
        "--readme",
        type=Path,
        default=Path("README.md"),
        help="Path to README.md file to update.",
    )
    return parser.parse_args()


def load_results(path: Path) -> dict[tuple[str, str, str], float]:
    data: list[dict[str, Any]] = json.loads(path.read_text(encoding="utf-8"))
    lookup: dict[tuple[str, str, str], float] = {}
    for item in data:
        algo = item.get("algorithm", "")
        lib = item.get("library", "")
        op = item.get("operation", "")
        ops = float(item.get("ops_per_second", 0.0))
        if algo and lib and op:
            lookup[(algo, op, lib)] = ops
    return lookup


def format_table(lookup: dict[tuple[str, str, str], float]) -> str:
    lines = [
        "| Algorithm | Operation | OxyJWT | PyJWT | Authlib | python-jose | OxyJWT Speedup |",
        "| :--- | :--- | ---: | ---: | ---: | ---: | :---: |",
    ]

    for algo, op_key, op_label in DEFAULT_TARGET_ROWS:
        oxy_ops = lookup.get((algo, op_key, "OxyJWT"), 0.0)
        py_ops = lookup.get((algo, op_key, "PyJWT"), 0.0)
        auth_ops = lookup.get((algo, op_key, "Authlib"), 0.0)
        jose_ops = lookup.get((algo, op_key, "python-jose"), 0.0)

        # Skip row if neither OxyJWT nor PyJWT have measurements
        if oxy_ops <= 0 and py_ops <= 0:
            continue

        oxy_str = f"**{oxy_ops:,.0f}**" if oxy_ops > 0 else "*N/A*"
        py_str = f"{py_ops:,.0f}" if py_ops > 0 else "*N/A*"
        auth_str = f"{auth_ops:,.0f}" if auth_ops > 0 else "*N/A*"
        jose_str = f"{jose_ops:,.0f}" if jose_ops > 0 else "*N/A*"

        if oxy_ops > 0 and py_ops > 0:
            ratio = oxy_ops / py_ops
            speedup = f"**~{ratio:.1f}× faster** 🚀" if ratio >= 1.0 else f"**{ratio:.2f}×**"
        elif oxy_ops > 0:
            speedup = "**Leader** 🚀"
        else:
            speedup = "-"

        row = (
            f"| **{algo}** | **{op_label}** | {oxy_str} | {py_str} | "
            f"{auth_str} | {jose_str} | {speedup} |"
        )
        lines.append(row)

    return "\n".join(lines)


def update_readme(readme_path: Path, table_md: str) -> bool:
    content = readme_path.read_text(encoding="utf-8")
    pattern = re.compile(
        rf"({re.escape(START_MARKER)}\n)(.*?)(\n{re.escape(END_MARKER)})",
        re.DOTALL,
    )

    if not pattern.search(content):
        raise ValueError(
            f"Could not find markers '{START_MARKER}' and '{END_MARKER}' in {readme_path}"
        )

    new_content = pattern.sub(rf"\g<1>{table_md}\g<3>", content)
    if new_content != content:
        readme_path.write_text(new_content, encoding="utf-8")
        return True
    return False


def main() -> None:
    args = parse_args()
    if not args.json.exists():
        raise SystemExit(f"JSON results file not found: {args.json}")
    if not args.readme.exists():
        raise SystemExit(f"README file not found: {args.readme}")

    lookup = load_results(args.json)
    table_md = format_table(lookup)
    updated = update_readme(args.readme, table_md)
    if updated:
        print(f"Successfully updated benchmark table in {args.readme}")
    else:
        print(f"No changes needed in {args.readme}")


if __name__ == "__main__":
    main()
