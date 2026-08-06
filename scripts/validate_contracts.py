from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "schemas" / "v1"


def main() -> int:
    failures: list[str] = []
    identifiers: set[str] = set()
    for path in sorted(SCHEMAS.glob("*.schema.json")):
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            failures.append(f"{path}: {exc}")
            continue
        for required in ("$schema", "$id", "title"):
            if required not in document:
                failures.append(f"{path}: missing {required}")
        identifier = document.get("$id")
        if identifier in identifiers:
            failures.append(f"{path}: duplicate $id {identifier}")
        if identifier:
            identifiers.add(identifier)
        if document.get("type") != "object":
            failures.append(f"{path}: root type must be object")
    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print(f"Validated {len(identifiers)} JSON contract files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
