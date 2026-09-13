"""Show the finished prompt exactly as an AI would receive it.

Not a test: a look at the artifact. Run it after changing anything in the rendering path,
because the block layout is a contract and reading it is faster than reasoning about it.

    python scripts/show_prompt.py                 # newest bundle in var/packages
    python scripts/show_prompt.py B-lsp-verify    # a specific one
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main(argv: list[str]) -> int:
    packages = ROOT / "var" / "packages"
    if not packages.is_dir():
        print("no var/packages yet: run `python scripts/demo.py` first")
        return 1

    if argv:
        target = packages / argv[0]
    else:
        candidates = sorted(
            (p for p in packages.iterdir() if p.is_dir() and (p / "ai").is_dir()),
            key=lambda p: p.stat().st_mtime,
        )
        if not candidates:
            print("no bundles with an ai/ directory: run `python scripts/demo.py` first")
            return 1
        target = candidates[-1]

    meta = json.loads((target / "ai" / "blocks_meta.json").read_text(encoding="utf-8"))
    prefix = json.loads((target / "ai" / "cache_prefix.json").read_text(encoding="utf-8"))
    blocks = [
        json.loads(line)
        for line in (target / "ai" / "blocks.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    print(f"bundle {target.name}\n")
    print(f"{'order':>5}  {'block_id':<26} {'tokens':>6}  cacheable  in-prefix")
    reusable = set(prefix["prefix_blocks"])
    for index, block in enumerate(meta):
        print(
            f"{index:>5}  {block['block_id']:<26} {block['tokens']:>6}  "
            f"{str(block['cacheable']):<9}  {'yes' if block['block_id'] in reusable else ''}"
        )
    print(
        f"\nprefix starts at {prefix['prefix_start']} "
        f"({prefix['stable_prefix_tokens']} tokens): {', '.join(prefix['prefix_blocks'])}"
    )
    print(f"whole prompt: {len(blocks)} blocks, {sum(b['tokens'] for b in blocks)} tokens\n")

    print("=" * 78)
    print((target / "ai" / "prompt.md").read_text(encoding="utf-8"))
    print("=" * 78)
    print(f"\nfeed it with:  {target / 'ai' / 'prompt.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
