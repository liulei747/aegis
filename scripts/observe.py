"""Print the observability views for the newest bundle (review helper)."""

from __future__ import annotations

import glob
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.observability import views  # noqa: E402
from app.schemas.domain import AnalysisBundleManifest  # noqa: E402

packages = [p for p in glob.glob(str(ROOT / "var" / "packages" / "B-*")) if Path(p).is_dir()]
if not packages:
    raise SystemExit("no bundles yet: run `python scripts/demo.py` first")

target = sys.argv[1] if len(sys.argv) > 1 else max(packages, key=os.path.getmtime)
manifest = AnalysisBundleManifest.model_validate(
    json.loads((Path(target) / "bundle.json").read_text(encoding="utf-8"))["manifest"]
)

print(f"bundle {manifest.bundle_id}\n")

print("== overview ==")
for key, value in vars(views.overview(manifest)).items():
    print(f"  {key:22} {value}")

print("\n== funnel ==")
print(f"  {'step':46}{'count':>7}{'prev':>8}{'lost':>6}  reasons")
for step in views.funnel(manifest):
    previous = f"{step.of_previous:.0%}" if step.of_previous is not None else "-"
    print(
        f"  {step.label[:44]:46}{step.count:>7}{previous:>8}{step.lost:>6}  "
        f"{', '.join(step.loss_reasons) or '-'}"
    )

print("\n== timeline ==")
for stage in views.timeline(manifest):
    print(f"  {stage.label:34}{stage.ms:>7} ms  {stage.share:>6.1%}")

print("\n== providers ==")
print(f"  {'provider':26}{'trust':>8}{'conf':>6}{'methods':>9}{'edges':>7}")
for stat in views.providers(manifest):
    print(
        f"  {stat.provider:26}{stat.trust:>8}{stat.confidence:>6.2f}"
        f"{stat.methods:>9}{stat.edges:>7}"
    )

print("\n== contexts ==")
for view in views.context_views(manifest):
    print(f"  {view.context_id}  focus={view.focus_name} ({view.focus_location})")
    print(
        f"    severity={view.worst_severity}  methods={len(view.methods)}  "
        f"edges={len(view.edges)}  tokens={view.estimated_tokens}  "
        f"truncated={view.truncated}  depths={view.depth_histogram}"
    )
    for row in view.methods:
        chain = " -> ".join(row["origin_chain"]) if row["origin_chain"] else "-"
        print(
            f"      d{row['depth']} [{row['trust']:5}] {row['qualified_name']:22}"
            f" {row['location']:18} via={row['via'] or '-'}"
        )
        print(f"           chain: {chain}")

print("\n== scanner ==")
print(json.dumps(views.scan_summary(manifest), indent=2, ensure_ascii=False))
