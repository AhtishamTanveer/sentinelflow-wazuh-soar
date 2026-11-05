import copy
import json
import sys
import time
from pathlib import Path

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE.parent))
import app as sf

model = sys.argv[1]
mode = sys.argv[2] if len(sys.argv) > 2 else "full"
sf.MODEL = model
data = json.loads((BASE / "dataset.json").read_text())
if mode == "quick":
    data = [data[0], data[8], data[16]]

rows = []
for i, item in enumerate(data, 1):
    expected = item["expected_verdict"]
    enriched = {k: v for k, v in item.items() if k != "expected_verdict"}
    enriched["received_at"] = "eval"
    t0 = time.time()
    raw, err = None, None
    try:
        raw = sf.triage(copy.deepcopy(enriched))
    except Exception as e:
        err = str(e)[:120]
    secs = round(time.time() - t0, 1)
    raw_v = raw.get("verdict") if raw else "error"
    final_v = raw_v
    if raw:
        final_v = sf.guard(copy.deepcopy(enriched), copy.deepcopy(raw)).get("verdict")
    rows.append({"i": i, "rule": item["rule_id"], "expected": expected, "raw": raw_v, "final": final_v, "secs": secs, "error": err, "llm": raw})
    print(i, "/", len(data), "| rule", item["rule_id"], "| expected", expected, "| raw", raw_v, "| final", final_v, "|", secs, "s", flush=True)


def summary(key):
    ok = sum(1 for r in rows if r[key] == r["expected"])
    fn = sum(1 for r in rows if r["expected"] == "true_positive" and r[key] == "false_positive")
    over = sum(1 for r in rows if r["expected"] == "false_positive" and r[key] == "true_positive")
    return ok, fn, over


n = len(rows)
for key, name in (("raw", "LLM only"), ("final", "LLM + validation")):
    ok, fn, over = summary(key)
    print(name, "| accuracy", ok, "/", n, "| missed attacks (TP->FP)", fn, "| over-escalated (FP->TP)", over)
print("avg seconds per alert:", round(sum(r["secs"] for r in rows) / n, 1), "| errors:", sum(1 for r in rows if r["error"]))
out = BASE / ("results_" + model.replace(":", "_").replace("/", "_") + "_" + mode + ".json")
out.write_text(json.dumps(rows, indent=1))
print("saved", out.name)
