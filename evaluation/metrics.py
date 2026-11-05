import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from statistics import median

B = Path(__file__).resolve().parent.parent


def rows(name):
    out, bad = [], 0
    p = B / name
    if not p.exists():
        return out, bad
    for line in p.read_text(errors="replace").splitlines():
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            bad += 1
    return out, bad


recv, b1 = rows("alerts_received.jsonl")
enr, b2 = rows("alerts_enriched.jsonl")
tri, b3 = rows("alerts_triaged.jsonl")
iris, b4 = rows("iris_sent.jsonl")

print("raw alerts received:", len(recv), "| enriched:", len(enr), "| triaged units:", len(tri), "| sent to IRIS:", len(iris))
print("unreadable lines (received/enriched/triaged/iris):", b1, b2, b3, b4)
print("top alert rules seen:")
for (rid, desc), n in Counter((r.get("rule_id"), r.get("description")) for r in enr).most_common(5):
    print("  ", n, "x", rid, (desc or "")[:50])

events = sum((r["alert"].get("event_count") or 1) for r in tri)
print("events represented in triage:", events, "| triage units:", len(tri))
print("enriched alerts not represented in any triage:", len(enr) - events)

done = [r for r in tri if r.get("triage")]
print("verdicts:", dict(Counter(r["triage"].get("verdict") for r in done)))
print("cases auto-created:", sum(1 for d in iris if (d.get("case") or {}).get("escalate_status") == 200), "| IRIS non-200:", sum(1 for d in iris if d.get("status") != 200))

lat = []
for r in tri:
    try:
        a = datetime.fromisoformat(r["alert"]["received_at"])
        b = datetime.fromisoformat(r["triaged_at"])
        lat.append((b - a).total_seconds())
    except Exception:
        pass
if lat:
    lat.sort()
    print("alert received -> triaged, seconds: median", round(median(lat)), "| 90th percentile", round(lat[int(0.9 * (len(lat) - 1))]), "| max", round(lat[-1]), "| n =", len(lat))
