import json
import sys
from pathlib import Path

n = int(sys.argv[1]) if len(sys.argv) > 1 else 4
lines = (Path(__file__).parent / "alerts_triaged.jsonl").read_text().splitlines()[-n:]
for line in lines:
    r = json.loads(line)
    a = r["alert"]
    t = r.get("triage") or {}
    print(a.get("rule_id"), "|", a.get("description"), "| user:", a.get("target_user"), "| src:", a.get("src_ip"))
    print("   ->", t.get("verdict"), t.get("confidence"), t.get("severity"), t.get("mitre_technique"), "| overrides:", t.get("guard_overrides"), "| err:", r.get("error"))
    print("   ", t.get("reasoning"))
