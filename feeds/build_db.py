import csv
import hashlib
import json
import sqlite3
import urllib.request
from pathlib import Path

B = Path(__file__).resolve().parent
db = B / "misp.db"
if db.exists():
    db.unlink()
con = sqlite3.connect(db)
con.execute("CREATE TABLE ioc(h TEXT, uuid TEXT)")
con.execute("CREATE TABLE events(uuid TEXT PRIMARY KEY, info TEXT, date TEXT, threat INTEGER)")
with open(B / "hashes.csv", newline="") as f:
    con.executemany("INSERT INTO ioc VALUES (?, ?)", (r for r in csv.reader(f) if len(r) == 2))
con.execute("CREATE INDEX idx_h ON ioc(h)")
m = json.load(open(B / "manifest.json"))
con.executemany(
    "INSERT INTO events VALUES (?, ?, ?, ?)",
    [(k, v.get("info"), v.get("date"), v.get("threat_level_id")) for k, v in m.items()],
)
con.commit()
print("ioc rows:", con.execute("SELECT count(*) FROM ioc").fetchone()[0], "| events:", con.execute("SELECT count(*) FROM events").fetchone()[0])


def lookup(value):
    h = hashlib.md5(value.encode()).hexdigest()
    return con.execute(
        "SELECT e.info, e.date, e.threat FROM ioc i JOIN events e ON e.uuid = i.uuid WHERE i.h = ?", (h,)
    ).fetchall()


uuid = next(iter(m))
ev = json.load(urllib.request.urlopen("https://www.circl.lu/doc/misp/feed-osint/%s.json" % uuid, timeout=30))
attrs = ev["Event"].get("Attribute", [])
pick = None
for t in ("sha256", "md5", "sha1", "ip-dst", "domain"):
    pick = next((a for a in attrs if a["type"] == t), None)
    if pick:
        break
if not pick:
    print("NO_ATTR_FOUND")
else:
    hit = lookup(pick["value"])
    print("TEST", pick["type"], pick["value"][:16] + "...", "->", "HIT" if hit else "MISS", hit[:1])
print("NEGATIVE test:", "HIT (unexpected)" if lookup("not-an-ioc-12345") else "no hit (correct)")
