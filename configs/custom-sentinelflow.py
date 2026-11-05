import json
import sys
import urllib.request


def main():
    alert_file = sys.argv[1]
    hook_url = sys.argv[3]
    with open(alert_file) as f:
        alert = json.load(f)
    req = urllib.request.Request(
        hook_url,
        data=json.dumps(alert).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        print("sent, status", resp.status)


main()
