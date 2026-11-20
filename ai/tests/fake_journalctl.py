#!/usr/bin/env python3
"""Stand-in for journalctl in tests: prints the JSON entries of $HORNET_FAKE_JOURNAL
that match every FIELD=value argument, like `journalctl -o json FIELD=value ...`."""
import json
import os
import sys

if os.environ.get("HORNET_FAKE_JOURNAL_FAIL"):
    sys.exit("Failed to open journal")
matches = dict(a.split("=", 1) for a in sys.argv[1:] if "=" in a and not a.startswith("-"))
try:
    with open(os.environ["HORNET_FAKE_JOURNAL"]) as f:
        lines = f.readlines()
except (KeyError, FileNotFoundError):
    lines = []
for line in lines:
    entry = json.loads(line)
    if all(str(entry.get(k)) == v for k, v in matches.items()):
        sys.stdout.write(line)
