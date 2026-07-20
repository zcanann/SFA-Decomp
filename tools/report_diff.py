#!/usr/bin/env python3
"""Per-unit, per-section differential between two report.json snapshots.

Usage:
    tools/report_diff.py snapshot <out.json>          # capture current report
    tools/report_diff.py diff <before.json> <after.json>

A splits.txt / symbols.txt edit rewrites every retail object, so a global
fuzzy delta is not enough to prove a change is local.  This prints every
unit+section whose fuzzy/total/matched numbers moved, plus the tree totals.
"""
import json
import sys


REPORT = "build/GSAE01/report.json"


def _key_metrics(m):
    return {
        "fuzzy": m.get("fuzzy_match_percent"),
        "total_code": m.get("total_code"),
        "matched_code": m.get("matched_code"),
        "total_data": m.get("total_data"),
        "matched_data": m.get("matched_data"),
        "matched_data_percent": m.get("matched_data_percent"),
        "matched_functions": m.get("matched_functions"),
        "complete_units": m.get("complete_units"),
        "total_units": m.get("total_units"),
    }


def capture(path):
    d = json.load(open(REPORT))
    out = {"totals": _key_metrics(d["measures"]), "units": {}}
    for u in d["units"]:
        name = u["name"]
        entry = {"measures": _key_metrics(u["measures"]), "sections": {}}
        for s in u.get("sections", []):
            entry["sections"][s["name"]] = {
                "size": s.get("size"),
                "virtual_address": (s.get("metadata") or {}).get("virtual_address"),
            }
        out["units"][name] = entry
    json.dump(out, open(path, "w"), indent=0, sort_keys=True)
    print("captured %d units -> %s" % (len(out["units"]), path))


def diff(before_path, after_path):
    a = json.load(open(before_path))
    b = json.load(open(after_path))

    moved = 0
    for name in sorted(set(a["units"]) | set(b["units"])):
        ua = a["units"].get(name)
        ub = b["units"].get(name)
        if ua is None:
            print("ADDED unit %s" % name)
            moved += 1
            continue
        if ub is None:
            print("REMOVED unit %s" % name)
            moved += 1
            continue
        if ua["measures"] != ub["measures"]:
            print("UNIT %s" % name)
            for k in sorted(ua["measures"]):
                if ua["measures"][k] != ub["measures"][k]:
                    print("    %-22s %s -> %s" % (k, ua["measures"][k], ub["measures"][k]))
            moved += 1
        for sec in sorted(set(ua["sections"]) | set(ub["sections"])):
            sa = ua["sections"].get(sec)
            sb = ub["sections"].get(sec)
            if sa != sb:
                print("  SECTION %s %s" % (name, sec))
                if sa is None or sb is None:
                    print("    %s -> %s" % (sa, sb))
                    continue
                for k in sorted(sa):
                    if sa[k] != sb[k]:
                        print("    %-22s %s -> %s" % (k, sa[k], sb[k]))

    print("\n=== units with moved measures: %d ===" % moved)
    print("TOTALS")
    for k in sorted(a["totals"]):
        if a["totals"][k] != b["totals"][k]:
            print("    %-22s %s -> %s" % (k, a["totals"][k], b["totals"][k]))
        else:
            print("    %-22s %s (unchanged)" % (k, a["totals"][k]))


def main():
    if len(sys.argv) >= 3 and sys.argv[1] == "snapshot":
        capture(sys.argv[2])
    elif len(sys.argv) == 4 and sys.argv[1] == "diff":
        diff(sys.argv[2], sys.argv[3])
    else:
        print(__doc__)
        sys.exit(2)


if __name__ == "__main__":
    main()
