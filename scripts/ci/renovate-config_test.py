#!/usr/bin/env python3
"""Config test for renovate.json and renovate-security.json (gauntlet #141,
items 1 and 5).

  - renovate.json sets top-level minimumReleaseAge "3 days";
  - the ghcr.io/aquasecurity/trivy package rule sets
    minimumReleaseAgeBehaviour "timestamp-optional" (ghcr.io gives no release
    time);
  - security fixes do not wait: vulnerabilityAlerts has no minimumReleaseAge,
    or null / "0 days"; the same for renovate-security.json at top level and
    in its vulnerabilityAlerts;
  - dependencyDashboard is the object form {"enabled": false};
  - both files are valid JSON; timezone and schedule keys are present.

Needs: python3 (stdlib only).
Run: python3 -I scripts/ci/renovate-config_test.py
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
failures = 0
total = 0


def check(name, ok, detail=""):
    global failures, total
    total += 1
    if ok:
        print("PASS " + name)
    else:
        failures += 1
        print("FAIL " + name + (": " + detail if detail else ""))


def load(name):
    path = os.path.join(ROOT, name)
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        check(name + " is valid JSON", False, str(e))
        return None
    check(name + " is valid JSON", isinstance(data, dict))
    return data if isinstance(data, dict) else None


def no_delay(obj):
    """True if obj sets no minimumReleaseAge, or null / '0 days'."""
    if "minimumReleaseAge" not in obj:
        return True
    return obj["minimumReleaseAge"] in (None, "0 days")


main = load("renovate.json")
sec = load("renovate-security.json")

if main is not None:
    check("renovate.json minimumReleaseAge is '3 days'",
          main.get("minimumReleaseAge") == "3 days",
          "got %r" % (main.get("minimumReleaseAge"),))

    trivy = [r for r in main.get("packageRules", [])
             if "ghcr.io/aquasecurity/trivy" in r.get("matchPackageNames", [])]
    check("a packageRule matches ghcr.io/aquasecurity/trivy", len(trivy) > 0)
    check("trivy rule sets minimumReleaseAgeBehaviour 'timestamp-optional'",
          any(r.get("minimumReleaseAgeBehaviour") == "timestamp-optional"
              for r in trivy),
          "got %r" % ([r.get("minimumReleaseAgeBehaviour") for r in trivy],))

    va = main.get("vulnerabilityAlerts", {})
    check("renovate.json vulnerabilityAlerts does not delay security fixes",
          isinstance(va, dict) and no_delay(va),
          "got %r" % (va.get("minimumReleaseAge") if isinstance(va, dict) else va,))

    check("dependencyDashboard is {'enabled': false}",
          main.get("dependencyDashboard") == {"enabled": False},
          "got %r" % (main.get("dependencyDashboard"),))

    check("renovate.json keeps timezone", "timezone" in main)
    check("renovate.json keeps schedule", "schedule" in main)

if sec is not None:
    check("renovate-security.json top level does not delay security fixes",
          no_delay(sec),
          "got %r" % (sec.get("minimumReleaseAge"),))
    sva = sec.get("vulnerabilityAlerts", {})
    check("renovate-security.json vulnerabilityAlerts does not delay security fixes",
          isinstance(sva, dict) and no_delay(sva),
          "got %r" % (sva.get("minimumReleaseAge") if isinstance(sva, dict) else sva,))

    # #141 item 2: this file is still read as global config by the daily
    # security run, so it may hold only these keys (no global-only options).
    top_ok = {"$schema", "description", "pruneStaleBranches",
              "osvVulnerabilityAlerts", "vulnerabilityAlerts", "packageRules"}
    extra = sorted(set(sec) - top_ok)
    check("renovate-security.json top-level keys are only the allowed ones",
          not extra, "unexpected %r" % (extra,))
    va_extra = sorted(set(sva) - {"enabled", "schedule"}) if isinstance(sva, dict) else ["not an object"]
    check("renovate-security.json vulnerabilityAlerts holds only enabled and schedule",
          not va_extra, "unexpected %r" % (va_extra,))
    rules = sec.get("packageRules", [])
    rule_extra = sorted({k for r in rules if isinstance(r, dict)
                         for k in set(r) - {"description", "matchPackageNames", "enabled"}}) \
        if isinstance(rules, list) else ["not a list"]
    check("renovate-security.json packageRules entries hold only description, matchPackageNames, enabled",
          not rule_extra, "unexpected %r" % (rule_extra,))

print("%d checks, %d failed" % (total, failures))
sys.exit(1 if failures else 0)
