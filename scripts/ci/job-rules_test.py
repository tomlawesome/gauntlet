#!/usr/bin/env python3
"""Job-set test for .gitlab-ci.yml (gauntlet #121, item "catch-up MRs skip the
secret and personal-details scans").

Evaluates workflow:rules and every job's rules: for these pipelines and
compares the set of jobs created with a hard-coded expectation:

  (a) a catch-up MR (chore/catchup-x -> batch-a): exactly catchup-check,
      lint:secrets, private-details, lint:flake-check;
  (b) a plain MR into dev, and (c) a push to dev: the sets the file produced
      before #121 (hard-coded below, so a later edit cannot move them silently).

Modelled on ai/agent-infra scripts/catchup-check/ci-template-test.sh: a small
evaluator for if: expressions (==, !=, =~, !~, &&, ||, parentheses, quoted
strings, /regex/, $VARS, null), plus include: resolution of ai/agent-infra
project files at their pinned ref via `git show` in the sibling checkout
(~/projects/agent-infra, read only), `!reference` and `extends` resolution.

Supported rule keys: if, when, variables (ignored for creation), allow_failure
(ignored). Anything else (changes:, exists:, needs:, start_in, ...), a regex
flag, a ${VAR} reference, a non-project include, or an unresolvable
!reference/extends makes the evaluation raise and the case FAIL with the
reason; nothing is guessed.

Needs: python3, PyYAML, git, ~/projects/agent-infra with the pinned refs.
Run: python3 -I scripts/ci/job-rules_test.py
"""
import copy
import os
import re
import subprocess
import sys

try:
    import yaml
except Exception:
    print("FAIL: PyYAML is not available")
    sys.exit(1)

HERE = os.path.dirname(os.path.abspath(__file__))
CI_FILE = os.path.join(HERE, "..", "..", ".gitlab-ci.yml")
AGENT_INFRA = os.path.expanduser(os.environ.get("AGENT_INFRA_DIR", "~/projects/agent-infra"))
INFRA_PROJECT = "ai/agent-infra"


class Unsupported(Exception):
    pass


class Ref(list):
    """A `!reference [job, key, ...]` node."""


class Loader(yaml.SafeLoader):
    pass


Loader.add_constructor(
    "!reference", lambda l, n: Ref(l.construct_sequence(n, deep=True))
)

# ---- loading and includes ----------------------------------------------------


def load_text(text):
    return yaml.load(text, Loader=Loader) or {}


def deep_merge(base, over):
    """GitLab merge: hashes merge recursively, everything else is replaced."""
    if isinstance(base, dict) and isinstance(over, dict):
        out = dict(base)
        for k, v in over.items():
            out[k] = deep_merge(base[k], v) if k in base else v
        return out
    return over


def git_show(ref, path):
    r = subprocess.run(
        ["git", "-C", AGENT_INFRA, "show", "%s:%s" % (ref, path)],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        raise Unsupported("git show %s:%s failed: %s" % (ref, path, r.stderr.strip()))
    return r.stdout


def load_pipeline():
    with open(CI_FILE) as f:
        main = load_text(f.read())
    merged = {}
    inc = main.get("include") or []
    if isinstance(inc, dict):
        inc = [inc]
    for item in inc:
        if not (isinstance(item, dict) and item.get("project") == INFRA_PROJECT
                and "ref" in item and "file" in item):
            raise Unsupported("include other than a pinned %s file: %r" % (INFRA_PROJECT, item))
        files = item["file"] if isinstance(item["file"], list) else [item["file"]]
        for fl in files:
            merged = deep_merge(merged, load_text(git_show(item["ref"], fl)))
    main = {k: v for k, v in main.items() if k != "include"}
    return deep_merge(merged, main)


def lookup_ref(doc, path, seen):
    if tuple(path) in seen:
        raise Unsupported("!reference cycle at %r" % (path,))
    node = doc
    for p in path:
        if not isinstance(node, dict) or p not in node:
            raise Unsupported("!reference %r does not resolve" % (path,))
        node = node[p]
    return resolve(doc, node, seen | {tuple(path)})


def resolve(doc, node, seen=frozenset()):
    """Replace Ref nodes (spliced into lists) throughout node."""
    if isinstance(node, Ref):
        return lookup_ref(doc, list(node), seen)
    if isinstance(node, list):
        out = []
        for x in node:
            if isinstance(x, Ref):
                v = lookup_ref(doc, list(x), seen)
                out.extend(v if isinstance(v, list) else [v])
            else:
                out.append(resolve(doc, x, seen))
        return out
    if isinstance(node, dict):
        return {k: resolve(doc, v, seen) for k, v in node.items()}
    return node


def resolve_extends(doc, name, stack=()):
    if name in stack:
        raise Unsupported("extends cycle at %s" % name)
    if name not in doc or not isinstance(doc[name], dict):
        raise Unsupported("extends names unknown job %s" % name)
    job = doc[name]
    ext = job.get("extends")
    if ext is None:
        return copy.deepcopy(job)
    ext = [ext] if isinstance(ext, str) else ext
    base = {}
    for e in ext:
        base = deep_merge(base, resolve_extends(doc, e, stack + (name,)))
    return deep_merge(base, {k: v for k, v in job.items() if k != "extends"})


RESERVED = {"stages", "variables", "workflow", "default", "include", "image",
            "services", "cache", "before_script", "after_script", "pages"}


def job_names(doc):
    return [k for k, v in doc.items()
            if not k.startswith(".") and k not in RESERVED and isinstance(v, dict)]

# ---- if: expressions ---------------------------------------------------------

TOKEN = re.compile(
    r'\s*(?:(\$[A-Za-z_][A-Za-z0-9_]*)|("(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\')'
    r'|(/(?:[^/\\]|\\.)*/)|(==|!=|=~|!~|&&|\|\||\(|\)|null\b))')


def tokenize(s):
    pos, out, s = 0, [], s.strip()
    while pos < len(s):
        m = TOKEN.match(s, pos)
        if not m:
            raise Unsupported("cannot tokenize %r at %d" % (s, pos))
        if m.group(1):
            out.append(("var", m.group(1)[1:]))
        elif m.group(2):
            out.append(("str", m.group(2)[1:-1]))
        elif m.group(3):
            out.append(("re", m.group(3)[1:-1].replace("\\/", "/")))
            if s[m.end():m.end() + 1] in ("i", "m", "s"):
                raise Unsupported("regex flags in %r" % s)
        else:
            out.append(("op", m.group(4)))
        pos = m.end()
    return out


def evaluate(expr, env):
    toks = tokenize(expr)
    i = [0]

    def peek():
        return toks[i[0]] if i[0] < len(toks) else (None, None)

    def take():
        t = peek()
        i[0] += 1
        return t

    def truthy(v):
        return v is not None and v != "" and v is not False

    def atom():
        k, v = take()
        if k == "var":
            return env.get(v)
        if k == "str":
            return v
        if k == "re":
            return re.compile(v)
        if (k, v) == ("op", "null"):
            return None
        if (k, v) == ("op", "("):
            r = or_()
            if take() != ("op", ")"):
                raise Unsupported("missing ) in %r" % expr)
            return r
        raise Unsupported("unexpected %r in %r" % (v, expr))

    def cmp_():
        a = atom()
        if peek() in (("op", "=="), ("op", "!="), ("op", "=~"), ("op", "!~")):
            op = take()[1]
            b = atom()
            if op in ("=~", "!~"):
                if not isinstance(b, re.Pattern):
                    raise Unsupported("non-regex right side of %s in %r" % (op, expr))
                hit = a is not None and b.search(a) is not None
                return hit if op == "=~" else not hit
            return (a == b) if op == "==" else (a != b)
        return a

    def and_():
        r = cmp_()
        while peek() == ("op", "&&"):
            take()
            b = cmp_()
            r = truthy(r) and truthy(b)
        return r

    def or_():
        r = and_()
        while peek() == ("op", "||"):
            take()
            b = and_()
            r = truthy(r) or truthy(b)
        return r

    r = or_()
    if i[0] != len(toks):
        raise Unsupported("trailing tokens in %r" % expr)
    return truthy(r)

# ---- rules -------------------------------------------------------------------

RULE_KEYS = {"if", "when", "variables", "allow_failure"}
WHENS = {"on_success", "always", "manual", "delayed", "on_failure", "never"}


def first_match(rules, env, what):
    """Return the first matching rule dict, or None."""
    if not isinstance(rules, list):
        raise Unsupported("%s: rules is not a list" % what)
    for r in rules:
        if not isinstance(r, dict):
            raise Unsupported("%s: rule is not a mapping: %r" % (what, r))
        extra = set(r) - RULE_KEYS
        if extra:
            raise Unsupported("%s: unsupported rule keys %s" % (what, sorted(extra)))
        if r.get("when", "on_success") not in WHENS:
            raise Unsupported("%s: unknown when %r" % (what, r.get("when")))
        if "if" not in r or evaluate(r["if"], env):
            return r
    return None


def jobs_created(doc, ctx):
    """Names of the jobs a pipeline with predefined variables ctx creates."""
    env = {k: str(v) for k, v in (doc.get("variables") or {}).items()}
    env.update(ctx)
    wf = (doc.get("workflow") or {}).get("rules")
    if wf is not None:
        r = first_match(wf, env, "workflow")
        if r is None or r.get("when") == "never":
            return set()
        env.update({k: str(v) for k, v in (r.get("variables") or {}).items()})
    out = set()
    for name in job_names(doc):
        job = resolve_extends(doc, name)
        if "rules" not in job:
            if job.get("when") != "never":
                out.add(name)
            continue
        r = first_match(job["rules"], env, name)
        if r is not None and r.get("when", "on_success") != "never":
            out.add(name)
    return out

# ---- the cases ---------------------------------------------------------------

CATCHUP = {"catchup-check", "lint:secrets", "private-details", "lint:flake-check",
           "lint:script-tests"}
# lint:script-tests (#123) runs wherever lint:flake-check runs (same rules).

# Today's sets (base 9f4f784), computed from the file before #121 and fixed here.
PLAIN_MR_DEV = {
    "lint:go", "lint:licences", "lint:vulncheck", "lint:trivy", "lint:shellcheck", "lint:apidiff", "lint:secrets",
    "lint:flake-check", "lint:script-tests", "private-details", "test:go",
    "test:contract",
}
PUSH_DEV = {"lint:secrets", "lint:flake-check", "lint:script-tests", "private-details"}

# The sets below lock today's behaviour (computed by this evaluator against
# the .gitlab-ci.yml of this change, not judged right or wrong); every set
# that holds lint:flake-check also holds lint:script-tests (#123).
MR_BATCH = {
    "lint:go", "lint:licences", "lint:vulncheck", "lint:trivy", "lint:shellcheck", "lint:apidiff", "lint:secrets",
    "lint:flake-check", "lint:script-tests", "private-details",
}
FULL_GATE = PLAIN_MR_DEV  # lint jobs plus test:go and test:contract
MAIN_PUSH = FULL_GATE | {"release:gitlab", "release:version"}
# #122: promotion MRs (dev -> preview, preview -> main) run the full gate plus
# the release-readiness check, which runs first.
PROMOTION = FULL_GATE | {"release_readiness"}

CASES = [
    ("(a) catch-up MR chore/catchup-x -> batch-a creates exactly the four scan and check jobs",
     {"CI_PIPELINE_SOURCE": "merge_request_event",
      "CI_MERGE_REQUEST_SOURCE_BRANCH_NAME": "chore/catchup-x",
      "CI_MERGE_REQUEST_TARGET_BRANCH_NAME": "batch-a"}, CATCHUP),
    ("(b) plain MR feature/x -> dev creates today's job set",
     {"CI_PIPELINE_SOURCE": "merge_request_event",
      "CI_MERGE_REQUEST_SOURCE_BRANCH_NAME": "feature/x",
      "CI_MERGE_REQUEST_TARGET_BRANCH_NAME": "dev"}, PLAIN_MR_DEV),
    ("(c) push to dev creates today's job set",
     {"CI_PIPELINE_SOURCE": "push", "CI_COMMIT_BRANCH": "dev"}, PUSH_DEV),
    ("(d) push to batch-b creates no jobs (an MR covers it)",
     {"CI_PIPELINE_SOURCE": "push", "CI_COMMIT_BRANCH": "batch-b"}, set()),
    ("(e) MR feature/x -> batch-a creates the lint jobs, no test jobs",
     {"CI_PIPELINE_SOURCE": "merge_request_event",
      "CI_MERGE_REQUEST_SOURCE_BRANCH_NAME": "feature/x",
      "CI_MERGE_REQUEST_TARGET_BRANCH_NAME": "batch-a"}, MR_BATCH),
    ("(f) MR feature/x -> batch-b creates the lint jobs, no test jobs",
     {"CI_PIPELINE_SOURCE": "merge_request_event",
      "CI_MERGE_REQUEST_SOURCE_BRANCH_NAME": "feature/x",
      "CI_MERGE_REQUEST_TARGET_BRANCH_NAME": "batch-b"}, MR_BATCH),
    ("(g) push to preview creates the full gate plus release_readiness (#134)",
     {"CI_PIPELINE_SOURCE": "push", "CI_COMMIT_BRANCH": "preview"}, PROMOTION),
    ("(h) push to main creates the full gate plus the release jobs",
     {"CI_PIPELINE_SOURCE": "push", "CI_COMMIT_BRANCH": "main"}, MAIN_PUSH),
    ("(i) scheduled pipeline creates no jobs",
     {"CI_PIPELINE_SOURCE": "schedule", "CI_COMMIT_BRANCH": "dev"}, set()),
    ("(j) tag pipeline (v1.0.0) creates no jobs",
     {"CI_PIPELINE_SOURCE": "push", "CI_COMMIT_TAG": "v1.0.0"}, set()),
    ("(k) web pipeline on main creates the full gate, no release jobs",
     {"CI_PIPELINE_SOURCE": "web", "CI_COMMIT_BRANCH": "main"}, FULL_GATE),
    ("(k2) web pipeline on preview creates the full gate, no release_readiness (#134)",
     {"CI_PIPELINE_SOURCE": "web", "CI_COMMIT_BRANCH": "preview"}, FULL_GATE),
    ("(l) MR dev -> preview creates the full gate plus release_readiness (#122)",
     {"CI_PIPELINE_SOURCE": "merge_request_event",
      "CI_MERGE_REQUEST_SOURCE_BRANCH_NAME": "dev",
      "CI_MERGE_REQUEST_TARGET_BRANCH_NAME": "preview"}, PROMOTION),
    ("(m) MR preview -> main creates the full gate plus release_readiness (#122)",
     {"CI_PIPELINE_SOURCE": "merge_request_event",
      "CI_MERGE_REQUEST_SOURCE_BRANCH_NAME": "preview",
      "CI_MERGE_REQUEST_TARGET_BRANCH_NAME": "main"}, PROMOTION),
    # P-RS1: RENOVATE=true only matters in a schedule pipeline; in any other
    # source it must not create the renovate job (the sets are today's).
    ("(p) schedule on dev with RENOVATE=true creates exactly renovate (P-RS1)",
     {"CI_PIPELINE_SOURCE": "schedule", "CI_COMMIT_BRANCH": "dev",
      "RENOVATE": "true"}, {"renovate"}),
    ("(q) web pipeline on dev with RENOVATE=true creates the full gate, no renovate (P-RS1)",
     {"CI_PIPELINE_SOURCE": "web", "CI_COMMIT_BRANCH": "dev",
      "RENOVATE": "true"}, FULL_GATE),
    ("(q2) api pipeline on dev with RENOVATE=true creates the full gate, no renovate (P-RS1)",
     {"CI_PIPELINE_SOURCE": "api", "CI_COMMIT_BRANCH": "dev",
      "RENOVATE": "true"}, FULL_GATE),
    ("(r) push to dev with RENOVATE=true creates today's push set, no renovate (P-RS1)",
     {"CI_PIPELINE_SOURCE": "push", "CI_COMMIT_BRANCH": "dev",
      "RENOVATE": "true"}, PUSH_DEV),
]

# (n) In every promotion pipeline (both MRs and the push to preview, #134) every job other than release_readiness must
# be unable to start before it: in a later stage than release_readiness, and,
# if it names `needs:`, listing release_readiness (a needs list without it
# would let the job start at once). release_readiness itself is in the first
# stage, `readiness`.
PROMOTION_CTXS = [
    ("MR dev -> preview", {"CI_PIPELINE_SOURCE": "merge_request_event",
                           "CI_MERGE_REQUEST_SOURCE_BRANCH_NAME": "dev",
                           "CI_MERGE_REQUEST_TARGET_BRANCH_NAME": "preview"}),
    ("MR preview -> main", {"CI_PIPELINE_SOURCE": "merge_request_event",
                            "CI_MERGE_REQUEST_SOURCE_BRANCH_NAME": "preview",
                            "CI_MERGE_REQUEST_TARGET_BRANCH_NAME": "main"}),
    ("push to preview", {"CI_PIPELINE_SOURCE": "push", "CI_COMMIT_BRANCH": "preview"}),
]


def need_names(job):
    out = []
    for n in job.get("needs") or []:
        out.append(n.get("job") if isinstance(n, dict) else n)
    return out


def ordering_problems(doc, ctx):
    stages = doc.get("stages") or []
    rr = resolve_extends(doc, "release_readiness")
    problems = []
    if not stages or stages[0] != "readiness":
        problems.append("first stage is %r, want 'readiness'" % (stages[:1],))
    if rr.get("stage") != "readiness":
        problems.append("release_readiness is in stage %r, want 'readiness'" % rr.get("stage"))
    for name in sorted(jobs_created(doc, ctx) - {"release_readiness"}):
        job = resolve_extends(doc, name)
        stage = job.get("stage", "test")
        later = stage in stages and "readiness" in stages and stages.index(stage) > stages.index("readiness")
        if "needs" in job:
            if "release_readiness" not in need_names(job):
                problems.append("%s has needs without release_readiness" % name)
        elif not later:
            problems.append("%s (stage %s) is not after the readiness stage" % (name, stage))
    return problems


def source_ref_problems(doc):
    """release_readiness must read the MR's source branch sha, set inline on
    the command: a job-level variables: entry could be overridden by a
    project or pipeline variable (#122)."""
    rr = resolve_extends(doc, "release_readiness")
    problems = []
    script = rr.get("script") or []
    lines = [l for x in script for l in str(x).splitlines()]
    if not any("CI_MERGE_REQUEST_SOURCE_BRANCH_SHA" in l for l in lines):
        problems.append("script never mentions CI_MERGE_REQUEST_SOURCE_BRANCH_SHA")
    want = ('READINESS_SOURCE_REF="${CI_MERGE_REQUEST_SOURCE_BRANCH_SHA:-$CI_COMMIT_SHA}"',
            'READINESS_TARGET_REF="origin/$target"')
    # #134: $target is the MR's target, or main in preview's push pipeline,
    # set in the script itself, never from a variables: entry.
    if 'target="${CI_MERGE_REQUEST_TARGET_BRANCH_NAME:-main}"' not in lines:
        problems.append('script does not set target="${CI_MERGE_REQUEST_TARGET_BRANCH_NAME:-main}" on its own line')
    if not any('target=main' in l for l in lines) or not any('unset CI_MERGE_REQUEST_SOURCE_BRANCH_SHA' in l for l in lines):
        problems.append("a push pipeline does not pin target=main and drop CI_MERGE_REQUEST_SOURCE_BRANCH_SHA")
    cmd = [l for l in lines if "scripts/release-readiness.sh" in l and not l.lstrip().startswith("#")]
    if not cmd or not all(w in cmd[-1] and cmd[-1].index(w) < cmd[-1].index("scripts/release-readiness.sh") for w in want):
        problems.append("the release-readiness.sh command line lacks the inline %s and %s" % want)
    held = sorted(k for k in (rr.get("variables") or {}) if k.startswith("READINESS_"))
    if held:
        problems.append("variables: holds %s" % held)
    return problems


def main():
    fails = 0
    try:
        raw = load_pipeline()
        doc = resolve(raw, raw)
    except Exception as e:
        print("FAIL: cannot load .gitlab-ci.yml and its includes -- [%s]" % e)
        print("job-rules_test: 0 passed, 1 failed")
        return 1
    passes = 0
    for name, ctx, want in CASES:
        try:
            got = jobs_created(doc, ctx)
        except Exception as e:
            print("FAIL: %s -- [cannot evaluate: %s]" % (name, e))
            fails += 1
            continue
        if got == want:
            print("PASS: " + name)
            passes += 1
        else:
            print("FAIL: %s -- [missing %s; unexpected %s]" % (
                name, sorted(want - got), sorted(got - want)))
            fails += 1
    for label, ctx in PROMOTION_CTXS:
        name = "(n) %s: every job other than release_readiness waits for it (#122)" % label
        try:
            problems = ordering_problems(doc, ctx)
        except Exception as e:
            print("FAIL: %s -- [cannot evaluate: %s]" % (name, e))
            fails += 1
            continue
        if not problems:
            print("PASS: " + name)
            passes += 1
        else:
            print("FAIL: %s -- %s" % (name, problems))
            fails += 1
    name = "(o) release_readiness takes the source branch sha, inline, not from variables: (#122)"
    try:
        problems = source_ref_problems(doc)
    except Exception as e:
        problems = ["cannot evaluate: %s" % e]
    if not problems:
        print("PASS: " + name)
        passes += 1
    else:
        print("FAIL: %s -- %s" % (name, problems))
        fails += 1
    print("job-rules_test: %d passed, %d failed" % (passes, fails))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
