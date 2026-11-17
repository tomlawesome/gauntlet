#!/usr/bin/env python3
"""Look inside the Go modules gauntlet links for code and files their
declared licence does not cover (#64).

The second half of scripts/licence-check.sh. The first half,
`go-licenses check`, gives every linked package the licence of the
nearest licence file above it in its module and holds that to the
allow-list. That already covers vendored code that carries its own
licence file: go-webauthn/x's revoke/ (BSD-2-Clause) and
crypto/secp256k1/ (ISC) and go-jose's json/ (BSD-3-Clause) are each
checked by their own file, not by their module's. What go-licenses
cannot see is the same gap birdcage #179 found in pip packages: code
that hides behind its carrier's licence, and files that have no licence
field at all. This script checks those two:

  - Vendored code with no licence of its own. A linked package under a
    `vendor`, `third_party`, `third-party` or `thirdparty` directory (at
    any depth, so `internal/third_party` too) with no LICENSE, LICENCE,
    COPYING or UNLICENSE file between it and that directory. go-licenses
    would credit it to the module's root licence, which is exactly how
    someone else's code passes unread.
  - Embedded files. Every file a linked package embeds with //go:embed is
    compiled into each binary that links it: web pages, stylesheets,
    scripts, images, fonts, and data files too (a dataset is someone
    else's work as often as a font is). None of them carries a licence
    field, and go-licenses never looks at them.

Each such file must sit under a reviewed entry in supply-chain/
licence-policy.yml's `go-bundled-assets:` list, in birdcage's
python-bundled-assets shape: "<module>@<version> <path-prefix> <licence
or finding>", the prefix relative to the module's root. An unreviewed
file fails. An entry that matches no shipped file is stale and fails. A
version bump stops the module's entries matching, on purpose, so the
files are read again.

What counts as shipped: the non-test dependencies of the main module's
packages, from `go list -deps ./...` -- the same set `go-licenses check
./...` gates, and what an application linking gauntlet compiles in.
Test-only modules (kin-openapi, mmdbwriter) never reach a binary. The
main module's own files are its own and are not checked here.

Files a module carries but nothing links or embeds -- a README badge, a
vendored directory no linked package sits in -- never reach a binary
either. They are listed, so whoever reads the log can see them, but need
no review.

This script never reads what a licence file says: it only notes where
one is. Deciding what a file's licence is, and whether it is acceptable,
is for whoever records the review.

Usage: licence-check-bundled.py <policy_file> [package pattern ...]
  Runs `go list -deps -json` on the patterns (default ./...) in the
  current directory.
Exit codes: 0 clean; 1 an unreviewed file or a stale review; 2 the
policy file or `go list` could not be read.
"""
import json
import os
import re
import subprocess
import sys

VENDOR_DIRS = {"vendor", "third_party", "third-party", "thirdparty"}

# Names of a file that states a licence. Deliberately narrower than
# go-licenses' own pattern, which also takes README and NOTICE: neither
# is a licence, so a vendored directory with only those has no licence
# of its own.
LICENCE_FILE = re.compile(r"^(?i:(UN)?LICEN[CS]E|COPYING)")

# Files a module can carry that are the usual vehicle for someone else's
# work. Only used to list what ships nowhere; every embedded file needs a
# review whatever its type.
ASSET_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".bmp", ".webp",
    ".css", ".js", ".mjs", ".html", ".htm", ".tmpl",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp3", ".wav", ".mp4", ".mmdb",
}

# Every kind of source file `go list` reports for a package: all of them
# are compiled into the package.
SOURCE_FIELDS = (
    "GoFiles", "CgoFiles", "CFiles", "CXXFiles", "MFiles", "HFiles",
    "FFiles", "SFiles", "SwigFiles", "SwigCXXFiles", "SysoFiles",
)


def read_reviews(policy_file):
    """Return the `go-bundled-assets:` entries as (module@version, prefix,
    licence) tuples. Same hand-rolled reading as licence-check.sh's awk
    and birdcage's checker: the file's shape is simple and fixed, and no
    YAML library is needed in the CI image. `go-bundled-assets: []` is an
    empty list."""
    reviews = []
    in_list = False
    with open(policy_file, encoding="utf-8") as f:
        for line in f:
            stripped = line.rstrip("\n")
            if stripped.startswith("go-bundled-assets:"):
                in_list = True
                continue
            if in_list and stripped and not stripped[0].isspace():
                break
            if in_list:
                text = stripped.strip()
                if text.startswith("- "):
                    entry = text[2:].split(" #", 1)[0].strip()
                    parts = entry.split(None, 2)
                    if len(parts) != 3:
                        raise ValueError(f"go-bundled-assets entry needs three fields: {entry!r}")
                    reviews.append((parts[0], parts[1], parts[2]))
    return reviews


def go_list(patterns):
    out = subprocess.run(
        ["go", "list", "-deps", "-json", "--", *patterns],
        check=True, capture_output=True, text=True,
    ).stdout
    decoder = json.JSONDecoder()
    pkgs, i = [], 0
    while True:
        while i < len(out) and out[i].isspace():
            i += 1
        if i >= len(out):
            return pkgs
        obj, i = decoder.raw_decode(out, i)
        pkgs.append(obj)


def nearest_licence(directory, stop):
    """The first licence file in directory or a parent of it, up to and
    including stop, or None."""
    d, stop = os.path.normpath(directory), os.path.normpath(stop)
    while True:
        try:
            names = sorted(os.listdir(d))
        except OSError:
            names = []
        for n in names:
            if LICENCE_FILE.match(n) and os.path.isfile(os.path.join(d, n)):
                return os.path.join(d, n)
        if d == stop or len(d) <= len(stop):
            return None
        d = os.path.dirname(d)


def vendored_root(rel):
    """For a package path relative to its module root, return the
    vendored directory it sits in ("third_party/foo") and the
    vendor-named directory itself ("third_party"), or (None, None)."""
    parts = rel.split("/") if rel != "." else []
    for i, part in enumerate(parts):
        if part in VENDOR_DIRS:
            return "/".join(parts[: i + 2]), "/".join(parts[: i + 1])
    return None, None


def root_licence_text(mod_dir):
    try:
        names = sorted(os.listdir(mod_dir))
    except OSError:
        return None
    for n in names:
        p = os.path.join(mod_dir, n)
        if LICENCE_FILE.match(n) and os.path.isfile(p):
            with open(p, "rb") as f:
                return f.read()
    return None


def unshipped(mod_dir, linked_dirs, shipped_files):
    """Vendored or separately licensed directories no linked package sits
    in, and asset-type files nothing embeds: present in the module,
    absent from every binary. Listed for the reader, never failed."""
    notes = []
    root_text = root_licence_text(mod_dir)
    for root, dirs, files in os.walk(mod_dir):
        dirs[:] = sorted(d for d in dirs if not d.startswith((".", "_")) and d != "testdata")
        rel = os.path.relpath(root, mod_dir)
        rel = "" if rel == "." else rel
        inside_linked = any(ld == rel or ld.startswith(rel + "/") if rel else True for ld in linked_dirs)
        base = os.path.basename(root)
        parent = os.path.basename(os.path.dirname(root))
        if rel and (base in VENDOR_DIRS or parent in VENDOR_DIRS) and not inside_linked:
            notes.append(f"{rel}/ (vendored, not linked)")
            dirs[:] = []
            continue
        if rel and not inside_linked:
            for n in files:
                p = os.path.join(root, n)
                if LICENCE_FILE.match(n):
                    with open(p, "rb") as f:
                        if f.read() != root_text:
                            notes.append(f"{rel}/ (own licence file {n}, not linked)")
                            break
        for n in sorted(files):
            path = f"{rel}/{n}" if rel else n
            if os.path.splitext(n)[1].lower() in ASSET_EXTENSIONS and path not in shipped_files:
                notes.append(f"{path} (not embedded by linked code)")
    return notes


def main(argv):
    if len(argv) < 2:
        print(f"usage: {argv[0]} <policy_file> [package pattern ...]", file=sys.stderr)
        return 2
    policy_file, patterns = argv[1], argv[2:] or ["./..."]
    try:
        reviews = read_reviews(policy_file)
    except (OSError, ValueError) as e:
        print(f"licence-check-bundled: cannot read {policy_file}: {e}", file=sys.stderr)
        return 2
    try:
        pkgs = go_list(patterns)
    except (subprocess.CalledProcessError, ValueError) as e:
        detail = getattr(e, "stderr", "") or str(e)
        print(f"licence-check-bundled: go list failed: {detail}", file=sys.stderr)
        return 2

    modules = {}  # module@version -> {"dir", "linked_dirs", "files": {path: why}}
    own_licence = []  # (module@version, licence file) of linked code licensed apart from its module
    for p in pkgs:
        mod = p.get("Module")
        if p.get("Standard") or not mod or mod.get("Main"):
            continue
        key = f"{mod['Path']}@{mod.get('Version', '')}"
        mod_dir = mod.get("Dir") or ""
        entry = modules.setdefault(key, {"dir": mod_dir, "linked_dirs": set(), "files": {}})
        rel = os.path.relpath(p["Dir"], mod_dir).replace(os.sep, "/")
        entry["linked_dirs"].add("" if rel == "." else rel)
        prefix = "" if rel == "." else rel + "/"

        # Listed for the reader: linked code whose nearest licence file is
        # not the module's own. go-licenses gates these by that file.
        nearest = nearest_licence(p["Dir"], mod_dir)
        if nearest and os.path.dirname(nearest) != os.path.normpath(mod_dir):
            with open(nearest, "rb") as f:
                if f.read() != root_licence_text(mod_dir):
                    lrel = os.path.relpath(nearest, mod_dir).replace(os.sep, "/")
                    own_licence.append((key, lrel))

        vdir, vname = vendored_root(rel)
        if vdir is not None:
            if not nearest_licence(p["Dir"], os.path.join(mod_dir, vname)):
                for field in SOURCE_FIELDS:
                    for f in p.get(field) or []:
                        entry["files"][prefix + f] = "vendored code, no licence of its own"

        for f in p.get("EmbedFiles") or []:
            entry["files"][prefix + f] = "embedded"

    unreviewed = {}  # (module@version, directory, why) -> count
    reviewed = {}  # review -> count
    used = set()
    for key, entry in sorted(modules.items()):
        for path, why in sorted(entry["files"].items()):
            review = next((r for r in reviews if r[0] == key and path.startswith(r[1])), None)
            if review is None:
                k = (key, os.path.dirname(path) or ".", why)
                unreviewed[k] = unreviewed.get(k, 0) + 1
            else:
                used.add(review)
                reviewed[review] = reviewed.get(review, 0) + 1

    print(f"licence-check-bundled: {len(modules)} linked module(s) checked for vendored code and embedded files")
    for key, lfile in sorted(set(own_licence)):
        print(f"  {key} {lfile} -- linked code under its own licence file, gated by go-licenses above")
    for key, entry in sorted(modules.items()):
        shipped = set(entry["files"])
        for note in unshipped(entry["dir"], entry["linked_dirs"], shipped):
            print(f"  {key} {note} -- ships in no binary, no review needed")

    failed = False
    if unreviewed:
        failed = True
        print(
            f"licence-check-bundled: {sum(unreviewed.values())} shipped file(s) with no "
            "go-bundled-assets review -- they carry no licence of their own, so each "
            "directory needs reading and its licence recording:",
            file=sys.stderr,
        )
        for (key, directory, why), count in sorted(unreviewed.items()):
            print(f"  {key} {directory}/ ({count} file(s), {why})", file=sys.stderr)

    stale = [r for r in reviews if r not in used]
    if stale:
        failed = True
        print(
            f"licence-check-bundled: {len(stale)} stale go-bundled-assets review(s) in "
            f"{policy_file} matched no shipped file -- delete them, or review the new version:",
            file=sys.stderr,
        )
        for name_version, prefix, licence in stale:
            print(f"  {name_version} {prefix} {licence}", file=sys.stderr)

    if failed:
        return 1

    if reviewed:
        print(f"licence-check-bundled: {sum(reviewed.values())} shipped file(s) passed by recorded review:")
        for (name_version, prefix, licence), count in sorted(reviewed.items()):
            print(f"  {name_version} {prefix} ({count}) -- {licence}")
    print("licence-check-bundled: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
