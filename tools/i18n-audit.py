#!/usr/bin/env python3
"""
i18n-audit.py — key parity + placeholder audit for PGPony Desktop's two string layers.

The desktop carries the same `strings.xml` shape as the Android app on purpose (see
src/main/kotlin/com/pgpony/desktop/Strings.kt), so one script audits both trees:

    vendor/app-strings/   VERBATIM Android — a finding here is an UPSTREAM bug. Fix it in
                          PGPonyAndroid and re-run tools/sync-strings.sh; never edit in place.
    i18n/                 desktop-owned. Findings here are ours to fix.

What it checks, per layer, per locale, against that layer's English base:

  missing      a base key with no translation — renders in English (a warning, not an error:
               a half-translated file is allowed to degrade)
  extra        a translated key the base doesn't declare — dead weight, or a typo'd name, or a
               key that was deleted from the base and left behind in the translation
  placeholders %1$s / %2$d arity and CONVERSION TYPE mismatches against the base. This is the
               one that actually crashes at runtime: String.format throws on a %d handed a
               String. (tr() catches it and shows the raw template, so the symptom in the wild
               is "one label renders with visible % codes" — subtle enough to ship. Hence this
               script.)
  quantities   a <plurals> whose translation is missing the `other` item. `one` may be absent
               (Japanese has no plural form); `other` is the fallback trQuantity() lands on and
               must exist wherever the plural does.
  duplicates   the same name declared twice in one file — the later silently wins in the parser
               and in aapt, so this is always a mistake
  escapes      a literal `\'`-style escape left inside an XML comment (a real slip made while
               authoring these files: Android's escaping convention does not apply in comments)

Exit status is 0 when nothing worse than `missing` was found, 1 otherwise, so it can gate a
build. --strict promotes `missing` to an error too.

Usage:
    tools/i18n-audit.py                     both layers
    tools/i18n-audit.py --layer i18n        one layer
    tools/i18n-audit.py --strict            missing translations fail the run
    tools/i18n-audit.py --quiet             findings only, no per-locale summary
"""

import argparse
import os
import re
import sys
import xml.etree.ElementTree as ET

# Repo root, from tools/.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

LAYERS = [
    ("vendor/app-strings", "vendored Android (fix upstream, never here)"),
    ("i18n", "desktop-owned"),
]

# The locale set both layers ship. "values" is the English base.
LOCALE_DIRS = ["values", "values-de", "values-es", "values-fr", "values-ja", "values-pt-rBR"]

# Locales with a single CLDR plural category: `one` is not a missing translation there, it is a
# form the language does not have. Everything else must translate both items of every plural.
NO_PLURAL_DISTINCTION = {"values-ja"}

# %1$s, %2$d, %s, %d, %1$.2f ... — java.util.Formatter, which is also Android's syntax.
PLACEHOLDER = re.compile(r"%(?:(\d+)\$)?([-#+ 0,(]*)(\d+)?(?:\.(\d+))?([a-zA-Z])")

COMMENT_ESCAPE = re.compile(r"<!--.*?-->", re.S)


def placeholders(text):
    """
    Ordered (position, conversion) pairs. Positional args (%1$s) are keyed by their index so a
    translation may reorder them freely — that's the whole point of the positional form, and
    German and Japanese use it constantly. Non-positional (%s) are keyed by occurrence order.
    """
    out = {}
    auto = 0
    for m in PLACEHOLDER.finditer(text):
        conv = m.group(5)
        if conv == "%":
            continue
        if m.group(1):
            idx = int(m.group(1))
        else:
            auto += 1
            idx = auto
        # A repeated %1$s must agree with itself; last one wins for reporting, which is fine
        # because a self-disagreeing template is already reported as a mismatch downstream.
        out[idx] = conv.lower()
    return out


def parse_file(path):
    """
    -> (entries, duplicates, errors). `entries` maps key -> text, with plurals flattened to
    `name/quantity`, matching I18n.parse() in Strings.kt so the audit sees exactly what the app
    will see.
    """
    entries, dupes, errors = {}, [], []
    try:
        tree = ET.parse(path)
    except ET.ParseError as e:
        return entries, dupes, ["not well-formed XML: %s" % e]
    root = tree.getroot()

    def add(key, text):
        if key in entries:
            dupes.append(key)
        entries[key] = text

    for el in root:
        name = el.get("name")
        if not name:
            continue
        if el.tag == "string":
            add(name, "".join(el.itertext()))
        elif el.tag == "plurals":
            for item in el.findall("item"):
                q = item.get("quantity")
                if q:
                    add("%s/%s" % (name, q), "".join(item.itertext()))
    return entries, dupes, errors


def comment_escapes(path):
    """Android's backslash escapes inside an XML comment are literal text, not escapes."""
    with open(path, encoding="utf-8") as fh:
        body = fh.read()
    hits = []
    for m in COMMENT_ESCAPE.finditer(body):
        if re.search(r"\\['\"]", m.group(0)):
            line = body.count("\n", 0, m.start()) + 1
            hits.append(line)
    return hits


def audit_layer(layer, note, strict, quiet):
    base_dir = os.path.join(ROOT, layer)
    if not os.path.isdir(base_dir):
        print("  (skipped: %s not present)" % layer)
        return 0, 0
    base_path = os.path.join(base_dir, "values", "strings.xml")
    if not os.path.isfile(base_path):
        print("  ERROR: no English base at %s/values/strings.xml" % layer)
        return 1, 0

    errors = warnings = 0
    base, base_dupes, base_errs = parse_file(base_path)
    for e in base_errs:
        print("  ERROR %s/values/strings.xml: %s" % (layer, e))
        errors += 1
    for k in sorted(set(base_dupes)):
        print("  ERROR %s/values: duplicate key '%s'" % (layer, k))
        errors += 1
    for line in comment_escapes(base_path):
        print("  ERROR %s/values/strings.xml:%d: backslash escape inside an XML comment" % (layer, line))
        errors += 1

    print("  base: %d keys" % len(base))

    for d in LOCALE_DIRS:
        if d == "values":
            continue
        path = os.path.join(base_dir, d, "strings.xml")
        if not os.path.isfile(path):
            print("  ERROR %s/%s: missing strings.xml" % (layer, d))
            errors += 1
            continue

        entries, dupes, errs = parse_file(path)
        for e in errs:
            print("  ERROR %s/%s: %s" % (layer, d, e))
            errors += 1
        for k in sorted(set(dupes)):
            print("  ERROR %s/%s: duplicate key '%s'" % (layer, d, k))
            errors += 1
        for line in comment_escapes(path):
            print("  ERROR %s/%s/strings.xml:%d: backslash escape inside an XML comment"
                  % (layer, d, line))
            errors += 1

        missing = sorted(k for k in base if k not in entries)
        extra = sorted(k for k in entries if k not in base)

        # `one` may legitimately be absent (ja); `other` may not.
        plural_names = {k.split("/")[0] for k in base if "/" in k}
        for name in sorted(plural_names):
            if any(k.startswith(name + "/") for k in entries) and (name + "/other") not in entries:
                print("  ERROR %s/%s: plurals '%s' has no `other` item" % (layer, d, name))
                errors += 1
        if d in NO_PLURAL_DISTINCTION:
            missing = [k for k in missing if not k.endswith("/one")]

        bad = []
        for k, text in entries.items():
            if k not in base:
                continue
            want, got = placeholders(base[k]), placeholders(text)
            if want != got:
                bad.append((k, want, got))
        for k, want, got in sorted(bad):
            print("  ERROR %s/%s: placeholder mismatch in '%s' — base %s, translation %s"
                  % (layer, d, k, fmt_ph(want), fmt_ph(got)))
            errors += 1

        for k in extra:
            print("  ERROR %s/%s: '%s' is not declared in the English base" % (layer, d, k))
            errors += 1

        if missing:
            level = "ERROR" if strict else "warn "
            for k in missing:
                print("  %s %s/%s: '%s' not translated (falls back to English)" % (level, layer, d, k))
            if strict:
                errors += len(missing)
            else:
                warnings += len(missing)

        if not quiet:
            print("  %-14s %4d/%d translated%s" %
                  (d, len(base) - len(missing), len(base),
                   "" if not missing else "  (%d missing)" % len(missing)))

    return errors, warnings


def fmt_ph(d):
    return "{" + ", ".join("%%%d$%s" % (i, c) for i, c in sorted(d.items())) + "}" if d else "{none}"


def main():
    ap = argparse.ArgumentParser(description="PGPony Desktop string audit")
    ap.add_argument("--layer", action="append", help="audit only this layer (repeatable)")
    ap.add_argument("--strict", action="store_true", help="untranslated keys are errors too")
    ap.add_argument("--quiet", action="store_true", help="findings only, no per-locale summary")
    args = ap.parse_args()

    layers = [(l, n) for l, n in LAYERS if not args.layer or l in args.layer]
    total_e = total_w = 0
    for layer, note in layers:
        print("\n%s — %s" % (layer, note))
        e, w = audit_layer(layer, note, args.strict, args.quiet)
        total_e += e
        total_w += w

    print("\n%d error(s), %d untranslated key(s)." % (total_e, total_w))
    return 1 if total_e else 0


if __name__ == "__main__":
    sys.exit(main())
