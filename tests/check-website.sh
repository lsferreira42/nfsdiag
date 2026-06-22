#!/bin/sh
# Static validation of the website/ directory: every page must be parseable
# HTML/XML, internal links and assets must resolve to a file that exists, and
# the sitemap must be well-formed. Run from the repository root.
set -eu

SITE=website
fail=0
note() { echo "[FAIL] $1" >&2; fail=1; }

[ -d "$SITE" ] || { echo "[FAIL] $SITE not found" >&2; exit 1; }
command -v xmllint >/dev/null 2>&1 || { echo "[SKIP] xmllint not installed" >&2; exit 0; }

# Well-formedness: HTML pages (lenient HTML parser) and the XML sitemap.
for f in "$SITE"/*.html; do
    xmllint --html --noout "$f" 2>/dev/null || note "$f is not parseable HTML"
done
if [ -f "$SITE/sitemap.xml" ]; then
    xmllint --noout "$SITE/sitemap.xml" || note "sitemap.xml is not valid XML"
fi

# Internal links and assets resolve to an existing file. External (http///,
# mailto), anchors and query-only links are out of scope. A temp file collects
# failures because the link loop runs in a pipeline subshell.
flagfile=$(mktemp)
trap 'rm -f "$flagfile"' EXIT
for f in "$SITE"/*.html; do
    grep -oE '(href|src)="[^"]+"' "$f" | sed -E 's/^(href|src)="//; s/"$//' | while IFS= read -r link; do
        case "$link" in
            http:*|https:*|//*|mailto:*|data:*|"#"*|"") continue ;;
        esac
        target=${link%%#*}
        target=${target%%\?*}
        [ -z "$target" ] && continue
        case "$target" in
            /*) path="$SITE$target" ;;   # site-absolute
            *)  path="$SITE/$target" ;;  # page-relative (pages live at site root)
        esac
        if [ ! -e "$path" ]; then
            echo "[FAIL] $f: link '$link' -> missing $path" >&2
            echo x >>"$flagfile"
        fi
    done
done
[ -s "$flagfile" ] && fail=1

if [ "$fail" -eq 0 ]; then
    echo "[OK] website pages parse and internal links resolve"
fi
exit "$fail"
