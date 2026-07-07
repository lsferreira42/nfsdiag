#!/bin/sh
# Regenerate ./configure from configure.ac. Run after editing configure.ac or
# bumping VERSION (the cache is cleared so the embedded version stays in sync).
set -e
rm -rf autom4te.cache
autoreconf -i 2>/dev/null || autoconf
chmod +x configure
echo "configure regenerated."
