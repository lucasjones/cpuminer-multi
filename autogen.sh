#!/bin/sh
# Regenerate the build system. Needs autoconf >= 2.69, automake >= 1.14
# and pkg-config (or pkgconf).

set -e

autoreconf -fi
