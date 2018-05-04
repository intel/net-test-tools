#/usr/bin/env bash

autoreconf -i

[ -z "$NOCONFIGURE" ] && ./configure -q --enable-maintainer-mode "$@"
