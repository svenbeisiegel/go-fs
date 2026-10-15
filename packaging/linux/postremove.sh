#!/bin/sh
# The unit file is gone, or replaced, so systemd reads its units again. The
# configuration, the served files and the go-fs account are kept: they are
# the data of whoever ran the server.
[ -d /run/systemd/system ] || exit 0
systemctl daemon-reload >/dev/null 2>&1 || :
exit 0
