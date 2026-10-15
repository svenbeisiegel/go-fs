#!/bin/sh
# The account the service runs as, made before the files are put in place,
# since they are owned by it. rpm passes 1 on an install and 2 on an upgrade;
# either way an account that is there already is kept as it is.
getent group go-fs >/dev/null || groupadd --system go-fs
getent passwd go-fs >/dev/null || useradd --system --gid go-fs \
    --home-dir /var/lib/go-fs --no-create-home --shell /sbin/nologin \
    --comment "go-fs file server" go-fs
exit 0
