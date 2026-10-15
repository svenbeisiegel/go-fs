#!/bin/sh
# rpm passes 0 when the package is removed and 1 when it is upgraded. Only a
# removal stops and disables the service; an upgrade restarts it after.
[ -d /run/systemd/system ] || exit 0
if [ "${1:-0}" -eq 0 ]; then
    systemctl disable --now go-fs.service >/dev/null 2>&1 || :
fi
exit 0
