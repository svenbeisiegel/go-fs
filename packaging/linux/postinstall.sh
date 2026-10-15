#!/bin/sh
# rpm passes 1 on an install and 2 or more on an upgrade. The service is
# enabled and started on the install, and restarted into the new binary on an
# upgrade, unless it had been stopped. Without systemd running, in a container
# build for instance, there is nothing to start.
[ -d /run/systemd/system ] || exit 0
systemctl daemon-reload >/dev/null 2>&1 || :
if [ "${1:-1}" -eq 1 ]; then
    systemctl enable --now go-fs.service >/dev/null 2>&1 || :
else
    systemctl try-restart go-fs.service >/dev/null 2>&1 || :
fi
exit 0
