#!/bin/sh
# rpm passes 1 on an install and 2 or more on an upgrade. The service is
# enabled and started on the install, and restarted into the new binary on an
# upgrade, unless it had been stopped. Without systemd running, in a container
# build for instance, there is nothing to start.
#
# Either way the last lines rpm prints say where the admin interface is, and
# after a first install which account logs in to it.
note() {
    echo "go-fs: the admin interface is available at http://localhost:8080/?go-fs=admin"
    if [ "${1:-1}" -eq 1 ]; then
        echo "go-fs: log in as admin with the password admin, then change that password"
    fi
}
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || :
    if [ "${1:-1}" -eq 1 ]; then
        systemctl enable --now go-fs.service >/dev/null 2>&1 || :
    else
        systemctl try-restart go-fs.service >/dev/null 2>&1 || :
    fi
fi
note "${1:-1}"
exit 0
