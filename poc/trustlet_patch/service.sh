#!/system/bin/sh
MODDIR=${0%/*}
. "$MODDIR/common.sh"
prepare_trustlet || exit 1

# Wait for init services to be visible; do not assume names or startup timing.
waited=0
while [ "$(getprop sys.boot_completed)" != 1 ] && [ "$waited" -lt 60 ]; do
    sleep 2
    waited=$((waited + 1))
done
if [ "$(getprop sys.boot_completed)" != 1 ]; then
    log "FAILED: boot-completed timeout; no restart requests sent"
    exit 1
fi

services=$(getprop | sed -n 's/^\[init.svc.\([^]]*\)\]: \[running\]$/\1/p')
found=0
# Request the TEE daemon first, then the KeyMint/Keymaster HAL.
for pattern in 'mobicore|mcdriver' 'keymint|keymaster'; do
    for name in $(printf '%s\n' "$services" | grep -Ei "$pattern"); do
        found=1
        if setprop ctl.restart "$name" >> "$MODDIR/module.log" 2>&1; then
            log "Restart REQUEST sent to discovered running service: $name"
        else
            log "FAILED: restart request for $name"
            exit 1
        fi
    done
done
if [ "$found" -eq 0 ]; then
    log "FAILED: no matching running init services; inspect device init configuration"
    exit 1
fi
log "Requests sent, NOT proof of session reload or attestation change; collect loader logs and a fresh certificate"
