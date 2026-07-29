#!/system/bin/sh
# service.sh: runs at boot. Re-mount if needed, then restart daemon to pick up patched trustlet.
TRUSTLET=/vendor/app/mcRegistry/0706000000000000000000000000004d.tlbin
MODDIR=${0%/*}

# Ensure bind mount is active (in case post-fs-data failed)
if ! mountpoint -q "$TRUSTLET" 2>/dev/null; then
    mount --bind "$MODDIR/0706000000000000000000000000004d.tlbin" "$TRUSTLET" 2>/dev/null
fi

# Wait for mobicore daemon to start, then restart it so it reads the patched trustlet
(
    sleep 8
    # Restart the mobicore daemon - it will re-read the trustlet from the bind-mounted file
    stop mobicore 2>/dev/null
    stop vendor.mobicore 2>/dev/null
    sleep 2
    start mobicore 2>/dev/null
    start vendor.mobicore 2>/dev/null

    # Also restart the keymint HAL so it reconnects to the fresh TEE
    sleep 3
    setprop ctl.restart vendor.keymint-trustonic 2>/dev/null
    setprop ctl.restart keymint-1-1 2>/dev/null
    setprop ctl.restart vendor.keymint-1-1 2>/dev/null
) &
