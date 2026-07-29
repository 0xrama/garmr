#!/system/bin/sh
# post-fs-data: bind-mount patched trustlet before mcDriverDaemon starts
TRUSTLET=/vendor/app/mcRegistry/0706000000000000000000000000004d.tlbin
MODDIR=${0%/*}

if [ ! -f "$MODDIR/0706000000000000000000000000004d.tlbin" ]; then
    echo "KM patch: trustlet binary missing from $MODDIR"
    exit 1
fi

# Bind mount as early as possible
mount --bind "$MODDIR/0706000000000000000000000000004d.tlbin" "$TRUSTLET" 2>/dev/null
if [ $? -eq 0 ]; then
    echo "KM patch: post-fs-data bind mount OK"
else
    echo "KM patch: post-fs-data bind mount FAILED"
fi
