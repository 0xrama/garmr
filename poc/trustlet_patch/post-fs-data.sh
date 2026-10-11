#!/system/bin/sh
MODDIR=${0%/*}
. "$MODDIR/common.sh"
prepare_trustlet || exit 1
