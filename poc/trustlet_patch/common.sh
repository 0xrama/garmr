# Shared validation for the experimental 20-5-12 module (sourced, not executed).
TRUSTLET=/vendor/app/mcRegistry/0706000000000000000000000000004d.tlbin
PATCHED="$MODDIR/0706000000000000000000000000004d.tlbin"
STOCK_HASH=c4a77a3c955dec5bdbd82c105492f03176b8deebf1297e4b9348ce383f67fde7
PATCHED_HASH=9e60cd423a031eec46afa6736084eea82934de662d42e6e233a74c38df71cec5

log() {
    echo "KM experiment: $*" >> "$MODDIR/module.log"
}

file_hash() {
    sha256sum "$1" | cut -d ' ' -f 1
}

prepare_trustlet() {
    build=$(getprop ro.vendor.build.fingerprint)
    case "$build" in
        *"/V1TDS35H.83-20-5-12/"*) ;;
        *) log "REFUSED: vendor firmware does not match 20-5-12: $build"; return 1 ;;
    esac
    if [ ! -f "$PATCHED" ] || [ ! -f "$TRUSTLET" ]; then
        log "REFUSED: missing source or vendor trustlet"
        return 1
    fi
    if [ "$(file_hash "$PATCHED")" != "$PATCHED_HASH" ]; then
        log "REFUSED: module trustlet hash mismatch"
        return 1
    fi
    current=$(file_hash "$TRUSTLET")
    case "$current" in
        "$STOCK_HASH")
            if ! mount --bind "$PATCHED" "$TRUSTLET" >> "$MODDIR/module.log" 2>&1; then
                log "FAILED: bind mount; services left unchanged"
                return 1
            fi
            ;;
        "$PATCHED_HASH") ;;
        *) log "REFUSED: vendor trustlet hash mismatch: $current"; return 1 ;;
    esac
    if ! grep -Fq " $TRUSTLET " /proc/self/mountinfo ||
            [ "$(file_hash "$TRUSTLET")" != "$PATCHED_HASH" ]; then
        log "FAILED: mounted path/content verification; services left unchanged"
        return 1
    fi
    log "Mounted content verified: $PATCHED_HASH; secure-world execution NOT verified"
}
