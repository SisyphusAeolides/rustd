#!/usr/bin/bash

det_archive() {
    local bz='BZh' xz gz zs headerblock
    xz="$(printf '\3757zXZ')"
    gz="$(printf '\037\213')"
    zs="$(printf '\050\265\057\375')"
    if [[ -n ${1:-} ]]; then
        headerblock="$(dd if="$1" bs=262 count=1 2>/dev/null | tr -d '\0')"
    else
        headerblock="$(dd bs=262 count=1 2>/dev/null | tr -d '\0')"
    fi
    case "$headerblock" in
        $xz*) echo xz ;;
        $gz*) echo gzip ;;
        $bz*) echo bzip2 ;;
        $zs*) echo zstd ;;
        07070*) echo cpio ;;
        *ustar) echo tar ;;
    esac
}

det_fs_img() {
    local dev rv
    dev=$(losetup --find --show "$1") || return 1
    det_fs "$dev"
    rv=$?
    losetup -d "$dev"
    return "$rv"
}

unpack_archive() {
    local img=${1:-} outdir=${2:-} compression archive_type
    [ -r "$img" ] && [ -n "$outdir" ] || return 1
    compression=$(det_archive "$img")
    case "$compression" in
        xz|gzip|bzip2|zstd) ;;
        cpio|tar) ;;
        *) return 1 ;;
    esac
    decompress() {
        case "$compression" in
            xz) xz -dc -- "$img" ;;
            gzip) gzip -dc -- "$img" ;;
            bzip2) bzip2 -dc -- "$img" ;;
            zstd) zstd -dc -- "$img" ;;
            cpio|tar) cat -- "$img" ;;
        esac
    }
    archive_type=$(decompress | det_archive)
    case "$archive_type" in
        cpio) ;;
        tar) ;;
        *) return 2 ;;
    esac
    mkdir -p "$outdir"
    (
        cd "$outdir" || exit
        case "$archive_type" in
            cpio) decompress | cpio -iumd 2>/dev/null ;;
            tar) decompress | tar -xf - 2>/dev/null ;;
        esac
    )
}

unpack_fs() {
    local img=${1:-} outdir=${2:-} mnt rv
    [ -r "$img" ] && [ -n "$outdir" ] || return 1
    mnt=$(mkuniqdir /tmp unpack_fs.) || return 1
    if ! mount -o loop "$img" "$mnt"; then
        rmdir "$mnt"
        return 1
    fi
    mkdir -p "$outdir"
    outdir=$(cd "$outdir" && pwd) || {
        umount "$mnt"
        rmdir "$mnt"
        return 1
    }
    copytree "$mnt" "$outdir"
    rv=$?
    umount "$mnt"
    rmdir "$mnt"
    return "$rv"
}

unpack_img() {
    local img=${1:-} outdir=${2:-}
    [ -r "$img" ] && [ -n "$outdir" ] || return 1
    if [ -n "$(det_archive "$img")" ]; then
        unpack_archive "$img" "$outdir"
    else
        unpack_fs "$img" "$outdir"
    fi
}

check_live_ram() {
    local minmem imgsize memsize runsize runavail
    minmem=$(getarg rd.minmem)
    imgsize=$1
    memsize=$(($(check_meminfo MemTotal:) >> 10))
    set -- $(findmnt -bnro SIZE,AVAIL /run)
    runsize=$(($1 >> 20))
    runavail=$(($2 >> 20))

    [ -n "$imgsize" ] || return 0
    if [ $((memsize - imgsize)) -lt "${minmem:=1024}" ]; then
        emergency_shell
    elif [ $((runavail - imgsize)) -lt "$minmem" ]; then
        mount -o remount,size=$((runsize - runavail + imgsize + minmem))M /run
    fi
}
