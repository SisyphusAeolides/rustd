#!/usr/bin/bash

check() {
    require_binaries tar gzip dd echo tr || return 1
    return 255
}

depends() {
    return 0
}

install() {
    inst_multiple tar gzip dd echo tr rmdir
    inst_multiple -o cpio xz bzip2 zstd
    inst_simple "$moddir/img-lib.sh" /lib/img-lib.sh
}
