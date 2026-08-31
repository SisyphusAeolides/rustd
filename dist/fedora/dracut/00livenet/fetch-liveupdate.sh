#!/usr/bin/sh

[ -e /tmp/liveupdates.info ] || return 0

command -v getarg >/dev/null 2>&1 || . /lib/dracut-lib.sh
command -v fetch_url >/dev/null 2>&1 || . /lib/url-lib.sh
command -v unpack_img >/dev/null 2>&1 || . /lib/img-lib.sh

read -r url < /tmp/liveupdates.info
info "fetching live updates from $url"

if ! fetch_url "$url" /tmp/updates.img; then
    warn "failed to fetch update image"
    warn "url: $url"
    return 1
fi

if ! unpack_img /tmp/updates.img /updates.tmp.$$; then
    warn "failed to unpack update image"
    warn "url: $url"
    return 1
fi

copytree /updates.tmp.$$ /updates
mv /tmp/liveupdates.info /tmp/liveupdates.done
