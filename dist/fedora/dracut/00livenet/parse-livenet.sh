#!/usr/bin/sh

[ -z "$root" ] && root=$(getarg root=)
command -v get_url_handler >/dev/null 2>&1 || . /lib/url-lib.sh

updates=$(getarg live.updates=)
if [ -n "$updates" ]; then
    [ -n "$netroot" ] || : > /tmp/net.ifaces
    echo "$updates" > /tmp/liveupdates.info
    echo '[ -e /tmp/liveupdates.done ]' > "$hookdir"/initqueue/finished/liveupdates.sh
fi

str_starts "$root" live: && liveurl=$root
str_starts "$liveurl" live: || return
liveurl=${liveurl#live:}

if get_url_handler "$liveurl" >/dev/null; then
    info "livenet: root image at $liveurl"
    netroot="livenet:$liveurl"
    root=livenet
    rootok=1
    wait_for_dev -n /dev/root
else
    info "livenet: no url handler for $liveurl"
fi
