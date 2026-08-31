#!/usr/bin/sh

command -v getarg >/dev/null 2>&1 || . /lib/dracut-lib.sh
command -v fetch_url >/dev/null 2>&1 || . /lib/url-lib.sh

PATH=/usr/sbin:/usr/bin:/sbin:/bin
RETRIES=${RETRIES:-100}
SLEEP=${SLEEP:-5}

[ -e /tmp/livenet.downloaded ] && exit 0

netroot=$2
liveurl=${netroot#livenet:}
info "fetching $liveurl"

if getargbool 0 rd.writable.fsimg; then
    if str_starts "$liveurl" tftp; then
        imgheader=$(curl -vsIL "$liveurl" 2>&1)
        ret=$?
        imgheaderlen=$(echo "$imgheader" | sed -n \
            's/\* got option=(tsize) value=(*\([[:digit:]]*\).*/\1/p')
        [ -n "$imgheaderlen" ] || warn "failed to get TFTP image size: error $ret"
    else
        imgheader=$(curl -sIL "$liveurl")
        ret=$?
        if [ "$ret" -ne 0 ]; then
            warn "failed to get live image header: error $ret"
        else
            imgheaderlen=$(echo "$imgheader" | sed -n \
                's/[cC]ontent-[lL]ength: *\([[:digit:]]*\).*/\1/p')
            [ -n "$imgheaderlen" ] || warn "live image has no Content-Length"
        fi
    fi
    if [ -n "$imgheaderlen" ]; then
        imgsize=$((imgheaderlen / (1024 * 1024)))
        check_live_ram "$imgsize"
    fi
fi

imgfile=
i=1
while [ "$i" -le "$RETRIES" ]; do
    imgfile=$(fetch_url "$liveurl")
    ret=$?
    if [ "$ret" -ne 0 ]; then
        warn "failed to download live image: error $ret"
        imgfile=
    fi
    if [ -n "$imgfile" ] && [ -s "$imgfile" ]; then
        break
    fi
    if [ "$i" -ge "$RETRIES" ]; then
        warn "failed to download live image after $i attempts"
        exit 1
    fi
    sleep "$SLEEP"
    i=$((i + 1))
done > /tmp/livenet.downloaded

if [ "${imgfile##*.}" = iso ]; then
    root=$(losetup -f)
    losetup "$root" "$imgfile"
else
    root=$imgfile
fi

exec /sbin/dmsquash-live-root "$root"
