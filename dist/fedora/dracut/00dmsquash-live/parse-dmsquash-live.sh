#!/usr/bin/sh
# Standard Fedora/RHEL live images use root=live:<backing-device>.

[ -z "$root" ] && root=$(getarg root=)

if getargbool 0 rd.live.image -d -y liveimg; then
    liveroot="live:$root"
fi

if [ "${root%%:*}" = live ]; then
    liveroot=$root
fi

[ "${liveroot%%:*}" = live ] || return 1

modprobe -q loop

case "$liveroot" in
    live:LABEL=* | LABEL=* | live:UUID=* | UUID=* | \
    live:PARTUUID=* | PARTUUID=* | live:PARTLABEL=* | PARTLABEL=*)
        root="live:$(label_uuid_to_dev "${root#live:}")"
        rootok=1
        ;;
    live:CDLABEL=* | CDLABEL=*)
        root="${root#live:}"
        root="$(echo "$root" | sed 's,/,\\x2f,g;s, ,\\x20,g')"
        root="live:/dev/disk/by-label/${root#CDLABEL=}"
        rootok=1
        ;;
    live:/*.[Ii][Ss][Oo] | /*.[Ii][Ss][Oo])
        root="${root#live:}"
        root="liveiso:$root"
        rootok=1
        ;;
    live:/dev/*)
        rootok=1
        ;;
    live:/*.[Ii][Mm][Gg] | /*.[Ii][Mm][Gg])
        [ -f "${root#live:}" ] && rootok=1
        ;;
esac

[ "$rootok" = 1 ] || return 1

info "root was $liveroot, is now $root"
[ -n "$root" ] || root=live
wait_for_dev -n /dev/root
