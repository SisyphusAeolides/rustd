#!/usr/bin/sh

isofile=$(getarg iso-scan/filename)
[ -n "$isofile" ] && /sbin/initqueue --settled --unique /sbin/iso-scan "$isofile"
