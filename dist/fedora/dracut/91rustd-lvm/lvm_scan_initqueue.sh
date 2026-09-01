#!/usr/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later

# Fedora's 64-lvm.rules normally queues /sbin/lvm_scan from a udev RUN
# action. RustD's early rule engine also runs a settled initqueue hook so
# LVM-backed roots do not depend on that one rule action being delivered.
/sbin/lvm_scan
