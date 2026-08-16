/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdint.h>

/*
 * capability.h — Linux capability helpers for service sandboxing.
 *
 * Implements CapabilityBoundingSet= and AmbientCapabilities= from
 * systemd.exec(5), mirroring upstream src/shared/capability-util.c (v261).
 *
 * Return values: 0 on success, -errno on failure.
 */

/* Map a capability name, with or without a CAP_ prefix, to its kernel number. */
int rustd_capability_name_to_num(const char *name);

/*
 * Drop every capability not present in keep_mask from the bounding set.
 * Must run before changing UID/GID while CAP_SETPCAP is still available.
 * keep_mask=0 drops all capabilities; UINT64_MAX keeps all.
 */
int rustd_capability_bounding_set_drop(uint64_t keep_mask);

/*
 * Add ambient_mask to the current permitted, inheritable, and effective sets
 * as required by PR_CAP_AMBIENT_RAISE. Must run after the identity transition
 * and before clearing PR_SET_KEEPCAPS.
 */
int rustd_capability_ambient_prepare(uint64_t ambient_mask);

/* Clear all ambient capabilities, then raise exactly ambient_mask. */
int rustd_capability_ambient_apply(uint64_t ambient_mask);
