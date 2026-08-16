// SPDX-License-Identifier: LGPL-2.1-or-later
//! Event source descriptors and token allocation.
//!
//! Each registered source (IO fd, signal, timer, inotify, child, defer) gets
//! a unique `SourceId`.  The lower 56 bits of the u64 epoll token carry the
//! `SourceId`; the upper 8 bits carry the `SourceKind` discriminant so the
//! dispatcher can route without a hash-table lookup on the hot path.
//!
//! Upstream reference: src/libsystemd/sd-event/sd-event.c `source_new()` (v261)

use std::num::NonZeroU32;

/// Unique identifier for a registered event source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SourceId(NonZeroU32);

impl SourceId {
    pub(crate) fn new(n: u32) -> Option<Self> {
        NonZeroU32::new(n).map(Self)
    }

    #[must_use]
    pub fn get(self) -> u32 {
        self.0.get()
    }
}

/// The kind of event source, encoded in the upper 8 bits of an epoll token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SourceKind {
    Io = 1,
    Signal = 2,
    Timer = 3,
    Inotify = 4,
    Child = 5,
    Defer = 6,
}

impl SourceKind {
    pub(crate) fn from_token_bits(bits: u8) -> Option<Self> {
        match bits {
            1 => Some(Self::Io),
            2 => Some(Self::Signal),
            3 => Some(Self::Timer),
            4 => Some(Self::Inotify),
            5 => Some(Self::Child),
            6 => Some(Self::Defer),
            _ => None,
        }
    }
}

/// A 64-bit token packed into epoll `data.u64`.
///
/// Layout: `[kind: u8][_reserved: u24][id: u32]`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceToken(pub(crate) u64);

impl SourceToken {
    #[must_use]
    pub fn encode(kind: SourceKind, id: SourceId) -> Self {
        let k = (kind as u64) << 56;
        let i = u64::from(id.get());
        Self(k | i)
    }

    #[must_use]
    pub fn kind(self) -> Option<SourceKind> {
        SourceKind::from_token_bits((self.0 >> 56) as u8)
    }

    #[must_use]
    pub fn id(self) -> u32 {
        (self.0 & 0x0000_0000_FFFF_FFFF) as u32
    }
}

/// Allocator for `SourceId` values — simple monotonic counter.
#[derive(Debug, Default)]
pub(crate) struct SourceIdAlloc(u32);

impl SourceIdAlloc {
    pub(crate) fn next(&mut self) -> SourceId {
        self.0 = self.0.wrapping_add(1);
        SourceId::new(self.0).expect("SourceId counter exhausted")
    }
}
