// SPDX-License-Identifier: LGPL-2.1-or-later
//! Unit file parsing — all unit types, specifiers, conditions, and loader.
//!
//! Upstream reference: `src/core/load-fragment.c`, `src/core/unit-file.c`,
//! `src/shared/specifier.c` (v261)

pub mod condition;
pub mod duration;
pub mod enable_state;
pub mod ini;
pub mod loader;
pub mod section_automount;
pub mod section_install;
pub mod section_mount;
pub mod section_path;
pub mod section_service;
pub mod section_slice;
pub mod section_socket;
pub mod section_swap;
pub mod section_timer;
pub mod section_unit;
pub mod specifier;

pub use loader::{LoadedUnit, ParsedUnit, UnitLoader};
pub use section_unit::UnitSection;

/// The lifecycle states of a systemd unit.
///
/// Upstream reference: `src/core/unit.h UnitActiveState` (v261)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitState {
    Inactive,
    Activating,
    Active,
    Deactivating,
    Failed,
    Maintenance,
}

impl std::fmt::Display for UnitState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UnitState::Inactive => write!(f, "inactive"),
            UnitState::Activating => write!(f, "activating"),
            UnitState::Active => write!(f, "active"),
            UnitState::Deactivating => write!(f, "deactivating"),
            UnitState::Failed => write!(f, "failed"),
            UnitState::Maintenance => write!(f, "maintenance"),
        }
    }
}
