// SPDX-License-Identifier: LGPL-2.1-or-later
//! Target unit activation.
//!
//! A target is a synchronization point: it becomes `Active` once all its
//! `Requires=` and `Wants=` dependencies are `Active` or `Inactive`.
//!
//! Upstream reference: `src/core/target.c` (v261)

use std::collections::HashMap;

use crate::service::UnitRecord;
use crate::unit::loader::LoadedUnit;
use crate::unit::UnitState;

/// Attempt to mark a target unit `Active`.
///
/// The target transitions to `Active` when all mandatory deps (`Requires=`)
/// are `Active`. A failed required dependency fails the target instead of
/// leaving it stuck in `Activating` forever.
///
/// Returns `true` if the target was transitioned to `Active`.
pub fn try_activate_target<S: std::hash::BuildHasher>(
    record: &mut UnitRecord,
    units: &HashMap<String, UnitRecord, S>,
) -> bool {
    let LoadedUnit::Target(_) = &record.loaded else {
        return false;
    };

    let unit_sec = record.loaded.unit_section();
    let requires = unit_sec.requires.clone();

    // Only Requires= gates target activation. Wants= is best-effort: a slow or
    // stuck optional dependency (for example time-wait-sync with an infinite
    // timeout) must not pin the whole boot.
    for dep in &requires {
        match units.get(dep.as_str()).map(|r| r.state) {
            // Successful oneshots without RemainAfterExit= end Inactive; that
            // still satisfies Requires=. Missing units are ignored here — load
            // failures for Requires= are handled when the start transaction is
            // built.
            Some(UnitState::Active | UnitState::Inactive) | None => {}
            Some(UnitState::Failed | UnitState::Maintenance) => {
                record.state = UnitState::Failed;
                return false;
            }
            Some(UnitState::Activating | UnitState::Deactivating) => return false,
        }
    }

    record.state = UnitState::Active;
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unit::loader::{LoadedUnit, ParsedUnit};
    use crate::unit::section_install::InstallSection;
    use crate::unit::section_unit::UnitSection;
    use std::path::PathBuf;

    fn make_target_record(name: &str, requires: &[&str]) -> UnitRecord {
        let unit = UnitSection {
            requires: requires.iter().map(|s| (*s).to_owned()).collect(),
            ..Default::default()
        };
        let loaded = LoadedUnit::Target(Box::new(ParsedUnit {
            name: name.to_owned(),
            source_path: PathBuf::from(format!("/fake/{name}")),
            unit,
            install: InstallSection::default(),
            specific: (),
        }));
        UnitRecord::new(loaded)
    }

    fn make_service_record(name: &str, state: UnitState) -> UnitRecord {
        let loaded = LoadedUnit::Target(Box::new(ParsedUnit {
            name: name.to_owned(),
            source_path: PathBuf::from(format!("/fake/{name}")),
            unit: UnitSection::default(),
            install: InstallSection::default(),
            specific: (),
        }));
        let mut record = UnitRecord::new(loaded);
        record.state = state;
        record
    }

    #[test]
    fn activates_when_deps_active() {
        let mut target = make_target_record("multi-user.target", &["foo.service"]);
        let mut units = HashMap::new();
        units.insert(
            "foo.service".to_string(),
            make_service_record("foo.service", UnitState::Active),
        );
        let result = try_activate_target(&mut target, &units);
        assert!(result);
        assert_eq!(target.state, UnitState::Active);
    }

    #[test]
    fn blocks_while_dep_activating() {
        let mut target = make_target_record("multi-user.target", &["foo.service"]);
        let mut units = HashMap::new();
        units.insert(
            "foo.service".to_string(),
            make_service_record("foo.service", UnitState::Activating),
        );
        let result = try_activate_target(&mut target, &units);
        assert!(!result);
        assert_ne!(target.state, UnitState::Active);
    }

    #[test]
    fn fails_when_required_dep_failed() {
        let mut target = make_target_record("multi-user.target", &["foo.service"]);
        target.state = UnitState::Activating;
        let mut units = HashMap::new();
        units.insert(
            "foo.service".to_string(),
            make_service_record("foo.service", UnitState::Failed),
        );
        let result = try_activate_target(&mut target, &units);
        assert!(!result);
        assert_eq!(target.state, UnitState::Failed);
    }
}
