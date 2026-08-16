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
/// are `Active` and no dep is still `Activating`.
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
    let wants = unit_sec.wants.clone();

    // All Requires= must be Active or Inactive; none Activating/Deactivating.
    for dep in &requires {
        match units.get(dep.as_str()).map(|r| r.state) {
            Some(UnitState::Active | UnitState::Inactive) | None => {}
            _ => return false,
        }
    }

    // Wants= that are still transitioning block the target.
    for dep in &wants {
        if let Some(UnitState::Activating | UnitState::Deactivating) =
            units.get(dep.as_str()).map(|r| r.state)
        {
            return false;
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
}
