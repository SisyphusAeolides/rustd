// SPDX-License-Identifier: LGPL-2.1-or-later
//! Dependency resolver — topological sort for unit activation order.
//!
//! Given a target unit name and the loaded unit registry, computes the full
//! transitive closure of units that must be started and returns them in
//! activation order (dependencies before dependents).
//!
//! `Wants=` deps that fail to load are silently skipped (upstream semantics).
//! `Requires=` deps that fail to load propagate as errors.
//!
//! Upstream reference: `src/core/transaction.c
//!   transaction_add_job_and_dependencies()` (v261)

use std::collections::{HashMap, HashSet};

use anyhow::anyhow;

use crate::unit::loader::LoadedUnit;
use crate::unit::UnitState;

/// Runtime record held in the unit registry (used for ordering queries).
pub struct DepUnit<'a> {
    pub loaded: &'a LoadedUnit,
    pub state: UnitState,
}

/// Resolve the ordered start sequence for `target`.
///
/// Returns units in topological order: all dependencies before the unit that
/// depends on them.  The target itself is the last element.
///
/// `loader` is a closure that attempts to load a unit by name; it returns
/// `None` on failure (used to simulate skip-on-missing for `Wants=`).
///
/// Distribution unit trees contain ordering cycles, so a cycle drops the edge
/// that closes it and the boot continues, as upstream does.
///
/// # Errors
/// Returns an error if a `Requires=` dep cannot be loaded.
pub fn resolve_start_order<F, S: std::hash::BuildHasher>(
    target: &str,
    known: &HashMap<String, DepUnit<'_>, S>,
    load: F,
) -> anyhow::Result<Vec<String>>
where
    F: FnMut(&str) -> Option<LoadedUnit>,
{
    let mut resolver = Resolver {
        known,
        extra: HashMap::new(),
        load,
        visited: HashSet::new(),
        on_stack: HashSet::new(),
        broken: HashSet::new(),
        order: Vec::new(),
    };

    resolver.resolve(target, None)?;

    Ok(resolver.order)
}

struct Resolver<'a, F, S: std::hash::BuildHasher> {
    known: &'a HashMap<String, DepUnit<'a>, S>,
    /// Units loaded during resolution that the registry does not hold yet.
    extra: HashMap<String, LoadedUnit>,
    load: F,
    visited: HashSet<String>,
    on_stack: HashSet<String>,
    broken: HashSet<(String, String)>,
    order: Vec<String>,
}

impl<F, S: std::hash::BuildHasher> Resolver<'_, F, S>
where
    F: FnMut(&str) -> Option<LoadedUnit>,
{
    fn resolve(&mut self, name: &str, from: Option<&str>) -> anyhow::Result<()> {
        if self.visited.contains(name) {
            return Ok(());
        }
        if self.on_stack.contains(name) {
            self.report_cycle(name, from);
            return Ok(());
        }

        let (wants, requires, after) = deps_for(name, self.known, &self.extra);

        self.on_stack.insert(name.to_owned());

        // Requires= — missing dep is an error.
        for dep in &requires {
            self.ensure_loaded(dep, true)?;
            self.resolve(dep, Some(name))?;
        }

        // Wants= — missing dep is silently skipped.
        for dep in &wants {
            let _ = self.ensure_loaded(dep, false);
            // Only recurse if the unit is present: load may have skipped it.
            if self.is_loaded(dep) {
                self.resolve(dep, Some(name))?;
            }
        }

        // After= — ordering only; the dep may already be pulled in above.
        for dep in &after {
            let _ = self.ensure_loaded(dep, false);
            if self.is_loaded(dep) {
                self.resolve(dep, Some(name))?;
            }
        }

        self.on_stack.remove(name);
        self.visited.insert(name.to_owned());
        self.order.push(name.to_owned());

        Ok(())
    }

    /// Drop the edge that closes a cycle and warn once about it.
    fn report_cycle(&mut self, name: &str, from: Option<&str>) {
        let from = from.unwrap_or(name);
        if self.broken.insert((from.to_owned(), name.to_owned())) {
            eprintln!(
                "rustd: found dependency cycle on '{name}', breaking edge '{from}' -> '{name}'"
            );
        }
    }

    fn is_loaded(&self, name: &str) -> bool {
        self.known.contains_key(name) || self.extra.contains_key(name)
    }

    /// Ensure `name` is present in the registry or the temporary store.
    /// `required` controls whether a load failure is an error or a skip.
    fn ensure_loaded(&mut self, name: &str, required: bool) -> anyhow::Result<()> {
        if self.is_loaded(name) {
            return Ok(());
        }
        match (self.load)(name) {
            Some(unit) => {
                self.extra.insert(name.to_owned(), unit);
                Ok(())
            }
            None if required => Err(anyhow!("required dependency '{name}' could not be loaded")),
            None => Ok(()),
        }
    }
}

/// Collect `(wants, requires, after)` for a named unit from known + extra.
fn deps_for<S: std::hash::BuildHasher>(
    name: &str,
    known: &HashMap<String, DepUnit<'_>, S>,
    extra: &HashMap<String, LoadedUnit>,
) -> (Vec<String>, Vec<String>, Vec<String>) {
    let unit_sec = known
        .get(name)
        .map(|r| r.loaded.unit_section())
        .or_else(|| extra.get(name).map(LoadedUnit::unit_section));

    match unit_sec {
        Some(u) => (u.wants.clone(), u.requires.clone(), u.after.clone()),
        None => (Vec::new(), Vec::new(), Vec::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unit::loader::{LoadedUnit, ParsedUnit};
    use crate::unit::section_install::InstallSection;
    use crate::unit::section_unit::UnitSection;
    use std::path::PathBuf;

    fn make_target(name: &str, wants: &[&str], after: &[&str]) -> LoadedUnit {
        let unit = UnitSection {
            wants: wants.iter().map(|s| (*s).to_owned()).collect(),
            after: after.iter().map(|s| (*s).to_owned()).collect(),
            ..Default::default()
        };
        LoadedUnit::Target(Box::new(ParsedUnit {
            name: name.to_owned(),
            source_path: PathBuf::from(format!("/fake/{name}")),
            unit,
            install: InstallSection::default(),
            specific: (),
        }))
    }

    fn dep_unit(u: &LoadedUnit) -> DepUnit<'_> {
        DepUnit {
            loaded: u,
            state: UnitState::Inactive,
        }
    }

    #[test]
    fn single_unit_no_deps() {
        let a = make_target("a.target", &[], &[]);
        let known: HashMap<String, DepUnit<'_>> = [("a.target".to_string(), dep_unit(&a))]
            .into_iter()
            .collect();
        let order = resolve_start_order("a.target", &known, |_| None).unwrap();
        assert_eq!(order, vec!["a.target"]);
    }

    #[test]
    fn linear_chain() {
        let a = make_target("a.target", &[], &[]);
        let b = make_target("b.target", &["a.target"], &["a.target"]);
        let known: HashMap<String, DepUnit<'_>> = [
            ("a.target".to_string(), dep_unit(&a)),
            ("b.target".to_string(), dep_unit(&b)),
        ]
        .into_iter()
        .collect();
        let order = resolve_start_order("b.target", &known, |_| None).unwrap();
        assert_eq!(order, vec!["a.target", "b.target"]);
    }

    #[test]
    fn diamond_resolves() {
        // b → a, c → a, d → b + c
        let a = make_target("a.target", &[], &[]);
        let b = make_target("b.target", &["a.target"], &[]);
        let c = make_target("c.target", &["a.target"], &[]);
        let d = make_target("d.target", &["b.target", "c.target"], &[]);
        let known: HashMap<String, DepUnit<'_>> = [
            ("a.target".to_string(), dep_unit(&a)),
            ("b.target".to_string(), dep_unit(&b)),
            ("c.target".to_string(), dep_unit(&c)),
            ("d.target".to_string(), dep_unit(&d)),
        ]
        .into_iter()
        .collect();
        let order = resolve_start_order("d.target", &known, |_| None).unwrap();
        // a must come before b and c; b and c before d.
        let ai = order.iter().position(|x| x == "a.target").unwrap();
        let bi = order.iter().position(|x| x == "b.target").unwrap();
        let ci = order.iter().position(|x| x == "c.target").unwrap();
        let di = order.iter().position(|x| x == "d.target").unwrap();
        assert!(ai < bi);
        assert!(ai < ci);
        assert!(bi < di);
        assert!(ci < di);
    }

    #[test]
    fn cycle_is_broken_instead_of_failing() {
        let a = make_target("a.target", &["b.target"], &[]);
        let b = make_target("b.target", &["a.target"], &[]);
        let known: HashMap<String, DepUnit<'_>> = [
            ("a.target".to_string(), dep_unit(&a)),
            ("b.target".to_string(), dep_unit(&b)),
        ]
        .into_iter()
        .collect();
        let order = resolve_start_order("a.target", &known, |_| None).unwrap();
        assert_eq!(order, vec!["b.target", "a.target"]);
    }

    #[test]
    fn self_referential_unit_resolves_once() {
        let a = make_target("a.target", &[], &["a.target"]);
        let known: HashMap<String, DepUnit<'_>> = [("a.target".to_string(), dep_unit(&a))]
            .into_iter()
            .collect();
        let order = resolve_start_order("a.target", &known, |_| None).unwrap();
        assert_eq!(order, vec!["a.target"]);
    }

    #[test]
    fn missing_wants_skipped() {
        let a = make_target("a.target", &["missing.target"], &[]);
        let known: HashMap<String, DepUnit<'_>> = [("a.target".to_string(), dep_unit(&a))]
            .into_iter()
            .collect();
        // Should not error — missing Wants= is silently skipped.
        let order = resolve_start_order("a.target", &known, |_| None).unwrap();
        assert_eq!(order, vec!["a.target"]);
    }

    #[test]
    fn missing_requires_errors() {
        let unit = UnitSection {
            requires: vec!["missing.target".to_owned()],
            ..Default::default()
        };
        let a = LoadedUnit::Target(Box::new(ParsedUnit {
            name: "a.target".to_owned(),
            source_path: PathBuf::from("/fake/a.target"),
            unit,
            install: InstallSection::default(),
            specific: (),
        }));
        let known: HashMap<String, DepUnit<'_>> = [("a.target".to_string(), dep_unit(&a))]
            .into_iter()
            .collect();
        assert!(resolve_start_order("a.target", &known, |_| None).is_err());
    }
}
