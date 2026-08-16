-- SPDX-License-Identifier: LGPL-2.1-or-later
module RustD.Unit.Transition where

open import Agda.Builtin.Nat      using (Nat; zero; suc)
open import Agda.Builtin.Equality using (_≡_; refl)
open import RustD.Unit.State

data Path : UnitState → UnitState → Set where
  done : ∀ {s}     → Path s s
  via  : ∀ {s i t} → ValidTransition s i → Path i t → Path s t

_++_ : ∀ {s i t} → Path s i → Path i t → Path s t
done       ++ q = q
(via h p)  ++ q = via h (p ++ q)

normalOneShotPath : Path Inactive Inactive
normalOneShotPath =
  via InactiveToActivating
    (via ActivatingToInactive done)

normalSimplePath : Path Inactive Inactive
normalSimplePath =
  via InactiveToActivating
    (via ActivatingToActive
      (via ActiveToDeactivating
        (via DeactivatingToInactive done)))

failedFromActive : Path Active Failed
failedFromActive = via ActiveToFailed done

failedFromActivating : Path Activating Failed
failedFromActivating = via ActivatingToFailed done

failedFromDeactivating : Path Deactivating Failed
failedFromDeactivating = via DeactivatingToFailed done

recoveryPath : Path Failed Inactive
recoveryPath = via FailedToInactive done

maintenanceFromAny : ∀ {s} → Path s Maintenance
maintenanceFromAny = via AnyToMaintenance done

maintenanceReturnsToInactive : Path Maintenance Inactive
maintenanceReturnsToInactive = via MaintenanceToInactive done

noActiveToActivating : ¬ (ValidTransition Active Activating)
noActiveToActivating ()

restartPath : Path Failed Activating
restartPath =
  via FailedToInactive
    (via InactiveToActivating done)
