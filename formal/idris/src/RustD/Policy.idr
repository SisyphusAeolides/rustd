-- SPDX-License-Identifier: LGPL-2.1-or-later
module RustD.Policy

import Data.List
import Data.Vect
import Data.String

%default total

-- ─── Unit activation states ───────────────────────────────────────────────
--
-- Models the native RustD unit lifecycle.

public export
data UnitState
  = Inactive
  | Activating
  | Active
  | Deactivating
  | Failed
  | Maintenance

public export
Eq UnitState where
  Inactive     == Inactive     = True
  Activating   == Activating   = True
  Active       == Active       = True
  Deactivating == Deactivating = True
  Failed       == Failed       = True
  Maintenance  == Maintenance  = True
  _            == _            = False

public export
Show UnitState where
  show Inactive     = "inactive"
  show Activating   = "activating"
  show Active       = "active"
  show Deactivating = "deactivating"
  show Failed       = "failed"
  show Maintenance  = "maintenance"

public export
data UnitType
  = ServiceUnit
  | SocketUnit
  | TimerUnit
  | PathUnit
  | MountUnit
  | SwapUnit
  | TargetUnit
  | SliceUnit
  | ScopeUnit

public export
data DepKind = Requires | Wants | After | Before | Conflicts

public export
UnitName : Type
UnitName = String

public export
record ActivationPolicy where
  constructor MkActivationPolicy
  allowDegradedBoot : Bool
  emergencyAction   : String

-- Legal transitions for the RustD unit state machine.
public export
data ValidTransition : UnitState -> UnitState -> Type where
  InactiveToActivating   : ValidTransition Inactive     Activating
  ActivatingToActive     : ValidTransition Activating   Active
  ActivatingToInactive   : ValidTransition Activating   Inactive
  ActivatingToFailed     : ValidTransition Activating   Failed
  ActiveToDeactivating   : ValidTransition Active       Deactivating
  ActiveToFailed         : ValidTransition Active       Failed
  DeactivatingToInactive : ValidTransition Deactivating Inactive
  DeactivatingToFailed   : ValidTransition Deactivating Failed
  FailedToInactive       : ValidTransition Failed       Inactive
  AnyToMaintenance       : ValidTransition s            Maintenance
  MaintenanceToInactive  : ValidTransition Maintenance  Inactive

public export
step : UnitState -> UnitState -> Maybe UnitState
step Inactive     Activating   = Just Activating
step Activating   Active       = Just Active
step Activating   Inactive     = Just Inactive
step Activating   Failed       = Just Failed
step Active       Deactivating = Just Deactivating
step Active       Failed       = Just Failed
step Deactivating Inactive     = Just Inactive
step Deactivating Failed       = Just Failed
step Failed       Inactive     = Just Inactive
step _            Maintenance  = Just Maintenance
step Maintenance  Inactive     = Just Inactive
step _            _            = Nothing

public export
data UnitConflict : UnitName -> UnitName -> Type where
  MkUnitConflict : (a : UnitName) -> (b : UnitName) -> UnitConflict a b

public export
unitConflictSym : UnitConflict a b -> UnitConflict b a
unitConflictSym (MkUnitConflict a b) = MkUnitConflict b a

public export
data ActivationDecision = Accept | RejectConflict | RejectMissing

public export
validateActivation : UnitType -> Bool -> ActivationDecision
validateActivation _ False = RejectMissing
validateActivation _ True  = Accept

public export
record RestartBudget where
  constructor MkRestartBudget
  maxAttempts  : Nat
  usedAttempts : Nat
  remaining    : Nat
  remainingEq  : remaining = minus maxAttempts usedAttempts

public export
consumeRestart : (budget : Nat) -> (used : Nat) -> RestartBudget
consumeRestart budget used =
  MkRestartBudget budget used (minus budget used) Refl

public export
isExhausted : RestartBudget -> Bool
isExhausted b = b.remaining == 0

public export
data ServiceType
  = Simple
  | Exec
  | Oneshot
  | Forking
  | Notify
  | NotifyReload
  | Dbus
  | Idle

public export
initialStateForType : ServiceType -> UnitState
initialStateForType Simple       = Active
initialStateForType Exec         = Active
initialStateForType Oneshot      = Activating
initialStateForType Forking      = Activating
initialStateForType Notify       = Activating
initialStateForType NotifyReload = Activating
initialStateForType Dbus         = Activating
initialStateForType Idle         = Activating

public export
initialStateIsStarting : (t : ServiceType) ->
  Either (initialStateForType t = Active) (initialStateForType t = Activating)
initialStateIsStarting Simple       = Left  Refl
initialStateIsStarting Exec         = Left  Refl
initialStateIsStarting Oneshot      = Right Refl
initialStateIsStarting Forking      = Right Refl
initialStateIsStarting Notify       = Right Refl
initialStateIsStarting NotifyReload = Right Refl
initialStateIsStarting Dbus         = Right Refl
initialStateIsStarting Idle         = Right Refl
