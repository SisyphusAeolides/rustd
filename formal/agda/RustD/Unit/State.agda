-- SPDX-License-Identifier: LGPL-2.1-or-later
module RustD.Unit.State where

open import Agda.Builtin.Nat      using (Nat; zero; suc)
open import Agda.Builtin.Equality using (_≡_; refl)
open import Agda.Builtin.List     using (List; []; _∷_)
open import Agda.Builtin.Bool     using (Bool; true; false)

infix 4 _≤_
data _≤_ : Nat → Nat → Set where
  z≤n : ∀ {n}     →         zero  ≤ n
  s≤s : ∀ {m n}   → m ≤ n → suc m ≤ suc n

≤-refl : ∀ {n} → n ≤ n
≤-refl {zero}  = z≤n
≤-refl {suc n} = s≤s ≤-refl

≤-trans : ∀ {a b c} → a ≤ b → b ≤ c → a ≤ c
≤-trans z≤n       _         = z≤n
≤-trans (s≤s l)   (s≤s r)   = s≤s (≤-trans l r)

≤-suc : ∀ {n} → n ≤ suc n
≤-suc {zero}  = z≤n
≤-suc {suc n} = s≤s ≤-suc

data ⊥ : Set where
¬_ : Set → Set
¬ A = A → ⊥

suc-not≤self : ∀ {n} → ¬ (suc n ≤ n)
suc-not≤self {zero}  ()
suc-not≤self {suc n} (s≤s p) = suc-not≤self p

-- Native RustD unit lifecycle states.
data UnitState : Set where
  Inactive     : UnitState
  Activating   : UnitState
  Active       : UnitState
  Deactivating : UnitState
  Failed       : UnitState
  Maintenance  : UnitState

data ValidTransition : UnitState → UnitState → Set where
  InactiveToActivating   : ValidTransition Inactive     Activating
  ActivatingToActive     : ValidTransition Activating   Active
  ActivatingToInactive   : ValidTransition Activating   Inactive
  ActivatingToFailed     : ValidTransition Activating   Failed
  ActiveToDeactivating   : ValidTransition Active       Deactivating
  ActiveToFailed         : ValidTransition Active       Failed
  DeactivatingToInactive : ValidTransition Deactivating Inactive
  DeactivatingToFailed   : ValidTransition Deactivating Failed
  FailedToInactive       : ValidTransition Failed       Inactive
  AnyToMaintenance       : ∀ {s} → ValidTransition s   Maintenance
  MaintenanceToInactive  : ValidTransition Maintenance  Inactive

data Reachable : UnitState → Set where
  base : Reachable Inactive
  step : ∀ {s t} → Reachable s → ValidTransition s t → Reachable t

reachActivating : Reachable Activating
reachActivating = step base InactiveToActivating

reachActive : Reachable Active
reachActive = step reachActivating ActivatingToActive

reachDeactivating : Reachable Deactivating
reachDeactivating = step reachActive ActiveToDeactivating

reachFailed : Reachable Failed
reachFailed = step reachActivating ActivatingToFailed

reachMaintenance : Reachable Maintenance
reachMaintenance = step base AnyToMaintenance

data _≢_ (s t : UnitState) : Set where
  neq : ¬ (s ≡ t) → s ≢ t

inactiveNeActivating : Inactive ≢ Activating
inactiveNeActivating = neq (λ ())

record DepChainStep (from to : Nat) : Set where
  constructor step
  field
    decreases : suc to ≤ from

noSelfEdge : ∀ {d} → ¬ (DepChainStep d d)
noSelfEdge (step p) = suc-not≤self p

data Terminates : Nat → Set where
  tzero : Terminates zero
  tstep : ∀ {n} → Terminates n → Terminates (suc n)

chainBounded : ∀ (n : Nat) → Terminates n
chainBounded zero    = tzero
chainBounded (suc n) = tstep (chainBounded n)

record RestartBudget : Set where
  constructor budget
  field
    maxAttempts  : Nat
    usedAttempts : Nat
    remaining    : Nat
    neverNegative : remaining ≤ maxAttempts

zeroBudget : (max used : Nat) → RestartBudget
zeroBudget max used = budget max used zero z≤n

consumeOne : RestartBudget → RestartBudget
consumeOne (budget (suc m) u (suc r) (s≤s p)) =
  budget (suc m) (suc u) r (≤-trans p ≤-suc)
consumeOne b = b

record JournalSeq : Set where
  constructor seq#
  field
    value : Nat

nextSeq : JournalSeq → JournalSeq
nextSeq (seq# n) = seq# (suc n)

seqIncreases : ∀ (s : JournalSeq) →
  JournalSeq.value s ≤ JournalSeq.value (nextSeq s)
seqIncreases (seq# n) = ≤-suc

seqStrictlyIncreases : ∀ (s : JournalSeq) →
  JournalSeq.value s ≤ JournalSeq.value (nextSeq s)
seqStrictlyIncreases = seqIncreases

data CanTrigger : UnitState → Set where
  triggerInactive : CanTrigger Inactive
  triggerFailed   : CanTrigger Failed

cannotTriggerActive : ¬ (CanTrigger Active)
cannotTriggerActive ()
