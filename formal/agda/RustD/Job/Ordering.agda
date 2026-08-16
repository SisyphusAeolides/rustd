-- SPDX-License-Identifier: LGPL-2.1-or-later
module RustD.Job.Ordering where

open import Agda.Builtin.Nat      using (Nat; zero; suc)
open import Agda.Builtin.Equality using (_≡_; refl)
open import Agda.Builtin.Bool     using (Bool; true; false)
open import Agda.Builtin.List     using (List; []; _∷_)
open import Agda.Builtin.String   using (String)

infix 4 _≤_
data _≤_ : Nat → Nat → Set where
  z≤n : ∀ {n}   →         zero  ≤ n
  s≤s : ∀ {m n} → m ≤ n → suc m ≤ suc n

data ⊥ : Set where
¬_ : Set → Set
¬ A = A → ⊥

data JobKind : Set where
  Start : JobKind
  Stop  : JobKind

UnitName : Set
UnitName = String

Deps : Set
Deps = List UnitName

record Job : Set where
  constructor job
  field
    name  : UnitName
    kind  : JobKind
    after : Deps

data Ready : Job → Set where
  stopReady  : ∀ n d   → Ready (job n Stop d)
  startReady : ∀ n     → Ready (job n Start [])

startBlockedNotReady : ∀ n dep rest →
  ¬ (Ready (job n Start (dep ∷ rest)))
startBlockedNotReady _ _ _ ()

length : ∀ {A : Set} → List A → Nat
length []       = zero
length (_ ∷ xs) = suc (length xs)

Transaction : Set
Transaction = List Job

removeAfter : UnitName → Deps → Deps
removeAfter _ []       = []
removeAfter u (x ∷ xs) with primStringEquality u x
  where
    postulate primStringEquality : String → String → Bool
... | true  = removeAfter u xs
... | false = x ∷ removeAfter u xs

dischargeUnit : UnitName → Transaction → Transaction
dischargeUnit _ []       = []
dischargeUnit u (j ∷ js) =
  job (Job.name j) (Job.kind j) (removeAfter u (Job.after j))
  ∷ dischargeUnit u js

totalDeps : Transaction → Nat
totalDeps []       = zero
totalDeps (j ∷ js) = length (Job.after j) + totalDeps js
  where
    _+_ : Nat → Nat → Nat
    zero  + m = m
    suc n + m = suc (n + m)

record Σ (A : Set) (P : A → Set) : Set where
  constructor _,_
  field
    fst : A
    snd : P fst

-- RustD's executable dependency resolver is obliged to provide a ready job
-- for each non-empty acyclic transaction. The constructive connection between
-- the proof object and implementation remains an explicit verification gap.
postulate
  acyclicHasReady : ∀ (t : Transaction) →
    ¬ (t ≡ []) →
    Σ Job (λ j → Ready j)
