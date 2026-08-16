-- SPDX-License-Identifier: LGPL-2.1-or-later
module RustD.Cgroup.Bound where

open import Agda.Builtin.Nat      using (Nat; zero; suc)
open import Agda.Builtin.Equality using (_≡_; refl)

infix 4 _≤_
data _≤_ : Nat → Nat → Set where
  z≤n : ∀ {n}   →         zero  ≤ n
  s≤s : ∀ {m n} → m ≤ n → suc m ≤ suc n

≤-refl : ∀ {n} → n ≤ n
≤-refl {zero}  = z≤n
≤-refl {suc n} = s≤s ≤-refl

≤-trans : ∀ {a b c} → a ≤ b → b ≤ c → a ≤ c
≤-trans z≤n     _       = z≤n
≤-trans (s≤s a) (s≤s b) = s≤s (≤-trans a b)

data ⊥ : Set where
¬_ : Set → Set
¬ A = A → ⊥

MIN-WEIGHT : Nat
MIN-WEIGHT = 1

MAX-WEIGHT : Nat
MAX-WEIGHT = 10000

record CgroupWeight : Set where
  constructor weight
  field
    value    : Nat
    atLeast1 : MIN-WEIGHT ≤ value
    atMost   : value ≤ MAX-WEIGHT

minWeight : CgroupWeight
minWeight = weight 1 (s≤s z≤n) (s≤s z≤n)

data Dec≤ (m n : Nat) : Set where
  yes : m ≤ n → Dec≤ m n
  no  : ¬ (m ≤ n) → Dec≤ m n

decide≤ : (m n : Nat) → Dec≤ m n
decide≤ zero    _       = yes z≤n
decide≤ (suc m) zero    = no (λ ())
decide≤ (suc m) (suc n) with decide≤ m n
... | yes p = yes (s≤s p)
... | no  f = no  (λ { (s≤s p) → f p })

clamp : (lo hi n : Nat) → lo ≤ hi → Nat
clamp lo _  n _ with decide≤ n lo
... | yes _ = lo
clamp _ hi n _ | no _ with decide≤ hi n
... | yes _ = hi
... | no  _ = n

clampBelowReturnsLo : ∀ lo hi n (p : lo ≤ hi) → n ≤ lo → clamp lo hi n p ≡ lo
clampBelowReturnsLo lo hi n p q with decide≤ n lo
... | yes _ = refl
... | no  f = ⊥-elim (f q)
  where
    ⊥-elim : ∀ {A : Set} → ⊥ → A
    ⊥-elim ()

record MemoryLimit : Set where
  constructor memlimit
  field
    bytes : Nat

data TasksAllowed : Nat → Set where
  some-tasks : ∀ {n} → TasksAllowed (suc n)

tasksAllowedEx : TasksAllowed 256
tasksAllowedEx = some-tasks

zeroTasksImpossible : ¬ (TasksAllowed zero)
zeroTasksImpossible ()

CGROUP-MAX-DEPTH : Nat
CGROUP-MAX-DEPTH = 64

record CgroupDepth : Set where
  constructor depth
  field
    level   : Nat
    bounded : level ≤ CGROUP-MAX-DEPTH

rootDepth : CgroupDepth
rootDepth = depth zero z≤n

childDepth : CgroupDepth → CgroupDepth
childDepth (depth zero    p) = depth 1 (s≤s z≤n)
childDepth (depth (suc n) p) with decide≤ (suc (suc n)) CGROUP-MAX-DEPTH
... | yes q = depth (suc (suc n)) q
... | no  _ = depth (suc n) p
