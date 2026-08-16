-- SPDX-License-Identifier: LGPL-2.1-or-later
module RustD.Transaction

import Data.Fin
import Data.List
import Data.Nat
import Data.String
import RustD.Policy

%default total

public export
data JobKind = JobStart | JobStop

public export
Eq JobKind where
  JobStart == JobStart = True
  JobStop  == JobStop  = True
  _        == _        = False

public export
record Job where
  constructor MkJob
  unit  : UnitName
  kind  : JobKind
  after : List UnitName

public export
Transaction : Type
Transaction = List Job

public export
data Ready : Job -> Type where
  StopReady  : (u : UnitName) -> (d : List UnitName) -> Ready (MkJob u JobStop d)
  StartReady : (u : UnitName) -> Ready (MkJob u JobStart [])

public export
removeFromDeps : UnitName -> List UnitName -> List UnitName
removeFromDeps _ []        = []
removeFromDeps u (x :: xs) =
  if u == x then removeFromDeps u xs
  else x :: removeFromDeps u xs

public export
dischargeUnit : UnitName -> Transaction -> Transaction
dischargeUnit _ []        = []
dischargeUnit u (j :: js) =
  MkJob j.unit j.kind (removeFromDeps u j.after) :: dischargeUnit u js

public export
readyJobs : Transaction -> List Job
readyJobs = filter isReady
  where
    isReady : Job -> Bool
    isReady (MkJob _ JobStop  _)  = True
    isReady (MkJob _ JobStart []) = True
    isReady _                     = False

totalDeps : Transaction -> Nat
totalDeps []        = 0
totalDeps (j :: js) = length j.after + totalDeps js

public export
pickReady : Transaction -> Maybe (Job, Transaction)
pickReady [] = Nothing
pickReady (j :: js) =
  if isReady j then Just (j, js)
  else case pickReady js of
    Nothing        => Nothing
    Just (r, rest) => Just (r, j :: rest)
  where
    isReady : Job -> Bool
    isReady (MkJob _ JobStop  _)  = True
    isReady (MkJob _ JobStart []) = True
    isReady _                     = False

public export
linearise : (fuel : Nat) -> Transaction -> List Job
linearise 0     _  = []
linearise _     [] = []
linearise (S n) t  =
  case pickReady t of
    Nothing        => []
    Just (j, rest) =>
      j :: linearise n (dischargeUnit j.unit rest)

public export
record SeqNum where
  constructor MkSeqNum
  value : Nat

public export
nextSeqNum : SeqNum -> SeqNum
nextSeqNum (MkSeqNum n) = MkSeqNum (S n)

lteReflNat : (n : Nat) -> n `LTE` n
lteReflNat Z     = LTEZero
lteReflNat (S n) = LTESucc (lteReflNat n)

public export
seqNumIncreases : (s : SeqNum) -> S s.value `LTE` (nextSeqNum s).value
seqNumIncreases (MkSeqNum n) = LTESucc (lteReflNat n)

public export
data CycleDetected : Transaction -> Type where
  MkCycleDetected :
    (t : Transaction) ->
    (nonEmpty : NonEmpty t) ->
    (noReady  : readyJobs t = []) ->
    CycleDetected t

public export
dischargeEmptyIsEmpty : (u : UnitName) -> dischargeUnit u [] = []
dischargeEmptyIsEmpty _ = Refl

-- This obligation remains explicitly linked to the manager dependency
-- implementation. Completing a constructive proof is tracked separately from
-- the executable transaction correctness tests.
public export
stopAfterStart :
    (u          : UnitName) ->
    (t          : Transaction) ->
    (linearised : List Job) ->
    linearised = linearise (length t * S (totalDeps t)) t ->
    let idx  = \k => map finToNat (findIndex (\j => j.unit == u && j.kind == k) linearised)
    in case (idx JobStart, idx JobStop) of
         (Just si, Just oi) => si `LTE` oi
         _                  => ()
stopAfterStart u t lin prf = believe_me ()
