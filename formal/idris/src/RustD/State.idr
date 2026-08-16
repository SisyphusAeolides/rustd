-- SPDX-License-Identifier: LGPL-2.1-or-later
module RustD.State

import Data.List
import RustD.Policy

%default total

public export
record UnitMachine where
  constructor MkUnitMachine
  name    : UnitName
  current : UnitState

public export
newUnit : UnitName -> UnitMachine
newUnit n = MkUnitMachine n Inactive

public export
applyTransition : UnitMachine -> UnitState -> Maybe UnitMachine
applyTransition m target =
  case step m.current target of
    Nothing => Nothing
    Just s  => Just (MkUnitMachine m.name s)

public export
newUnitIsInactive : (n : UnitName) -> (newUnit n).current = Inactive
newUnitIsInactive _ = Refl

public export
startNewUnit : UnitMachine -> Maybe UnitMachine
startNewUnit m = applyTransition m Activating

public export
newUnitCanStart : (n : UnitName) ->
  startNewUnit (newUnit n) = Just (MkUnitMachine n Activating)
newUnitCanStart _ = Refl

public export
Registry : Type
Registry = List (UnitName, UnitState)

public export
lookupUnit : UnitName -> Registry -> Maybe UnitState
lookupUnit _ []             = Nothing
lookupUnit n ((k, v) :: xs) =
  if n == k then Just v else lookupUnit n xs

public export
updateUnit : UnitName -> UnitState -> Registry -> Registry
updateUnit n s []             = [(n, s)]
updateUnit n s ((k, v) :: xs) =
  if n == k then (k, s) :: xs else (k, v) :: updateUnit n s xs

public export
isSettled : UnitState -> Bool
isSettled Inactive = True
isSettled Active   = True
isSettled Failed   = True
isSettled _        = False

public export
registrySettled : Registry -> Bool
registrySettled = all (isSettled . snd)

public export
buildRegistry : List UnitName -> Registry
buildRegistry = map (\n => (n, Inactive))

public export
builtRegistryAllInactive : (names : List UnitName) ->
  all (\pair => snd pair == Inactive) (buildRegistry names) = True
builtRegistryAllInactive []        = Refl
builtRegistryAllInactive (_ :: ns) = builtRegistryAllInactive ns

public export
data BootDecision
  = BootNormal
  | BootEmergency
  | BootRescue

public export
bootDecision : Registry -> BootDecision
bootDecision reg =
  let anyActive = any (\(_, s) => s == Active) reg
      anyFailed = any (\(_, s) => s == Failed) reg
  in if anyActive then BootNormal
     else if anyFailed then BootEmergency
     else BootNormal
