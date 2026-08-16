! SPDX-License-Identifier: LGPL-2.1-or-later
! sched.f90 — deterministic scheduling-weight and resource-score kernel.
!
! Provides a C-ABI scoring function used by the Rust service manager to
! normalize CPU and IO weights and break ties deterministically.
! Mirrors the role of ffi/routing.f90 in systemd-resolved-rs.
!
! Upstream reference: src/core/cgroup.c (CPUWeight, IOWeight normalization)
! in systemd/systemd at de9dbc37ad4aa637e200ac02a0545095997055df.

module sched_score_mod
  implicit none
  private
  public :: score_weight

contains

  ! score_weight: normalize a cgroup weight value to [1, 10000] and
  ! return a floating-point score suitable for scheduling decisions.
  !
  ! upstream_weight: raw CPUWeight or IOWeight value (1–10000)
  ! total_weight:    sum of all sibling unit weights (must be > 0)
  ! result:          normalized share in (0.0, 1.0]
  pure real(kind=8) function score_weight(upstream_weight, total_weight) &
      result(share)
    integer(kind=8), intent(in) :: upstream_weight
    integer(kind=8), intent(in) :: total_weight

    integer(kind=8) :: clamped

    ! Clamp to the legal cgroup weight range
    clamped = max(1_8, min(upstream_weight, 10000_8))

    if (total_weight <= 0_8) then
      share = 1.0d0
    else
      share = real(clamped, kind=8) / real(total_weight, kind=8)
    end if
  end function score_weight

end module sched_score_mod

! C-ABI entry point: rustd_sched_score_weight
!
! weight      — raw cgroup weight (1–10000)
! total       — sum of sibling weights
! score_out   — output: normalized share
subroutine rustd_sched_score_weight(weight, total, score_out) &
    bind(C, name="rustd_sched_score_weight")
  use iso_c_binding, only: c_int64_t, c_double
  use sched_score_mod, only: score_weight
  implicit none
  integer(c_int64_t), intent(in),  value :: weight
  integer(c_int64_t), intent(in),  value :: total
  real(c_double),     intent(out)        :: score_out

  score_out = score_weight(weight, total)
end subroutine rustd_sched_score_weight
