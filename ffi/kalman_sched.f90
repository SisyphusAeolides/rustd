! SPDX-License-Identifier: LGPL-2.1-or-later
! kalman_sched.f90 — Kalman-filter-based adaptive scheduling predictor.
!
! Provides a C-ABI entry point for predicting next-period resource demand
! using a scalar Kalman filter over historical CPU/IO observations.
! Stub — to be populated once the base scheduling kernel (sched.f90) is
! fully exercised against the v261 baseline.

module kalman_sched_mod
  use iso_fortran_env, only: real64
  implicit none
  private
  public :: kalman_update

  ! Scalar Kalman filter state.
  type, public :: KalmanState
    real(real64) :: estimate      ! current state estimate
    real(real64) :: error_cov     ! estimate error covariance
    real(real64) :: process_noise ! process noise covariance (Q)
    real(real64) :: meas_noise    ! measurement noise covariance (R)
  end type KalmanState

contains

  ! kalman_update: incorporate a new measurement and return the updated estimate.
  !
  ! state    — filter state (in/out)
  ! measured — new observation
  ! returns updated estimate
  real(real64) function kalman_update(state, measured) result(updated)
    type(KalmanState), intent(inout) :: state
    real(real64),      intent(in)    :: measured

    real(real64) :: kg  ! Kalman gain

    ! Predict step: error covariance grows by process noise
    state%error_cov = state%error_cov + state%process_noise

    ! Update step: compute gain, correct estimate, shrink covariance
    kg = state%error_cov / (state%error_cov + state%meas_noise)
    state%estimate  = state%estimate + kg * (measured - state%estimate)
    state%error_cov = (1.0_real64 - kg) * state%error_cov

    updated = state%estimate
  end function kalman_update

end module kalman_sched_mod

! C-ABI entry point: rustd_kalman_sched_update
!
! estimate_inout — current estimate (in), updated estimate (out)
! error_cov_inout — error covariance (in/out)
! process_noise  — Q parameter
! meas_noise     — R parameter
! measured       — new observation
subroutine rustd_kalman_sched_update( &
    estimate_inout, error_cov_inout, &
    process_noise, meas_noise, measured) &
    bind(C, name="rustd_kalman_sched_update")
  use iso_c_binding,  only: c_double
  use kalman_sched_mod, only: KalmanState, kalman_update
  implicit none
  real(c_double), intent(inout) :: estimate_inout
  real(c_double), intent(inout) :: error_cov_inout
  real(c_double), intent(in), value :: process_noise
  real(c_double), intent(in), value :: meas_noise
  real(c_double), intent(in), value :: measured

  type(KalmanState) :: st
  st%estimate      = estimate_inout
  st%error_cov     = error_cov_inout
  st%process_noise = process_noise
  st%meas_noise    = meas_noise

  estimate_inout  = kalman_update(st, measured)
  error_cov_inout = st%error_cov
end subroutine rustd_kalman_sched_update
