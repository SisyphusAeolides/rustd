//! ============================================================================
//! rustd · ML WEAVE
//! Lorenz attractor reservoir  ×  Mandelbrot nonlinear map  ×  online learners
//! ============================================================================
//!
//! A **very light** machine-learning fabric meant to be *woven through* the
//! whole manager — not a bolt-on demo. No ndarray, no BLAS, no GPU crates:
//! pure `std`, fixed-size math, O(F) online updates, safe for PID 1 if you
//! keep sample rates modest.
//!
//! ## Drop-in
//!
//! ```text
//! src/ml_weave/mod.rs   ← this file
//! ```
//!
//! ```toml
//! # Cargo.toml
//! [features]
//! ml-weave = []
//! ```
//!
//! ```rust,ignore
//! // src/lib.rs
//! #[cfg(feature = "ml-weave")]
//! pub mod ml_weave;
//! ```
//!
//! ## Woven through everything
//!
//! | Subsystem            | Hook                       | Model signal                       |
//! |----------------------|----------------------------|------------------------------------|
//! | Manager event tick   | `on_tick` / `weave_tick`   | global load / chaos regime         |
//! | JobQueue dispatch    | `score_job`                | start priority / defer             |
//! | service start/stop   | `on_unit_transition`       | restart risk, readiness ETA        |
//! | restart backoff      | `predict_restart_delay_ms` | learned failure clustering         |
//! | cgroup / resources   | `suggest_cpu_weight`       | Lorenz-energy → weight             |
//! | timer_unit           | `suggest_timer_slack_us`   | coalesce under high chaos          |
//! | notify / watchdog    | `anomaly_score`            | Mandelbrot-complexity residual     |
//! | journal rate         | `observe_log_rate`         | burst prediction                   |
//! | ipc / dbus           | `explain` / `status_line`  | `systemd-analyze weave` style      |
//!
//! ## Light ML stack (online, constant memory)
//!
//! 1. **Lorenz reservoir** — 3-D chaotic state driven by telemetry (echo-state
//!    style). Cheap nonlinear memory; reservoir is frozen, heads train.
//! 2. **Mandelbrot feature map** — multi-scale smooth potential of metric pairs.
//! 3. **LMS + logistic heads** — one tiny linear head per decision.
//! 4. **EWMA + Welford** — streaming mean/var for z-scores.
//! 5. **FNV unit hash table** — per-unit slots with epoch eviction.
//!
//! ## PID 1 posture
//!
//! - No threads spawned by the weave itself
//! - No file I/O on the hot path (weights save is explicit)
//! - All math finite-checked; NaN inputs clamped
//! - Feature flag off ⇒ zero code in the binary
//!
//! ============================================================================

#![allow(clippy::too_many_arguments)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::pedantic)]
#![allow(clippy::needless_raw_string_hashes)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::should_implement_trait)]

use std::collections::HashMap;
use std::f64::consts::{LN_2, PI};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// ############################################################################
// 0. CONSTANTS
// ############################################################################

/// Flat feature vector width seen by every linear head.
pub const FEAT_DIM: usize = 32;
/// Lorenz reservoir readout size.
pub const RESERVOIR_DIM: usize = 12;
/// Mandelbrot multi-scale probes.
pub const MANDEL_SCALES: usize = 4;
pub const DEFAULT_LR: f64 = 0.05;
pub const DEFAULT_L2: f64 = 1e-4;
pub const EWMA_FAST: f64 = 0.25;
pub const EWMA_SLOW: f64 = 0.02;
pub const MAX_UNIT_SLOTS: usize = 512;
pub const WEAVE_VERSION: &str = "ml-weave/1.0.0-lorenz-mandelbrot";

pub const INTEGRATION_GUIDE: &str = r#"
rustd ml-weave integration
===============================
1. Feature-gate: ml-weave
2. Manager tick  -> weave_tick / observe_pressure
3. Job dispatch  -> weave_job_score / weave_should_defer
4. Service start -> weave_on_starting + cpu_weight
5. READY=1       -> weave_on_ready
6. Failure       -> weave_on_failed + restart_delay_ms
7. Timers        -> weave_timer_slack_us
8. IPC           -> weave_status / weave_explain
9. Shutdown      -> weave_save_weights
10. Boot         -> weave_load_weights
"#;

// ############################################################################
// 1. NUMERIC PRIMITIVES
// ############################################################################

#[inline(always)]
fn finite(x: f64) -> f64 {
    if x.is_finite() {
        x
    } else {
        0.0
    }
}

#[inline(always)]
fn clamp01(x: f64) -> f64 {
    finite(x).clamp(0.0, 1.0)
}

#[inline(always)]
fn sigmoid(x: f64) -> f64 {
    let x = finite(x).clamp(-40.0, 40.0);
    1.0 / (1.0 + (-x).exp())
}

#[inline(always)]
fn tanh_approx(x: f64) -> f64 {
    let x = finite(x).clamp(-5.0, 5.0);
    let x2 = x * x;
    x * (27.0 + x2) / (27.0 + 9.0 * x2)
}

/// FNV-1a 64-bit — stable unit-name hashing.
#[inline]
pub fn fnv1a64(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

#[inline]
pub fn hash_unit(name: &str) -> u64 {
    fnv1a64(name.as_bytes())
}

// ############################################################################
// 2. STREAMING STATS
// ############################################################################

#[derive(Clone, Copy, Debug)]
pub struct Ewma {
    pub alpha: f64,
    pub value: f64,
    pub init: bool,
}

impl Ewma {
    pub const fn new(alpha: f64) -> Self {
        Self {
            alpha,
            value: 0.0,
            init: false,
        }
    }

    #[inline]
    pub fn push(&mut self, x: f64) -> f64 {
        let x = finite(x);
        if !self.init {
            self.value = x;
            self.init = true;
        } else {
            self.value = self.alpha * x + (1.0 - self.alpha) * self.value;
        }
        self.value
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Welford {
    pub n: u64,
    pub mean: f64,
    pub m2: f64,
}

impl Welford {
    #[inline]
    pub fn push(&mut self, x: f64) {
        let x = finite(x);
        self.n = self.n.saturating_add(1);
        let n = self.n as f64;
        let d = x - self.mean;
        self.mean += d / n;
        let d2 = x - self.mean;
        self.m2 += d * d2;
    }

    #[inline]
    pub fn variance(&self) -> f64 {
        if self.n < 2 {
            0.0
        } else {
            self.m2 / (self.n as f64 - 1.0)
        }
    }

    #[inline]
    pub fn stddev(&self) -> f64 {
        self.variance().max(0.0).sqrt()
    }

    #[inline]
    pub fn z(&self, x: f64) -> f64 {
        let s = self.stddev();
        if s < 1e-12 {
            0.0
        } else {
            (finite(x) - self.mean) / s
        }
    }
}

// ############################################################################
// 3. LORENZ ATTRACTOR — dynamical reservoir
// ############################################################################

#[derive(Clone, Copy, Debug)]
pub struct LorenzParams {
    pub sigma: f64,
    pub rho: f64,
    pub beta: f64,
}

impl Default for LorenzParams {
    #[inline]
    fn default() -> Self {
        Self {
            sigma: 10.0,
            rho: 28.0,
            beta: 8.0 / 3.0,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Vec3 {
    pub x: f64,
    pub y: f64,
    pub z: f64,
}

impl Vec3 {
    #[inline]
    pub const fn new(x: f64, y: f64, z: f64) -> Self {
        Self { x, y, z }
    }

    #[inline]
    pub fn scale(self, s: f64) -> Self {
        Self {
            x: self.x * s,
            y: self.y * s,
            z: self.z * s,
        }
    }

    #[inline]
    pub fn add(self, o: Self) -> Self {
        Self {
            x: self.x + o.x,
            y: self.y + o.y,
            z: self.z + o.z,
        }
    }

    #[inline]
    pub fn energy(self) -> f64 {
        finite(self.x * self.x + self.y * self.y + self.z * self.z)
    }

    #[inline]
    pub fn norm(self) -> f64 {
        self.energy().sqrt()
    }
}

#[inline(always)]
fn lorenz_deriv(p: &LorenzParams, v: Vec3) -> Vec3 {
    Vec3 {
        x: p.sigma * (v.y - v.x),
        y: v.x * (p.rho - v.z) - v.y,
        z: v.x * v.y - p.beta * v.z,
    }
}

/// Single RK4 step of the Lorenz flow.
#[inline(always)]
pub fn lorenz_rk4_step(p: &LorenzParams, v: Vec3, dt: f64) -> Vec3 {
    let k1 = lorenz_deriv(p, v);
    let k2 = lorenz_deriv(p, v.add(k1.scale(dt * 0.5)));
    let k3 = lorenz_deriv(p, v.add(k2.scale(dt * 0.5)));
    let k4 = lorenz_deriv(p, v.add(k3.scale(dt)));
    let sum = k1.add(k2.scale(2.0)).add(k3.scale(2.0)).add(k4);
    v.add(sum.scale(dt / 6.0))
}

/// Integrate a free trajectory (utility / splash / tests).
pub fn lorenz_trajectory(params: &LorenzParams, seed: Vec3, dt: f64, steps: usize) -> Vec<Vec3> {
    let mut out = Vec::with_capacity(steps);
    let mut s = seed;
    for _ in 0..steps {
        out.push(s);
        s = lorenz_rk4_step(params, s, dt);
    }
    out
}

/// Driven Lorenz reservoir (echo-state style).
///
/// Telemetry kicks the state; RK4 advances free dynamics; readout is a fixed
/// nonlinear expansion. Only the linear heads train.
#[derive(Clone, Debug)]
pub struct LorenzReservoir {
    pub params: LorenzParams,
    pub state: Vec3,
    pub dt: f64,
    pub in_gain: Vec3,
    pub energy_ewma: Ewma,
    pub steps: u64,
}

impl Default for LorenzReservoir {
    fn default() -> Self {
        Self {
            params: LorenzParams::default(),
            state: Vec3::new(0.1, 0.0, 0.0),
            dt: 0.01,
            in_gain: Vec3::new(0.15, 0.10, 0.08),
            energy_ewma: Ewma::new(EWMA_SLOW),
            steps: 0,
        }
    }
}

impl LorenzReservoir {
    /// Drive with normalized telemetry (roughly [0,1] or mild z-scores).
    pub fn drive(&mut self, load: f64, fail_rate: f64, job_depth: f64) {
        let load = finite(load);
        let fail_rate = finite(fail_rate);
        let job_depth = finite(job_depth);

        self.state.x = finite(self.state.x + self.in_gain.x * load);
        self.state.y = finite(self.state.y + self.in_gain.y * fail_rate);
        self.state.z = finite(self.state.z + self.in_gain.z * job_depth);

        let n = self.state.norm();
        if n > 80.0 {
            let s = 80.0 / n;
            self.state = self.state.scale(s);
        }

        self.state = lorenz_rk4_step(&self.params, self.state, self.dt);
        self.state.x = finite(self.state.x);
        self.state.y = finite(self.state.y);
        self.state.z = finite(self.state.z);

        self.energy_ewma.push(self.state.energy());
        self.steps = self.steps.saturating_add(1);
    }

    /// Fixed nonlinear readout → `RESERVOIR_DIM` features.
    pub fn readout(&self, out: &mut [f64]) {
        assert!(out.len() >= RESERVOIR_DIM);
        let s = self.state;
        let x = (s.x / 25.0).clamp(-1.5, 1.5);
        let y = (s.y / 35.0).clamp(-1.5, 1.5);
        let z = ((s.z - 25.0) / 25.0).clamp(-1.5, 1.5);
        let e = tanh_approx((self.energy_ewma.value / 800.0).ln_1p());

        out[0] = x;
        out[1] = y;
        out[2] = z;
        out[3] = x * y;
        out[4] = y * z;
        out[5] = z * x;
        out[6] = x * x - y * y;
        out[7] = tanh_approx(x + y);
        out[8] = tanh_approx(z - x);
        out[9] = e;
        out[10] = (self.steps as f64 * 0.001).sin() * 0.05;
        out[11] = clamp01(self.energy_ewma.value / 1200.0);
    }

    /// Scalar chaos regime in [0,1].
    #[inline]
    pub fn chaos_level(&self) -> f64 {
        clamp01(self.energy_ewma.value / 1000.0)
    }
}

// ############################################################################
// 4. MANDELBROT — nonlinear feature map
// ############################################################################

#[inline(always)]
fn mandel_interior(cr: f64, ci: f64) -> bool {
    let x = cr - 0.25;
    let q = x * x + ci * ci;
    if q * (q + x) < 0.25 * ci * ci {
        return true;
    }
    let xp1 = cr + 1.0;
    xp1 * xp1 + ci * ci < 0.0625
}

/// Smooth Mandelbrot potential in [0, max_iter].
#[inline(always)]
pub fn mandelbrot_smooth(cr: f64, ci: f64, max_iter: u32) -> f64 {
    if mandel_interior(cr, ci) {
        return max_iter as f64;
    }
    let mut zr = 0.0_f64;
    let mut zi = 0.0_f64;
    let mut iter = 0u32;
    while iter < max_iter {
        let zr2 = zr * zr;
        let zi2 = zi * zi;
        if zr2 + zi2 > 256.0 {
            let log_zn = (zr2 + zi2).ln() * 0.5;
            let nu = (log_zn / LN_2).ln() / LN_2;
            return iter as f64 + 1.0 - nu;
        }
        zi = (2.0 * zr).mul_add(zi, ci);
        zr = zr2 - zi2 + cr;
        iter += 1;
    }
    max_iter as f64
}

#[inline(always)]
pub fn mandelbrot_escape(cr: f64, ci: f64, max_iter: u32) -> u32 {
    if mandel_interior(cr, ci) {
        return max_iter;
    }
    let mut zr = 0.0_f64;
    let mut zi = 0.0_f64;
    let mut iter = 0u32;
    while iter < max_iter {
        let zr2 = zr * zr;
        let zi2 = zi * zi;
        if zr2 + zi2 > 4.0 {
            return iter;
        }
        zi = (2.0 * zr).mul_add(zi, ci);
        zr = zr2 - zi2 + cr;
        iter += 1;
    }
    max_iter
}

/// Map metric pairs into the Mandelbrot plane (cheap universal nonlinearity).
#[derive(Clone, Debug)]
pub struct MandelbrotEncoder {
    pub max_iter: u32,
    pub center_re: f64,
    pub center_im: f64,
    pub base_scale: f64,
    pub last: [f64; MANDEL_SCALES],
}

impl Default for MandelbrotEncoder {
    fn default() -> Self {
        Self {
            max_iter: 48,
            center_re: -0.75,
            center_im: 0.0,
            base_scale: 2.5,
            last: [0.0; MANDEL_SCALES],
        }
    }
}

impl MandelbrotEncoder {
    /// `u`,`v` roughly z-scored. Writes `MANDEL_SCALES` pots + deltas into `out`.
    pub fn encode(&mut self, u: f64, v: f64, out: &mut [f64]) {
        assert!(out.len() >= MANDEL_SCALES * 2);
        let u = finite(u).clamp(-4.0, 4.0);
        let v = finite(v).clamp(-4.0, 4.0);

        for s in 0..MANDEL_SCALES {
            let scale = self.base_scale * (0.45_f64).powi(s as i32);
            let cr = self.center_re + (u * 0.15 + 0.05 * (s as f64)) * scale;
            let ci = self.center_im + (v * 0.15 - 0.03 * (s as f64)) * scale;
            let pot = clamp01(mandelbrot_smooth(cr, ci, self.max_iter) / self.max_iter as f64);
            let delta = pot - self.last[s];
            self.last[s] = pot;
            out[s] = pot;
            out[MANDEL_SCALES + s] = tanh_approx(delta * 4.0);
        }
    }

    #[inline]
    pub fn complexity(&self) -> f64 {
        self.last[MANDEL_SCALES - 1]
    }
}

// ############################################################################
// 5. ONLINE LINEAR HEADS
// ############################################################################

/// LMS regressor with L2 decay.
#[derive(Clone, Debug)]
pub struct OnlineLinear {
    pub w: Vec<f64>,
    pub bias: f64,
    pub lr: f64,
    pub l2: f64,
    pub updates: u64,
    pub last_loss: f64,
}

impl OnlineLinear {
    pub fn new(dim: usize) -> Self {
        Self {
            w: vec![0.0; dim],
            bias: 0.0,
            lr: DEFAULT_LR,
            l2: DEFAULT_L2,
            updates: 0,
            last_loss: 0.0,
        }
    }

    #[inline]
    pub fn predict(&self, x: &[f64]) -> f64 {
        let n = self.w.len().min(x.len());
        let mut acc = self.bias;
        for i in 0..n {
            acc = finite(x[i]).mul_add(self.w[i], acc);
        }
        finite(acc)
    }

    pub fn observe(&mut self, x: &[f64], y: f64) -> f64 {
        let y = finite(y);
        let yhat = self.predict(x);
        let err = yhat - y;
        self.last_loss = 0.5 * err * err;
        let n = self.w.len().min(x.len());
        for i in 0..n {
            let g = err * finite(x[i]) + self.l2 * self.w[i];
            self.w[i] = finite(self.w[i] - self.lr * g);
        }
        self.bias = finite(self.bias - self.lr * err);
        self.updates = self.updates.saturating_add(1);
        yhat
    }
}

/// Online logistic classifier → P(positive) in [0,1].
#[derive(Clone, Debug)]
pub struct OnlineLogistic {
    pub w: Vec<f64>,
    pub bias: f64,
    pub lr: f64,
    pub l2: f64,
    pub updates: u64,
    pub last_loss: f64,
}

impl OnlineLogistic {
    pub fn new(dim: usize) -> Self {
        Self {
            w: vec![0.0; dim],
            bias: 0.0,
            lr: DEFAULT_LR,
            l2: DEFAULT_L2,
            updates: 0,
            last_loss: 0.0,
        }
    }

    #[inline]
    pub fn logit(&self, x: &[f64]) -> f64 {
        let n = self.w.len().min(x.len());
        let mut acc = self.bias;
        for i in 0..n {
            acc = finite(x[i]).mul_add(self.w[i], acc);
        }
        finite(acc)
    }

    #[inline]
    pub fn predict_proba(&self, x: &[f64]) -> f64 {
        sigmoid(self.logit(x))
    }

    pub fn observe(&mut self, x: &[f64], y: f64) -> f64 {
        let y = clamp01(y);
        let p = self.predict_proba(x);
        let err = p - y;
        self.last_loss = if y > 0.5 {
            -(p + 1e-12).ln()
        } else {
            -(1.0 - p + 1e-12).ln()
        };
        let n = self.w.len().min(x.len());
        for i in 0..n {
            let g = err * finite(x[i]) + self.l2 * self.w[i];
            self.w[i] = finite(self.w[i] - self.lr * g);
        }
        self.bias = finite(self.bias - self.lr * err);
        self.updates = self.updates.saturating_add(1);
        p
    }
}

#[derive(Clone, Debug)]
pub struct HeadBank {
    pub defer_job: OnlineLogistic,
    pub fail_risk: OnlineLogistic,
    pub ready_eta_ms: OnlineLinear,
    pub cpu_weight_log: OnlineLinear,
    pub anomaly: OnlineLogistic,
    pub timer_slack_log: OnlineLinear,
    pub restart_delay_log: OnlineLinear,
}

impl HeadBank {
    pub fn new(dim: usize) -> Self {
        Self {
            defer_job: OnlineLogistic::new(dim),
            fail_risk: OnlineLogistic::new(dim),
            ready_eta_ms: OnlineLinear::new(dim),
            cpu_weight_log: OnlineLinear::new(dim),
            anomaly: OnlineLogistic::new(dim),
            timer_slack_log: OnlineLinear::new(dim),
            restart_delay_log: OnlineLinear::new(dim),
        }
    }

    pub fn total_updates(&self) -> u64 {
        self.defer_job.updates
            + self.fail_risk.updates
            + self.ready_eta_ms.updates
            + self.cpu_weight_log.updates
            + self.anomaly.updates
            + self.timer_slack_log.updates
            + self.restart_delay_log.updates
    }
}

// ############################################################################
// 6. FEATURE BUILDER
// ############################################################################

/// Manager / unit telemetry snapshot. Fill what you have; rest may be 0.
#[derive(Clone, Debug, Default)]
pub struct Telemetry {
    pub load: f64,
    pub job_depth: f64,
    pub fail_rate: f64,
    pub notify_rate: f64,
    pub log_rate: f64,
    pub mem_pressure: f64,
    pub cpu_pressure: f64,
    pub io_pressure: f64,
    pub active_units: f64,
    pub uptime_s: f64,
    pub hour_of_day: f64,
    pub unit_restarts_1h: f64,
    pub unit_last_runtime_ms: f64,
    pub unit_fail_streak: f64,
    pub unit_importance: f64,
    pub unit_is_oneshot: f64,
    pub unit_is_socket_activated: f64,
    pub unit_cpu_usage: f64,
}

#[derive(Clone, Debug)]
pub struct FeatureBuilder {
    pub reservoir: LorenzReservoir,
    pub mandel: MandelbrotEncoder,
    pub load_stats: Welford,
    pub fail_stats: Welford,
    pub job_stats: Welford,
    pub log_stats: Welford,
    res_buf: [f64; RESERVOIR_DIM],
    man_buf: [f64; MANDEL_SCALES * 2],
    pub last_features: [f64; FEAT_DIM],
}

impl Default for FeatureBuilder {
    fn default() -> Self {
        Self {
            reservoir: LorenzReservoir::default(),
            mandel: MandelbrotEncoder::default(),
            load_stats: Welford::default(),
            fail_stats: Welford::default(),
            job_stats: Welford::default(),
            log_stats: Welford::default(),
            res_buf: [0.0; RESERVOIR_DIM],
            man_buf: [0.0; MANDEL_SCALES * 2],
            last_features: [0.0; FEAT_DIM],
        }
    }
}

impl FeatureBuilder {
    /// Drive reservoir + Mandelbrot encode; return internal feature row.
    pub fn build(&mut self, t: &Telemetry) -> &[f64; FEAT_DIM] {
        self.load_stats.push(t.load);
        self.fail_stats.push(t.fail_rate);
        self.job_stats.push(t.job_depth);
        self.log_stats.push(t.log_rate);

        let z_load = self.load_stats.z(t.load);
        let z_fail = self.fail_stats.z(t.fail_rate);
        let z_job = self.job_stats.z(t.job_depth);
        let z_log = self.log_stats.z(t.log_rate);

        self.reservoir.drive(
            clamp01(t.load / 8.0) + 0.1 * z_load.abs().tanh(),
            clamp01(t.fail_rate * 10.0) + 0.1 * z_fail.abs().tanh(),
            clamp01(t.job_depth / 32.0) + 0.1 * z_job.abs().tanh(),
        );
        self.reservoir.readout(&mut self.res_buf);

        self.mandel.encode(z_load, z_fail, &mut self.man_buf);
        let mut tmp = [0.0_f64; MANDEL_SCALES * 2];
        let mut m2 = MandelbrotEncoder {
            max_iter: self.mandel.max_iter,
            center_re: self.mandel.center_re,
            center_im: self.mandel.center_im,
            base_scale: self.mandel.base_scale,
            last: [0.0; MANDEL_SCALES],
        };
        m2.encode(z_job, z_log, &mut tmp);
        for i in 0..MANDEL_SCALES {
            self.man_buf[i] = 0.7 * self.man_buf[i] + 0.3 * tmp[i];
        }

        let f = &mut self.last_features;
        f.fill(0.0);

        f[0] = clamp01(t.load / 8.0);
        f[1] = clamp01(t.job_depth / 64.0);
        f[2] = clamp01(t.fail_rate * 5.0);
        f[3] = clamp01(t.notify_rate / 100.0);
        f[4] = clamp01(t.log_rate / 500.0);
        f[5] = clamp01(t.mem_pressure);
        f[6] = clamp01(t.cpu_pressure);
        f[7] = clamp01(t.io_pressure);

        f[8] = tanh_approx(z_load);
        f[9] = tanh_approx(z_fail);
        f[10] = tanh_approx(z_job);
        f[11] = tanh_approx(z_log);

        f[12] = clamp01(t.unit_restarts_1h / 20.0);
        f[13] = tanh_approx((t.unit_last_runtime_ms + 1.0).ln() / 10.0);
        f[14] = clamp01(t.unit_fail_streak / 10.0);
        f[15] = clamp01(t.unit_importance);
        f[16] = clamp01(t.unit_is_oneshot);
        f[17] = clamp01(t.unit_is_socket_activated);

        f[18] = self.res_buf[0];
        f[19] = self.res_buf[1];
        f[20] = self.res_buf[2];
        f[21] = self.res_buf[3];
        f[22] = self.res_buf[9];
        f[23] = self.res_buf[11];

        f[24] = self.man_buf[0];
        f[25] = self.man_buf[1];
        f[26] = self.man_buf[2];
        f[27] = self.man_buf[3];
        f[28] = self.man_buf[4];
        f[29] = self.man_buf[5];

        let hod = t.hour_of_day.rem_euclid(24.0);
        f[30] = (hod * (2.0 * PI / 24.0)).sin();
        f[31] = tanh_approx((t.uptime_s + 1.0).ln() / 12.0);

        for x in f.iter_mut() {
            *x = finite(*x);
        }
        &*f
    }
}

// ############################################################################
// 7. PER-UNIT MEMORY
// ############################################################################

#[derive(Clone, Debug)]
pub struct UnitSlot {
    pub hash: u64,
    pub epoch: u64,
    pub restarts_1h: Ewma,
    pub runtime_ms: Ewma,
    pub fail_streak: f64,
    pub last_fail_ns: u64,
    pub last_start_ns: u64,
    pub last_ready_ns: u64,
    pub importance: f64,
    pub is_oneshot: f64,
    pub is_socket_act: f64,
    pub local_fail_bias: f64,
    pub observations: u64,
}

impl UnitSlot {
    fn fresh(hash: u64, epoch: u64) -> Self {
        Self {
            hash,
            epoch,
            restarts_1h: Ewma::new(0.15),
            runtime_ms: Ewma::new(0.2),
            fail_streak: 0.0,
            last_fail_ns: 0,
            last_start_ns: 0,
            last_ready_ns: 0,
            importance: 0.5,
            is_oneshot: 0.0,
            is_socket_act: 0.0,
            local_fail_bias: 0.0,
            observations: 0,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct UnitTable {
    pub slots: Vec<UnitSlot>,
    pub epoch: u64,
}

impl UnitTable {
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            slots: Vec::with_capacity(cap.min(MAX_UNIT_SLOTS)),
            epoch: 1,
        }
    }

    pub fn get_mut(&mut self, name: &str) -> &mut UnitSlot {
        let h = hash_unit(name);
        if let Some(i) = self.slots.iter().position(|s| s.hash == h) {
            self.slots[i].epoch = self.epoch;
            return &mut self.slots[i];
        }
        self.epoch = self.epoch.saturating_add(1);
        if self.slots.len() >= MAX_UNIT_SLOTS {
            if let Some(min_i) = self
                .slots
                .iter()
                .enumerate()
                .min_by_key(|(_, s)| s.epoch)
                .map(|(i, _)| i)
            {
                self.slots[min_i] = UnitSlot::fresh(h, self.epoch);
                return &mut self.slots[min_i];
            }
        }
        self.slots.push(UnitSlot::fresh(h, self.epoch));
        let i = self.slots.len() - 1;
        &mut self.slots[i]
    }

    pub fn get(&self, name: &str) -> Option<&UnitSlot> {
        let h = hash_unit(name);
        self.slots.iter().find(|s| s.hash == h)
    }
}

// ############################################################################
// 8. DECISIONS
// ############################################################################

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobPriorityHint {
    Immediate,
    Normal,
    Deferred,
    Hold,
}

impl fmt::Display for JobPriorityHint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Immediate => write!(f, "immediate"),
            Self::Normal => write!(f, "normal"),
            Self::Deferred => write!(f, "deferred"),
            Self::Hold => write!(f, "hold"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct WeaveDecision {
    pub unit: String,
    pub job_priority: JobPriorityHint,
    pub defer_proba: f64,
    pub fail_risk: f64,
    pub ready_eta_ms: f64,
    pub cpu_weight: u64,
    pub anomaly: f64,
    pub timer_slack_us: u64,
    pub restart_delay_ms: u64,
    pub chaos_level: f64,
    pub mandel_complexity: f64,
    pub lorenz: Vec3,
    pub features: [f64; FEAT_DIM],
}

impl Default for WeaveDecision {
    fn default() -> Self {
        Self {
            unit: String::new(),
            job_priority: JobPriorityHint::Normal,
            defer_proba: 0.0,
            fail_risk: 0.0,
            ready_eta_ms: 0.0,
            cpu_weight: 100,
            anomaly: 0.0,
            timer_slack_us: 0,
            restart_delay_ms: 100,
            chaos_level: 0.0,
            mandel_complexity: 0.0,
            lorenz: Vec3::default(),
            features: [0.0; FEAT_DIM],
        }
    }
}

impl fmt::Display for WeaveDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} prio={} defer={:.2} fail={:.2} eta_ms={:.0} cpu_w={} anomaly={:.2} restart_ms={} chaos={:.2}",
            self.unit,
            self.job_priority,
            self.defer_proba,
            self.fail_risk,
            self.ready_eta_ms,
            self.cpu_weight,
            self.anomaly,
            self.restart_delay_ms,
            self.chaos_level
        )
    }
}

#[derive(Clone, Debug)]
pub struct WeaveExplanation {
    pub chaos_level: f64,
    pub mandel_complexity: f64,
    pub lorenz: Vec3,
    pub reservoir_steps: u64,
    pub head_updates: u64,
    pub units_tracked: usize,
    pub last_tick_us: u64,
    pub global_load_mean: f64,
    pub global_fail_mean: f64,
    pub notes: Vec<String>,
}

impl fmt::Display for WeaveExplanation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "chaos={:.3} mandel={:.3} lorenz=({:.2},{:.2},{:.2}) steps={}",
            self.chaos_level,
            self.mandel_complexity,
            self.lorenz.x,
            self.lorenz.y,
            self.lorenz.z,
            self.reservoir_steps
        )?;
        writeln!(
            f,
            "units={} head_updates={} last_tick={}µs load_mean={:.2} fail_mean={:.3}",
            self.units_tracked,
            self.head_updates,
            self.last_tick_us,
            self.global_load_mean,
            self.global_fail_mean
        )?;
        for n in &self.notes {
            writeln!(f, "  note: {n}")?;
        }
        Ok(())
    }
}

// ############################################################################
// 9. WEAVE BRAIN
// ############################################################################

#[derive(Debug, Default)]
pub struct WeaveCounters {
    pub ticks: AtomicU64,
    pub decisions: AtomicU64,
    pub learns: AtomicU64,
    pub anomalies_raised: AtomicU64,
}

impl Clone for WeaveCounters {
    fn clone(&self) -> Self {
        Self {
            ticks: AtomicU64::new(self.ticks.load(Ordering::Relaxed)),
            decisions: AtomicU64::new(self.decisions.load(Ordering::Relaxed)),
            learns: AtomicU64::new(self.learns.load(Ordering::Relaxed)),
            anomalies_raised: AtomicU64::new(self.anomalies_raised.load(Ordering::Relaxed)),
        }
    }
}

/// Central ML weave state — embed in `Manager` or use the process global.
#[derive(Debug)]
pub struct WeaveBrain {
    pub features: FeatureBuilder,
    pub heads: HeadBank,
    pub units: UnitTable,
    pub global: Telemetry,
    pub counters: WeaveCounters,
    pub boot: Instant,
    pub last_tick: Instant,
    pub last_tick_us: u64,
    pub defer_threshold: f64,
    pub flap_threshold: f64,
    pub learning_enabled: bool,
    decision_cache: HashMap<u64, WeaveDecision>,
}

impl Default for WeaveBrain {
    fn default() -> Self {
        Self::new()
    }
}

impl WeaveBrain {
    pub fn new() -> Self {
        Self {
            features: FeatureBuilder::default(),
            heads: HeadBank::new(FEAT_DIM),
            units: UnitTable::with_capacity(256),
            global: Telemetry::default(),
            counters: WeaveCounters::default(),
            boot: Instant::now(),
            last_tick: Instant::now(),
            last_tick_us: 0,
            defer_threshold: 0.55,
            flap_threshold: 0.60,
            learning_enabled: true,
            decision_cache: HashMap::with_capacity(128),
        }
    }

    #[inline]
    pub fn uptime_s(&self) -> f64 {
        self.boot.elapsed().as_secs_f64()
    }

    #[inline]
    pub fn now_ns_wall() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
    }

    #[inline]
    fn hour_of_day() -> f64 {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        ((secs % 86_400) as f64) / 3600.0
    }

    // ----- global ingest -----

    pub fn on_tick(&mut self, mut t: Telemetry) {
        let t0 = Instant::now();
        t.uptime_s = self.uptime_s();
        if t.hour_of_day == 0.0 {
            t.hour_of_day = Self::hour_of_day();
        }
        self.global = t.clone();
        let _ = self.features.build(&t);
        self.last_tick_us = t0.elapsed().as_micros() as u64;
        self.last_tick = Instant::now();
        self.counters.ticks.fetch_add(1, Ordering::Relaxed);
    }

    pub fn observe_rates(&mut self, load: f64, job_depth: f64, fail_rate: f64, log_rate: f64) {
        let mut t = self.global.clone();
        t.load = load;
        t.job_depth = job_depth;
        t.fail_rate = fail_rate;
        t.log_rate = log_rate;
        self.on_tick(t);
    }

    pub fn observe_log_rate(&mut self, lines_per_sec: f64) {
        self.global.log_rate = lines_per_sec;
    }

    pub fn observe_notify_rate(&mut self, per_sec: f64) {
        self.global.notify_rate = per_sec;
    }

    pub fn observe_pressure(&mut self, cpu: f64, mem: f64, io: f64) {
        self.global.cpu_pressure = clamp01(cpu);
        self.global.mem_pressure = clamp01(mem);
        self.global.io_pressure = clamp01(io);
    }

    // ----- unit lifecycle -----

    pub fn on_unit_loaded(
        &mut self,
        name: &str,
        importance: f64,
        is_oneshot: bool,
        is_socket_activated: bool,
    ) {
        let s = self.units.get_mut(name);
        s.importance = clamp01(importance);
        s.is_oneshot = if is_oneshot { 1.0 } else { 0.0 };
        s.is_socket_act = if is_socket_activated { 1.0 } else { 0.0 };
    }

    pub fn on_unit_starting(&mut self, name: &str) -> WeaveDecision {
        let now = Self::now_ns_wall();
        {
            let s = self.units.get_mut(name);
            s.last_start_ns = now;
            s.observations = s.observations.saturating_add(1);
        }
        self.decide(name)
    }

    pub fn on_unit_ready(&mut self, name: &str, runtime_ms: f64) {
        let now = Self::now_ns_wall();
        let mut y_eta = runtime_ms;
        {
            let s = self.units.get_mut(name);
            s.last_ready_ns = now;
            s.runtime_ms.push(runtime_ms);
            s.fail_streak = (s.fail_streak * 0.5).max(0.0);
            if s.last_start_ns > 0 && now > s.last_start_ns {
                y_eta = (now - s.last_start_ns) as f64 / 1_000_000.0;
            }
        }
        let x = self.telemetry_for(name);
        let feat = *self.features.build(&x);
        if self.learning_enabled {
            let _ = self.heads.ready_eta_ms.observe(&feat, y_eta);
            let _ = self.heads.fail_risk.observe(&feat, 0.0);
            let _ = self.heads.defer_job.observe(&feat, 0.0);
            let _ = self.heads.cpu_weight_log.observe(&feat, (100.0_f64).ln());
            self.counters.learns.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn on_unit_failed(&mut self, name: &str) -> WeaveDecision {
        let now = Self::now_ns_wall();
        {
            let s = self.units.get_mut(name);
            s.last_fail_ns = now;
            s.fail_streak += 1.0;
            s.restarts_1h.push(1.0);
            s.local_fail_bias = (s.local_fail_bias + 0.05).min(1.0);
            s.observations = s.observations.saturating_add(1);
        }
        self.global.fail_rate = self.global.fail_rate * 0.9 + 0.1;

        let x = self.telemetry_for(name);
        let feat = *self.features.build(&x);
        if self.learning_enabled {
            let _ = self.heads.fail_risk.observe(&feat, 1.0);
            let _ = self.heads.anomaly.observe(&feat, 1.0);
            let streak = self.units.get(name).map(|s| s.fail_streak).unwrap_or(1.0);
            let delay = 100.0 * 2.0_f64.powf(streak.min(8.0));
            let _ = self
                .heads
                .restart_delay_log
                .observe(&feat, (delay + 1.0).ln());
            let defer_y = if self.features.reservoir.chaos_level() > 0.5 {
                1.0
            } else {
                0.4
            };
            let _ = self.heads.defer_job.observe(&feat, defer_y);
            self.counters.learns.fetch_add(1, Ordering::Relaxed);
        }
        self.decide(name)
    }

    pub fn on_unit_stopped(&mut self, name: &str, success: bool) {
        let x = self.telemetry_for(name);
        let feat = *self.features.build(&x);
        if self.learning_enabled {
            let y = if success { 0.0 } else { 1.0 };
            let _ = self.heads.fail_risk.observe(&feat, y);
            if success {
                let s = self.units.get_mut(name);
                s.fail_streak = 0.0;
                s.local_fail_bias *= 0.9;
            }
            self.counters.learns.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn on_unit_transition(
        &mut self,
        name: &str,
        from: &str,
        to: &str,
    ) -> Option<WeaveDecision> {
        let to_l = to.to_ascii_lowercase();
        let from_l = from.to_ascii_lowercase();
        match to_l.as_str() {
            "starting" | "activating" => Some(self.on_unit_starting(name)),
            "running" | "active" => {
                self.on_unit_ready(name, 0.0);
                None
            }
            "failed" => Some(self.on_unit_failed(name)),
            "dead" | "inactive" | "stopped" => {
                let ok = !from_l.contains("fail");
                self.on_unit_stopped(name, ok);
                None
            }
            _ => None,
        }
    }

    // ----- inference -----

    fn telemetry_for(&self, name: &str) -> Telemetry {
        let mut t = self.global.clone();
        t.uptime_s = self.uptime_s();
        t.hour_of_day = Self::hour_of_day();
        if let Some(s) = self.units.get(name) {
            t.unit_restarts_1h = s.restarts_1h.value;
            t.unit_last_runtime_ms = s.runtime_ms.value;
            t.unit_fail_streak = s.fail_streak;
            t.unit_importance = s.importance;
            t.unit_is_oneshot = s.is_oneshot;
            t.unit_is_socket_activated = s.is_socket_act;
        }
        t
    }

    pub fn decide(&mut self, name: &str) -> WeaveDecision {
        let t = self.telemetry_for(name);
        let feat = *self.features.build(&t);

        let mut defer = self.heads.defer_job.predict_proba(&feat);
        let mut fail = self.heads.fail_risk.predict_proba(&feat);
        let importance = if let Some(s) = self.units.get(name) {
            fail = clamp01(fail + 0.5 * s.local_fail_bias);
            defer *= 1.0 - 0.7 * s.importance;
            s.importance
        } else {
            0.5
        };

        let eta = self.heads.ready_eta_ms.predict(&feat).max(0.0);
        let cpu_log = self.heads.cpu_weight_log.predict(&feat);
        let cpu = finite(cpu_log.exp()).clamp(1.0, 10_000.0) as u64;

        let anomaly = self.heads.anomaly.predict_proba(&feat);
        if anomaly > 0.85 {
            self.counters
                .anomalies_raised
                .fetch_add(1, Ordering::Relaxed);
        }

        let slack_log = self.heads.timer_slack_log.predict(&feat);
        let mut slack = finite(slack_log.exp()).clamp(0.0, 50_000_000.0) as u64;
        let chaos = self.features.reservoir.chaos_level();
        if chaos > 0.5 {
            slack = slack.saturating_add((chaos * 2_000_000.0) as u64);
        }

        let delay_log = self.heads.restart_delay_log.predict(&feat);
        let mut delay = finite(delay_log.exp() - 1.0).clamp(0.0, 300_000.0) as u64;
        if fail > self.flap_threshold {
            delay = delay.saturating_mul(2).max(500);
        }

        let job_priority = if importance > 0.85 {
            JobPriorityHint::Immediate
        } else if defer > 0.75 && chaos > 0.7 {
            JobPriorityHint::Hold
        } else if defer > self.defer_threshold || chaos > 0.65 {
            JobPriorityHint::Deferred
        } else if importance > 0.6 {
            JobPriorityHint::Immediate
        } else {
            JobPriorityHint::Normal
        };

        let d = WeaveDecision {
            unit: name.to_string(),
            job_priority,
            defer_proba: defer,
            fail_risk: fail,
            ready_eta_ms: eta,
            cpu_weight: cpu,
            anomaly,
            timer_slack_us: slack,
            restart_delay_ms: delay.max(10),
            chaos_level: chaos,
            mandel_complexity: self.features.mandel.complexity(),
            lorenz: self.features.reservoir.state,
            features: feat,
        };

        self.decision_cache.insert(hash_unit(name), d.clone());
        self.counters.decisions.fetch_add(1, Ordering::Relaxed);
        d
    }

    /// Higher score ⇒ run sooner.
    pub fn score_job(&mut self, unit: &str, is_critical: bool) -> f64 {
        let d = self.decide(unit);
        let mut score = 1.0 - d.defer_proba;
        if is_critical {
            score += 0.5;
        } else {
            score += 0.25 * d.features[15];
        }
        if !is_critical {
            score -= 0.5 * d.chaos_level;
        }
        score -= 0.3 * d.fail_risk;
        score + 0.01 * tanh_approx(d.lorenz.x / 10.0)
    }

    pub fn predict_restart_delay_ms(&mut self, unit: &str) -> u64 {
        self.decide(unit).restart_delay_ms
    }

    pub fn suggest_cpu_weight(&mut self, unit: &str) -> u64 {
        self.decide(unit).cpu_weight
    }

    pub fn suggest_timer_slack_us(&mut self, unit: &str) -> u64 {
        self.decide(unit).timer_slack_us
    }

    pub fn anomaly_score(&mut self, unit: &str) -> f64 {
        self.decide(unit).anomaly
    }

    pub fn should_defer_job(&mut self, unit: &str) -> bool {
        matches!(
            self.decide(unit).job_priority,
            JobPriorityHint::Deferred | JobPriorityHint::Hold
        )
    }

    pub fn explain(&self) -> WeaveExplanation {
        let mut notes = Vec::new();
        let chaos = self.features.reservoir.chaos_level();
        if chaos > 0.7 {
            notes.push("high chaos regime — deferring non-critical jobs".into());
        }
        if self.features.load_stats.mean > 4.0 {
            notes.push(format!(
                "elevated load mean={:.2}",
                self.features.load_stats.mean
            ));
        }
        if self.features.fail_stats.mean > 0.2 {
            notes.push(format!(
                "elevated fail_rate mean={:.3}",
                self.features.fail_stats.mean
            ));
        }
        if self.features.mandel.complexity() > 0.85 {
            notes.push("mandelbrot complexity high — nonlinear stress".into());
        }

        WeaveExplanation {
            chaos_level: chaos,
            mandel_complexity: self.features.mandel.complexity(),
            lorenz: self.features.reservoir.state,
            reservoir_steps: self.features.reservoir.steps,
            head_updates: self.heads.total_updates(),
            units_tracked: self.units.slots.len(),
            last_tick_us: self.last_tick_us,
            global_load_mean: self.features.load_stats.mean,
            global_fail_mean: self.features.fail_stats.mean,
            notes,
        }
    }

    pub fn status_line(&self) -> String {
        let e = self.explain();
        format!(
            "weave: chaos={:.2} mandel={:.2} L=({:.1},{:.1},{:.1}) units={} updates={} tick={}µs",
            e.chaos_level,
            e.mandel_complexity,
            e.lorenz.x,
            e.lorenz.y,
            e.lorenz.z,
            e.units_tracked,
            e.head_updates,
            e.last_tick_us
        )
    }

    pub fn export_weights(&self) -> WeaveWeights {
        WeaveWeights {
            defer_job: HeadWeights::from_logistic(&self.heads.defer_job),
            fail_risk: HeadWeights::from_logistic(&self.heads.fail_risk),
            ready_eta_ms: HeadWeights::from_linear(&self.heads.ready_eta_ms),
            cpu_weight_log: HeadWeights::from_linear(&self.heads.cpu_weight_log),
            anomaly: HeadWeights::from_logistic(&self.heads.anomaly),
            timer_slack_log: HeadWeights::from_linear(&self.heads.timer_slack_log),
            restart_delay_log: HeadWeights::from_linear(&self.heads.restart_delay_log),
            lorenz_state: self.features.reservoir.state,
            reservoir_steps: self.features.reservoir.steps,
        }
    }

    pub fn import_weights(&mut self, w: &WeaveWeights) {
        w.defer_job.apply_logistic(&mut self.heads.defer_job);
        w.fail_risk.apply_logistic(&mut self.heads.fail_risk);
        w.ready_eta_ms.apply_linear(&mut self.heads.ready_eta_ms);
        w.cpu_weight_log
            .apply_linear(&mut self.heads.cpu_weight_log);
        w.anomaly.apply_logistic(&mut self.heads.anomaly);
        w.timer_slack_log
            .apply_linear(&mut self.heads.timer_slack_log);
        w.restart_delay_log
            .apply_linear(&mut self.heads.restart_delay_log);
        self.features.reservoir.state = w.lorenz_state;
        self.features.reservoir.steps = w.reservoir_steps;
    }
}

// ############################################################################
// 10. WEIGHT SNAPSHOTS
// ############################################################################

#[derive(Clone, Debug)]
pub struct HeadWeights {
    pub w: Vec<f64>,
    pub bias: f64,
    pub updates: u64,
}

impl HeadWeights {
    fn from_linear(h: &OnlineLinear) -> Self {
        Self {
            w: h.w.clone(),
            bias: h.bias,
            updates: h.updates,
        }
    }
    fn from_logistic(h: &OnlineLogistic) -> Self {
        Self {
            w: h.w.clone(),
            bias: h.bias,
            updates: h.updates,
        }
    }
    fn apply_linear(&self, h: &mut OnlineLinear) {
        if self.w.len() == h.w.len() {
            h.w.copy_from_slice(&self.w);
            h.bias = self.bias;
            h.updates = self.updates;
        }
    }
    fn apply_logistic(&self, h: &mut OnlineLogistic) {
        if self.w.len() == h.w.len() {
            h.w.copy_from_slice(&self.w);
            h.bias = self.bias;
            h.updates = self.updates;
        }
    }
}

#[derive(Clone, Debug)]
pub struct WeaveWeights {
    pub defer_job: HeadWeights,
    pub fail_risk: HeadWeights,
    pub ready_eta_ms: HeadWeights,
    pub cpu_weight_log: HeadWeights,
    pub anomaly: HeadWeights,
    pub timer_slack_log: HeadWeights,
    pub restart_delay_log: HeadWeights,
    pub lorenz_state: Vec3,
    pub reservoir_steps: u64,
}

impl WeaveWeights {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = String::with_capacity(4096);
        out.push_str("weave-weights-v1\n");
        out.push_str(&format!(
            "lorenz {} {} {} {}\n",
            self.lorenz_state.x, self.lorenz_state.y, self.lorenz_state.z, self.reservoir_steps
        ));
        for (name, h) in [
            ("defer_job", &self.defer_job),
            ("fail_risk", &self.fail_risk),
            ("ready_eta_ms", &self.ready_eta_ms),
            ("cpu_weight_log", &self.cpu_weight_log),
            ("anomaly", &self.anomaly),
            ("timer_slack_log", &self.timer_slack_log),
            ("restart_delay_log", &self.restart_delay_log),
        ] {
            out.push_str(&format!("head {name} {} {}\n", h.bias, h.updates));
            out.push('w');
            for v in &h.w {
                out.push_str(&format!(" {v}"));
            }
            out.push('\n');
        }
        out.into_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let s = std::str::from_utf8(bytes).ok()?;
        let mut lines = s.lines();
        if lines.next()? != "weave-weights-v1" {
            return None;
        }
        let lor = lines.next()?;
        let mut lp = lor.split_whitespace();
        if lp.next()? != "lorenz" {
            return None;
        }
        let lx: f64 = lp.next()?.parse().ok()?;
        let ly: f64 = lp.next()?.parse().ok()?;
        let lz: f64 = lp.next()?.parse().ok()?;
        let steps: u64 = lp.next()?.parse().ok()?;

        let mut map: HashMap<String, HeadWeights> = HashMap::new();
        while let Some(line) = lines.next() {
            if !line.starts_with("head ") {
                continue;
            }
            let mut p = line.split_whitespace();
            let _ = p.next()?;
            let name = p.next()?.to_string();
            let bias: f64 = p.next()?.parse().ok()?;
            let updates: u64 = p.next()?.parse().ok()?;
            let wline = lines.next()?;
            let mut wp = wline.split_whitespace();
            if wp.next()? != "w" {
                return None;
            }
            let w: Vec<f64> = wp.filter_map(|x| x.parse().ok()).collect();
            map.insert(name, HeadWeights { w, bias, updates });
        }

        let mut take = |k: &str| {
            map.remove(k).unwrap_or(HeadWeights {
                w: vec![0.0; FEAT_DIM],
                bias: 0.0,
                updates: 0,
            })
        };

        Some(Self {
            defer_job: take("defer_job"),
            fail_risk: take("fail_risk"),
            ready_eta_ms: take("ready_eta_ms"),
            cpu_weight_log: take("cpu_weight_log"),
            anomaly: take("anomaly"),
            timer_slack_log: take("timer_slack_log"),
            restart_delay_log: take("restart_delay_log"),
            lorenz_state: Vec3::new(lx, ly, lz),
            reservoir_steps: steps,
        })
    }

    pub fn save(&self, path: &str) -> std::io::Result<()> {
        std::fs::write(path, self.to_bytes())
    }

    pub fn load(path: &str) -> std::io::Result<Self> {
        let b = std::fs::read(path)?;
        Self::from_bytes(&b).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "bad weave weights")
        })
    }
}

// ############################################################################
// 11. PROCESS GLOBAL
// ############################################################################

static GLOBAL_BRAIN: OnceLock<Mutex<WeaveBrain>> = OnceLock::new();

pub fn global_brain() -> &'static Mutex<WeaveBrain> {
    GLOBAL_BRAIN.get_or_init(|| Mutex::new(WeaveBrain::new()))
}

pub fn with_brain<R>(f: impl FnOnce(&mut WeaveBrain) -> R) -> R {
    let mut g = global_brain().lock().unwrap_or_else(|e| e.into_inner());
    f(&mut g)
}

// ############################################################################
// 12. FREE ADAPTERS — zero-friction call sites
// ############################################################################

pub trait WeaveAware {
    fn weave_unit_name(&self) -> &str;
    fn weave_importance(&self) -> f64 {
        0.5
    }
    fn weave_is_critical(&self) -> bool {
        self.weave_importance() > 0.85
    }
}

#[inline]
pub fn weave_tick(load: f64, jobs: f64, fails: f64, logs: f64) {
    with_brain(|b| b.observe_rates(load, jobs, fails, logs));
}

#[inline]
pub fn weave_job_score(unit: &str, critical: bool) -> f64 {
    with_brain(|b| b.score_job(unit, critical))
}

#[inline]
pub fn weave_should_defer(unit: &str) -> bool {
    with_brain(|b| b.should_defer_job(unit))
}

#[inline]
pub fn weave_on_starting(unit: &str) -> WeaveDecision {
    with_brain(|b| b.on_unit_starting(unit))
}

#[inline]
pub fn weave_on_ready(unit: &str, runtime_ms: f64) {
    with_brain(|b| b.on_unit_ready(unit, runtime_ms));
}

#[inline]
pub fn weave_on_failed(unit: &str) -> WeaveDecision {
    with_brain(|b| b.on_unit_failed(unit))
}

#[inline]
pub fn weave_on_stopped(unit: &str, success: bool) {
    with_brain(|b| b.on_unit_stopped(unit, success));
}

#[inline]
pub fn weave_restart_delay_ms(unit: &str) -> u64 {
    with_brain(|b| b.predict_restart_delay_ms(unit))
}

#[inline]
pub fn weave_cpu_weight(unit: &str) -> u64 {
    with_brain(|b| b.suggest_cpu_weight(unit))
}

#[inline]
pub fn weave_timer_slack_us(unit: &str) -> u64 {
    with_brain(|b| b.suggest_timer_slack_us(unit))
}

#[inline]
pub fn weave_anomaly(unit: &str) -> f64 {
    with_brain(|b| b.anomaly_score(unit))
}

#[inline]
pub fn weave_status() -> String {
    with_brain(|b| b.status_line())
}

#[inline]
pub fn weave_explain() -> WeaveExplanation {
    with_brain(|b| b.explain())
}

#[inline]
pub fn weave_transition(unit: &str, from: &str, to: &str) -> Option<WeaveDecision> {
    with_brain(|b| b.on_unit_transition(unit, from, to))
}

#[inline]
pub fn weave_load_unit(name: &str, importance: f64, oneshot: bool, socket_act: bool) {
    with_brain(|b| b.on_unit_loaded(name, importance, oneshot, socket_act));
}

#[inline]
pub fn weave_save_weights(path: &str) -> std::io::Result<()> {
    with_brain(|b| b.export_weights().save(path))
}

#[inline]
pub fn weave_load_weights(path: &str) -> std::io::Result<()> {
    let w = WeaveWeights::load(path)?;
    with_brain(|b| b.import_weights(&w));
    Ok(())
}

// ############################################################################
// 13. IMPORTANCE + BOOTSTRAP + MANAGER WRAPPER
// ############################################################################

pub fn importance_from_name(name: &str) -> f64 {
    let n = name.to_ascii_lowercase();
    if n.contains("systemd-journal") || n.contains("dbus") || n.starts_with("sysinit") {
        0.95
    } else if n.contains("udev") || n.contains("network") || n.ends_with(".target") {
        0.85
    } else if n.contains("ssh") || n.contains("login") || n.contains("getty") {
        0.8
    } else if n.ends_with(".socket") {
        0.7
    } else if n.ends_with(".mount") || n.ends_with(".swap") {
        0.75
    } else if n.ends_with(".timer") {
        0.45
    } else if n.contains("oneshot") || n.contains("-shutdown") {
        0.3
    } else if n.ends_with(".service") {
        0.5
    } else {
        0.4
    }
}

/// Synthetic scenarios so cold boot isn't brain-dead.
pub fn bootstrap_priors(brain: &mut WeaveBrain, rounds: usize) {
    for i in 0..rounds {
        let phase = i as f64 / rounds.max(1) as f64;
        let t = Telemetry {
            load: 0.5 + 4.0 * phase,
            job_depth: 1.0 + 20.0 * phase,
            fail_rate: if i % 7 == 0 { 0.5 } else { 0.02 },
            log_rate: 50.0 + 200.0 * phase,
            notify_rate: 10.0,
            cpu_pressure: phase * 0.8,
            mem_pressure: phase * 0.4,
            active_units: 100.0,
            unit_importance: if i % 5 == 0 { 0.95 } else { 0.4 },
            unit_fail_streak: if i % 7 == 0 { (i % 4) as f64 } else { 0.0 },
            unit_restarts_1h: if i % 7 == 0 { 3.0 } else { 0.0 },
            unit_last_runtime_ms: 200.0 + (i % 50) as f64 * 10.0,
            hour_of_day: (i % 24) as f64,
            uptime_s: 600.0 + i as f64,
            ..Telemetry::default()
        };
        let feat = *brain.features.build(&t);
        let fail_y = if i % 7 == 0 { 1.0 } else { 0.0 };
        let defer_y = if t.load > 3.0 && t.unit_importance < 0.7 {
            1.0
        } else {
            0.0
        };
        let _ = brain.heads.fail_risk.observe(&feat, fail_y);
        let _ = brain.heads.defer_job.observe(&feat, defer_y);
        let _ = brain
            .heads
            .ready_eta_ms
            .observe(&feat, t.unit_last_runtime_ms);
        let cpu_t: f64 = if t.unit_importance > 0.9 {
            500.0
        } else {
            100.0
        };
        let _ = brain.heads.cpu_weight_log.observe(&feat, cpu_t.ln());
        let _ = brain.heads.anomaly.observe(&feat, fail_y);
        let delay = 100.0 * (1.0 + t.unit_fail_streak);
        let _ = brain
            .heads
            .restart_delay_log
            .observe(&feat, (delay + 1.0).ln());
        let slack: f64 = if t.cpu_pressure > 0.5 {
            5_000_000.0
        } else {
            50_000.0
        };
        let _ = brain
            .heads
            .timer_slack_log
            .observe(&feat, (slack + 1.0).ln());
    }
}

/// Bounded controller that turns six nonlinear systems into a small scheduling
/// signal. It never changes dependency correctness or configured unit policy.
#[derive(Clone, Debug)]
pub struct ChaosDynamics {
    rossler: Vec3,
    logistic: f64,
    duffing_x: f64,
    duffing_v: f64,
    lyapunov: f64,
}

impl Default for ChaosDynamics {
    fn default() -> Self {
        Self {
            rossler: Vec3::new(0.1, 0.0, 0.0),
            logistic: 0.417,
            duffing_x: 0.1,
            duffing_v: 0.0,
            lyapunov: 0.0,
        }
    }
}

impl ChaosDynamics {
    fn step(&mut self, pressure: f64) -> f64 {
        let pressure = clamp01(pressure);
        let dt = 0.01;

        // Rössler flow.
        let dx = -self.rossler.y - self.rossler.z;
        let dy = self.rossler.x + 0.2 * self.rossler.y;
        let dz = 0.2 + self.rossler.z * (self.rossler.x - 5.7);
        self.rossler.x = finite(self.rossler.x + dt * dx).clamp(-20.0, 20.0);
        self.rossler.y = finite(self.rossler.y + dt * dy).clamp(-20.0, 20.0);
        self.rossler.z = finite(self.rossler.z + dt * dz).clamp(0.0, 40.0);

        // Logistic map and its finite-time Lyapunov exponent.
        let r = 3.72 + 0.22 * pressure;
        self.logistic = clamp01(r * self.logistic * (1.0 - self.logistic));
        let local = (r * (1.0 - 2.0 * self.logistic)).abs().max(1.0e-9).ln();
        self.lyapunov = finite(0.98 * self.lyapunov + 0.02 * local).clamp(-4.0, 4.0);

        // Forced Duffing oscillator.
        let force = 0.3 * (self.logistic * std::f64::consts::TAU).sin();
        let acceleration = self.duffing_x - self.duffing_x.powi(3) - 0.25 * self.duffing_v + force;
        self.duffing_v = finite(self.duffing_v + dt * acceleration).clamp(-4.0, 4.0);
        self.duffing_x = finite(self.duffing_x + dt * self.duffing_v).clamp(-3.0, 3.0);

        let rossler_signal = tanh_approx((self.rossler.x + self.rossler.y) / 20.0);
        let logistic_signal = 2.0 * self.logistic - 1.0;
        let duffing_signal = tanh_approx(self.duffing_x);
        let lyapunov_signal = tanh_approx(self.lyapunov);
        (0.25 * (rossler_signal + logistic_signal + duffing_signal + lyapunov_signal))
            .clamp(-1.0, 1.0)
    }
}

/// Field on `Manager`:
/// `pub weave: ManagerWeave`
#[derive(Debug)]
pub struct ManagerWeave {
    pub brain: WeaveBrain,
    pub tick_every: Duration,
    dynamics: ChaosDynamics,
    last_auto_tick: Instant,
}

impl Default for ManagerWeave {
    fn default() -> Self {
        Self::new()
    }
}

impl ManagerWeave {
    pub fn new() -> Self {
        let mut brain = WeaveBrain::new();
        bootstrap_priors(&mut brain, 256);
        Self {
            brain,
            tick_every: Duration::from_millis(250),
            dynamics: ChaosDynamics::default(),
            last_auto_tick: Instant::now(),
        }
    }

    pub fn maybe_tick(&mut self, load: f64, jobs: usize, fail_rate: f64, log_rate: f64) {
        if self.last_auto_tick.elapsed() >= self.tick_every {
            let pressure = clamp01(load / 16.0 + fail_rate * 0.5);
            let signal = self.dynamics.step(pressure);
            let shaped_load = (load * (1.0 + 0.03 * signal)).max(0.0);
            let shaped_fail = clamp01(fail_rate + 0.01 * signal.max(0.0));
            self.brain
                .observe_rates(shaped_load, jobs as f64, shaped_fail, log_rate);
            self.last_auto_tick = Instant::now();
        }
    }

    pub fn decide(&mut self, unit: &str) -> WeaveDecision {
        self.brain.decide(unit)
    }

    pub fn status(&self) -> String {
        self.brain.status_line()
    }
}

pub type SharedWeave = Arc<Mutex<WeaveBrain>>;

// ############################################################################
// 14. RENDER HELPERS (offline / splash — not hot path)
// ############################################################################

#[derive(Clone, Debug)]
pub struct Framebuffer {
    pub width: usize,
    pub height: usize,
    pub pixels: Vec<u8>,
}

impl Framebuffer {
    pub fn new(w: usize, h: usize) -> Self {
        Self {
            width: w,
            height: h,
            pixels: vec![0; w.saturating_mul(h).saturating_mul(4)],
        }
    }

    pub fn write_ppm(&self, path: &str) -> std::io::Result<()> {
        use std::io::Write;
        let mut f = std::fs::File::create(path)?;
        writeln!(f, "P6\n{} {}\n255", self.width, self.height)?;
        for px in self.pixels.chunks_exact(4) {
            f.write_all(&px[..3])?;
        }
        Ok(())
    }
}

#[inline]
fn hot(t: f64) -> (u8, u8, u8) {
    let t = clamp01(t);
    let r = (3.0 * t).clamp(0.0, 1.0);
    let g = (3.0 * t - 1.0).clamp(0.0, 1.0);
    let b = (3.0 * t - 2.0).clamp(0.0, 1.0);
    ((r * 255.0) as u8, (g * 255.0) as u8, (b * 255.0) as u8)
}

pub fn render_lorenz_splash(brain: &WeaveBrain, w: usize, h: usize, steps: usize) -> Framebuffer {
    let mut fb = Framebuffer::new(w, h);
    let p = brain.features.reservoir.params;
    let mut s = brain.features.reservoir.state;
    let mut hist = vec![0u32; w * h];
    for _ in 0..steps {
        s = lorenz_rk4_step(&p, s, 0.005);
        let x = ((s.x + 25.0) / 50.0 * w as f64) as isize;
        let y = ((50.0 - s.z) / 50.0 * h as f64) as isize;
        if x >= 0 && y >= 0 && (x as usize) < w && (y as usize) < h {
            let i = y as usize * w + x as usize;
            hist[i] = hist[i].saturating_add(1);
        }
    }
    let maxc = hist.iter().copied().max().unwrap_or(1).max(1) as f64;
    for y in 0..h {
        for x in 0..w {
            let c = hist[y * w + x] as f64;
            let t = (c + 1.0).ln() / (maxc + 1.0).ln();
            let (r, g, b) = hot(t);
            let i = (y * w + x) * 4;
            fb.pixels[i] = r;
            fb.pixels[i + 1] = g;
            fb.pixels[i + 2] = b;
            fb.pixels[i + 3] = 255;
        }
    }
    fb
}

pub fn render_mandelbrot(w: usize, h: usize, max_iter: u32) -> Framebuffer {
    let mut fb = Framebuffer::new(w, h);
    for y in 0..h {
        let ci = 1.25 - (y as f64 / h as f64) * 2.5;
        for x in 0..w {
            let cr = -2.0 + (x as f64 / w as f64) * 3.0;
            let v = mandelbrot_smooth(cr, ci, max_iter);
            let (r, g, b) = if v >= max_iter as f64 - 1e-9 {
                (0, 0, 0)
            } else {
                let t = (v * 0.05).fract().abs();
                let rr = (9.0 * (1.0 - t) * t * t * t * 255.0) as u8;
                let gg = (15.0 * (1.0 - t) * (1.0 - t) * t * t * 255.0) as u8;
                let bb = (8.5 * (1.0 - t) * (1.0 - t) * (1.0 - t) * t * 255.0) as u8;
                (rr, gg, bb)
            };
            let i = (y * w + x) * 4;
            fb.pixels[i] = r;
            fb.pixels[i + 1] = g;
            fb.pixels[i + 2] = b;
            fb.pixels[i + 3] = 255;
        }
    }
    fb
}

// ############################################################################
// 15. DEMO HARNESS
// ############################################################################

pub fn demo_closed_loop(rounds: usize) -> WeaveExplanation {
    let mut brain = WeaveBrain::new();
    bootstrap_priors(&mut brain, 128);

    for i in 0..rounds {
        let load = 1.0 + ((i as f64 * 0.07).sin() + 1.0) * 3.0;
        let jobs = (5.0 + (i as f64 * 0.03).cos() * 10.0).max(0.0);
        let fail = if i % 11 == 0 { 0.4 } else { 0.01 };
        brain.observe_rates(load, jobs, fail, 80.0 + load * 10.0);

        let unit = match i % 3 {
            0 => "sshd.service",
            1 => "app-worker.service",
            _ => "logrotate.service",
        };
        brain.on_unit_loaded(unit, importance_from_name(unit), false, false);
        let _d = brain.on_unit_starting(unit);
        if i % 11 == 0 {
            let _ = brain.on_unit_failed(unit);
        } else {
            brain.on_unit_ready(unit, 50.0 + load * 20.0);
            brain.on_unit_stopped(unit, true);
        }
    }
    brain.explain()
}

pub fn version_banner() -> String {
    format!(
        "{WEAVE_VERSION} feat_dim={FEAT_DIM} reservoir={RESERVOIR_DIM} mandel_scales={MANDEL_SCALES} max_units={MAX_UNIT_SLOTS}"
    )
}

// ############################################################################
// 16. COPY-PASTE GLUE (reference — not compiled into call graph)
// ############################################################################
//
// ### Manager event loop
// ```ignore
// #[cfg(feature = "ml-weave")]
// self.weave.maybe_tick(loadavg1, self.jobs.len(), fail_ewma, journal_lps);
// ```
//
// ### JobQueue dispatch
// ```ignore
// #[cfg(feature = "ml-weave")]
// ready.sort_by(|a, b| {
//     let sa = crate::ml_weave::weave_job_score(&a.unit, a.critical);
//     let sb = crate::ml_weave::weave_job_score(&b.unit, b.critical);
//     sb.partial_cmp(&sa).unwrap_or(std::cmp::Ordering::Equal)
// });
// ```
//
// ### Service start
// ```ignore
// #[cfg(feature = "ml-weave")]
// let d = crate::ml_weave::weave_on_starting(&name);
// cgroup.set_cpu_weight(d.cpu_weight)?;
// ```
//
// ### READY=1
// ```ignore
// #[cfg(feature = "ml-weave")]
// crate::ml_weave::weave_on_ready(&name, elapsed_ms);
// ```
//
// ### Failure / restart
// ```ignore
// #[cfg(feature = "ml-weave")]
// let delay = crate::ml_weave::weave_restart_delay_ms(&name);
// ```
//
// ### Timers
// ```ignore
// #[cfg(feature = "ml-weave")]
// let slack = crate::ml_weave::weave_timer_slack_us(&name);
// ```
//
// ### IPC
// ```ignore
// #[cfg(feature = "ml-weave")]
// "weave-status" => Ok(crate::ml_weave::weave_status()),
// ```
//
// ### Persist
// ```ignore
// weave_save_weights("/var/lib/rustd/weave.weights")?;
// weave_load_weights("/var/lib/rustd/weave.weights")?;
// ```

// ############################################################################
// 17. TESTS
// ############################################################################

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lorenz_bounded() {
        let p = LorenzParams::default();
        let mut s = Vec3::new(1.0, 1.0, 1.0);
        for _ in 0..20_000 {
            s = lorenz_rk4_step(&p, s, 0.01);
            assert!(s.x.is_finite() && s.y.is_finite() && s.z.is_finite());
        }
    }

    #[test]
    fn mandelbrot_interior_origin() {
        assert!((mandelbrot_smooth(0.0, 0.0, 64) - 64.0).abs() < 1e-9);
    }

    #[test]
    fn mandelbrot_escape_far() {
        assert!(mandelbrot_escape(3.0, 3.0, 50) < 5);
    }

    #[test]
    fn feature_dim_packed() {
        let mut fb = FeatureBuilder::default();
        let t = Telemetry {
            load: 1.5,
            job_depth: 4.0,
            fail_rate: 0.01,
            ..Telemetry::default()
        };
        let f = fb.build(&t);
        assert_eq!(f.len(), FEAT_DIM);
        assert!(f.iter().all(|x| x.is_finite()));
    }

    #[test]
    fn online_linear_fits_constant() {
        let mut m = OnlineLinear::new(2);
        m.lr = 0.1;
        for _ in 0..500 {
            m.observe(&[1.0, 0.0], 3.0);
        }
        let y = m.predict(&[1.0, 0.0]);
        assert!((y - 3.0).abs() < 0.2, "y={y}");
    }

    #[test]
    fn online_logistic_separates() {
        let mut m = OnlineLogistic::new(1);
        m.lr = 0.2;
        for _ in 0..400 {
            m.observe(&[2.0], 1.0);
            m.observe(&[-2.0], 0.0);
        }
        assert!(m.predict_proba(&[2.0]) > 0.7);
        assert!(m.predict_proba(&[-2.0]) < 0.3);
    }

    #[test]
    fn brain_decision_smoke() {
        let mut b = WeaveBrain::new();
        bootstrap_priors(&mut b, 64);
        b.observe_rates(2.0, 5.0, 0.0, 10.0);
        b.on_unit_loaded("sshd.service", 0.9, false, false);
        let d = b.on_unit_starting("sshd.service");
        assert_eq!(d.unit, "sshd.service");
        assert!(d.cpu_weight >= 1);
        b.on_unit_ready("sshd.service", 120.0);
    }

    #[test]
    fn weights_roundtrip() {
        let mut b = WeaveBrain::new();
        bootstrap_priors(&mut b, 32);
        let w = b.export_weights();
        let bytes = w.to_bytes();
        let w2 = WeaveWeights::from_bytes(&bytes).expect("parse");
        let mut b2 = WeaveBrain::new();
        b2.import_weights(&w2);
        assert_eq!(b.heads.fail_risk.updates, b2.heads.fail_risk.updates);
    }

    #[test]
    fn unit_table_eviction() {
        let mut t = UnitTable::with_capacity(4);
        for i in 0..MAX_UNIT_SLOTS + 10 {
            let _ = t.get_mut(&format!("u{i}.service"));
        }
        assert!(t.slots.len() <= MAX_UNIT_SLOTS);
    }

    #[test]
    fn demo_runs() {
        let e = demo_closed_loop(40);
        assert!(e.reservoir_steps > 0);
        assert!(e.head_updates > 0);
    }

    #[test]
    fn global_helpers() {
        weave_tick(1.0, 2.0, 0.0, 5.0);
        weave_load_unit("demo.service", 0.5, false, false);
        assert!(weave_job_score("demo.service", false).is_finite());
        assert!(weave_status().contains("weave:"));
    }

    #[test]
    fn importance_heuristic() {
        assert!(importance_from_name("systemd-journald.service") > 0.9);
        assert!(importance_from_name("frob.timer") < 0.5);
    }

    #[test]
    fn trajectory_len() {
        let t = lorenz_trajectory(
            &LorenzParams::default(),
            Vec3::new(0.1, 0.0, 0.0),
            0.01,
            100,
        );
        assert_eq!(t.len(), 100);
    }

    #[test]
    fn nonlinear_controller_remains_bounded() {
        let mut dynamics = ChaosDynamics::default();
        for index in 0..100_000 {
            let signal = dynamics.step(f64::from(index % 101) / 100.0);
            assert!(signal.is_finite());
            assert!((-1.0..=1.0).contains(&signal));
        }
    }
}
