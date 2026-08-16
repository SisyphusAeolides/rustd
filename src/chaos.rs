#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]
//! Lorenz attractor and Mandelbrot kernels for opt-in diagnostics and stress tests.

use std::thread;

/// RGBA8 framebuffer in row-major order.
#[derive(Clone, Debug)]
pub struct Framebuffer {
    pub width: usize,
    pub height: usize,
    pub pixels: Vec<u8>,
}

impl Framebuffer {
    #[must_use]
    pub fn new(width: usize, height: usize) -> Self {
        Self {
            width,
            height,
            pixels: vec![0; width.saturating_mul(height).saturating_mul(4)],
        }
    }

    /// Set one pixel, ignoring coordinates outside the framebuffer.
    pub fn set_rgba(&mut self, x: usize, y: usize, red: u8, green: u8, blue: u8, alpha: u8) {
        if x >= self.width || y >= self.height {
            return;
        }
        let offset = (y * self.width + x) * 4;
        self.pixels[offset..offset + 4].copy_from_slice(&[red, green, blue, alpha]);
    }

    /// Write the framebuffer as binary PPM (P6).
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the destination cannot be created or written.
    pub fn write_ppm(&self, path: &str) -> std::io::Result<()> {
        use std::io::Write;

        let mut file = std::fs::File::create(path)?;
        writeln!(file, "P6\n{} {}\n255", self.width, self.height)?;
        for pixel in self.pixels.chunks_exact(4) {
            file.write_all(&pixel[..3])?;
        }
        Ok(())
    }

    /// Return an ANSI truecolour half-block preview.
    #[must_use]
    pub fn to_ansi_halfblocks(&self) -> String {
        use std::fmt::Write;

        let mut output =
            String::with_capacity(self.width.saturating_mul(self.height).saturating_mul(24));
        for y in (0..(self.height & !1)).step_by(2) {
            for x in 0..self.width {
                let top = (y * self.width + x) * 4;
                let bottom = ((y + 1) * self.width + x) * 4;
                let _ = write!(
                    output,
                    "\x1b[38;2;{};{};{}m\x1b[48;2;{};{};{}m▀",
                    self.pixels[top],
                    self.pixels[top + 1],
                    self.pixels[top + 2],
                    self.pixels[bottom],
                    self.pixels[bottom + 1],
                    self.pixels[bottom + 2],
                );
            }
            output.push_str("\x1b[0m\n");
        }
        output
    }
}

/// Compact viridis-like colour map for a value in the range 0..=1.
#[must_use]
pub fn colormap_viridis(value: f64) -> (u8, u8, u8) {
    let value = value.clamp(0.0, 1.0);
    let red =
        (0.267 + 0.005 * value + 2.1 * value * value - 2.3 * value * value * value).clamp(0.0, 1.0);
    let green = (0.005 + 1.4 * value - 0.55 * value * value).clamp(0.0, 1.0);
    let blue =
        (0.329 + 1.5 * value - 2.4 * value * value + 1.2 * value * value * value).clamp(0.0, 1.0);
    (
        (red * 255.0) as u8,
        (green * 255.0) as u8,
        (blue * 255.0) as u8,
    )
}

/// Hot colour map: black through red and yellow to white.
#[must_use]
pub fn colormap_hot(value: f64) -> (u8, u8, u8) {
    let value = value.clamp(0.0, 1.0);
    (
        (255.0 * (3.0 * value).clamp(0.0, 1.0)) as u8,
        (255.0 * (3.0 * value - 1.0).clamp(0.0, 1.0)) as u8,
        (255.0 * (3.0 * value - 2.0).clamp(0.0, 1.0)) as u8,
    )
}

fn default_threads() -> usize {
    thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
}

/// Parameters for the classic chaotic Lorenz attractor.
#[derive(Clone, Copy, Debug)]
pub struct LorenzParams {
    pub sigma: f64,
    pub rho: f64,
    pub beta: f64,
}

impl Default for LorenzParams {
    fn default() -> Self {
        Self {
            sigma: 10.0,
            rho: 28.0,
            beta: 8.0 / 3.0,
        }
    }
}

/// Three-dimensional point used by the Lorenz integrator.
#[derive(Clone, Copy, Debug, Default)]
pub struct Vec3 {
    pub x: f64,
    pub y: f64,
    pub z: f64,
}

impl Vec3 {
    #[must_use]
    pub const fn new(x: f64, y: f64, z: f64) -> Self {
        Self { x, y, z }
    }

    #[must_use]
    pub fn scale(self, scalar: f64) -> Self {
        Self {
            x: self.x * scalar,
            y: self.y * scalar,
            z: self.z * scalar,
        }
    }

    #[allow(clippy::should_implement_trait)]
    #[must_use]
    pub fn add(self, other: Self) -> Self {
        Self {
            x: self.x + other.x,
            y: self.y + other.y,
            z: self.z + other.z,
        }
    }
}

/// Return the Lorenz derivatives at `value`.
#[must_use]
pub fn lorenz_deriv(parameters: &LorenzParams, value: Vec3) -> Vec3 {
    Vec3 {
        x: parameters.sigma * (value.y - value.x),
        y: value.x * (parameters.rho - value.z) - value.y,
        z: value.x * value.y - parameters.beta * value.z,
    }
}

/// Advance the Lorenz system with a single RK4 step.
#[must_use]
pub fn lorenz_rk4_step(parameters: &LorenzParams, value: Vec3, delta: f64) -> Vec3 {
    let k1 = lorenz_deriv(parameters, value);
    let k2 = lorenz_deriv(parameters, value.add(k1.scale(delta * 0.5)));
    let k3 = lorenz_deriv(parameters, value.add(k2.scale(delta * 0.5)));
    let k4 = lorenz_deriv(parameters, value.add(k3.scale(delta)));
    value.add(
        k1.add(k2.scale(2.0))
            .add(k3.scale(2.0))
            .add(k4)
            .scale(delta / 6.0),
    )
}

/// Integrate a Lorenz trajectory into caller-owned structure-of-arrays buffers.
pub fn lorenz_integrate_soa(
    parameters: &LorenzParams,
    mut state: Vec3,
    delta: f64,
    steps: usize,
    xs: &mut [f64],
    ys: &mut [f64],
    zs: &mut [f64],
) -> usize {
    let count = steps.min(xs.len()).min(ys.len()).min(zs.len());
    for index in 0..count {
        xs[index] = state.x;
        ys[index] = state.y;
        zs[index] = state.z;
        state = lorenz_rk4_step(parameters, state, delta);
    }
    count
}

/// Allocate and integrate a single Lorenz trajectory.
#[must_use]
pub fn lorenz_trajectory(
    parameters: &LorenzParams,
    seed: Vec3,
    delta: f64,
    steps: usize,
) -> Vec<Vec3> {
    let mut trajectory = Vec::with_capacity(steps);
    let mut state = seed;
    for _ in 0..steps {
        trajectory.push(state);
        state = lorenz_rk4_step(parameters, state, delta);
    }
    trajectory
}

/// Integrate a multi-seed Lorenz ensemble using scoped worker threads.
///
/// # Panics
///
/// Panics if an internal worker panics.
#[must_use]
pub fn lorenz_ensemble_parallel(
    parameters: LorenzParams,
    seeds: &[Vec3],
    delta: f64,
    steps_per_seed: usize,
    threads: usize,
) -> Vec<Vec3> {
    if seeds.is_empty() || steps_per_seed == 0 {
        return Vec::new();
    }
    let threads = threads.max(1).min(seeds.len());
    let chunk_size = seeds.len().div_ceil(threads);
    let mut parts: Vec<Vec<Vec3>> = (0..threads).map(|_| Vec::new()).collect();
    thread::scope(|scope| {
        let mut handles = Vec::with_capacity(threads);
        for (worker, part) in parts.iter_mut().enumerate() {
            let start = worker * chunk_size;
            if start >= seeds.len() {
                break;
            }
            let seeds = &seeds[start..(start + chunk_size).min(seeds.len())];
            handles.push(scope.spawn(move || {
                let mut local = Vec::with_capacity(seeds.len().saturating_mul(steps_per_seed));
                for &seed in seeds {
                    let mut state = seed;
                    for _ in 0..steps_per_seed {
                        local.push(state);
                        state = lorenz_rk4_step(&parameters, state, delta);
                    }
                }
                *part = local;
            }));
        }
        for handle in handles {
            handle.join().expect("Lorenz worker panicked");
        }
    });
    parts.into_iter().flatten().collect()
}

/// Project a trajectory on a plane and colourize its density with a hot map.
///
/// # Panics
///
/// Panics if an internal worker panics.
#[must_use]
pub fn lorenz_density_render(
    points: &[Vec3],
    width: usize,
    height: usize,
    axis_horizontal: u8,
    axis_vertical: u8,
    horizontal_range: (f64, f64),
    vertical_range: (f64, f64),
) -> Framebuffer {
    let mut framebuffer = Framebuffer::new(width, height);
    if points.is_empty() || width == 0 || height == 0 {
        return framebuffer;
    }
    let horizontal_delta = (horizontal_range.1 - horizontal_range.0).max(1e-12);
    let vertical_delta = (vertical_range.1 - vertical_range.0).max(1e-12);
    let horizontal_scale = width as f64 / horizontal_delta;
    let vertical_scale = height as f64 / vertical_delta;
    let component = |point: &Vec3, axis| match axis {
        0 => point.x,
        1 => point.y,
        _ => point.z,
    };
    let threads = default_threads().min(points.len());
    let chunk_size = points.len().div_ceil(threads);
    let mut local_histograms = (0..threads)
        .map(|_| vec![0_u32; width * height])
        .collect::<Vec<_>>();
    thread::scope(|scope| {
        let mut handles = Vec::with_capacity(threads);
        for (worker, histogram) in local_histograms.iter_mut().enumerate() {
            let start = worker * chunk_size;
            if start >= points.len() {
                break;
            }
            let points = &points[start..(start + chunk_size).min(points.len())];
            handles.push(scope.spawn(move || {
                for point in points {
                    let horizontal = component(point, axis_horizontal);
                    let vertical = component(point, axis_vertical);
                    if horizontal < horizontal_range.0
                        || horizontal >= horizontal_range.1
                        || vertical < vertical_range.0
                        || vertical >= vertical_range.1
                    {
                        continue;
                    }
                    let x = ((horizontal - horizontal_range.0) * horizontal_scale) as usize;
                    let y = ((vertical_range.1 - vertical) * vertical_scale) as usize;
                    if x < width && y < height {
                        let cell = &mut histogram[y * width + x];
                        *cell = cell.saturating_add(1);
                    }
                }
            }));
        }
        for handle in handles {
            handle.join().expect("Lorenz density worker panicked");
        }
    });
    let mut histogram = vec![0_u32; width * height];
    for local in local_histograms {
        for (total, value) in histogram.iter_mut().zip(local) {
            *total = total.saturating_add(value);
        }
    }
    let maximum = f64::from(histogram.iter().copied().max().unwrap_or(1).max(1));
    for y in 0..height {
        for x in 0..width {
            let value = f64::from(histogram[y * width + x]);
            let intensity = (value + 1.0).ln() / (maximum + 1.0).ln();
            let (red, green, blue) = colormap_hot(intensity);
            framebuffer.set_rgba(x, y, red, green, blue, 255);
        }
    }
    framebuffer
}

/// Render the usual x-z butterfly projection.
#[must_use]
pub fn lorenz_default_frame(width: usize, height: usize, steps: usize) -> Framebuffer {
    let parameters = LorenzParams::default();
    let points = lorenz_trajectory(&parameters, Vec3::new(0.1, 0.0, 0.0), 0.005, steps);
    lorenz_density_render(&points, width, height, 0, 2, (-25.0, 25.0), (0.0, 50.0))
}

/// Mandelbrot viewport configuration.
#[derive(Clone, Copy, Debug)]
pub struct MandelbrotView {
    pub center_re: f64,
    pub center_im: f64,
    pub scale: f64,
    pub max_iter: u32,
}

impl Default for MandelbrotView {
    fn default() -> Self {
        Self {
            center_re: -0.75,
            center_im: 0.0,
            scale: 3.0,
            max_iter: 256,
        }
    }
}

fn mandel_interior_bailout(real: f64, imaginary: f64) -> bool {
    let x = real - 0.25;
    let q = x * x + imaginary * imaginary;
    q * (q + x) < 0.25 * imaginary * imaginary
        || (real + 1.0) * (real + 1.0) + imaginary * imaginary < 0.0625
}

/// Return the continuous Mandelbrot escape potential.
#[must_use]
pub fn mandelbrot_smooth(real: f64, imaginary: f64, max_iter: u32) -> f64 {
    if mandel_interior_bailout(real, imaginary) {
        return f64::from(max_iter);
    }
    let (mut zr, mut zi, mut iteration) = (0.0_f64, 0.0_f64, 0_u32);
    while iteration < max_iter {
        let real_squared = zr * zr;
        let imaginary_squared = zi * zi;
        if real_squared + imaginary_squared > 256.0 {
            let log_zn = (real_squared + imaginary_squared).ln() * 0.5;
            let nu = (log_zn / std::f64::consts::LN_2).ln() / std::f64::consts::LN_2;
            return f64::from(iteration) + 1.0 - nu;
        }
        zi = (2.0 * zr).mul_add(zi, imaginary);
        zr = real_squared - imaginary_squared + real;
        iteration += 1;
    }
    f64::from(max_iter)
}

/// Return the discrete Mandelbrot escape iteration.
#[must_use]
pub fn mandelbrot_escape(real: f64, imaginary: f64, max_iter: u32) -> u32 {
    if mandel_interior_bailout(real, imaginary) {
        return max_iter;
    }
    let (mut zr, mut zi, mut iteration) = (0.0_f64, 0.0_f64, 0_u32);
    while iteration < max_iter {
        let real_squared = zr * zr;
        let imaginary_squared = zi * zi;
        if real_squared + imaginary_squared > 4.0 {
            return iteration;
        }
        zi = (2.0 * zr).mul_add(zi, imaginary);
        zr = real_squared - imaginary_squared + real;
        iteration += 1;
    }
    max_iter
}

/// Render a Mandelbrot frame with row-tiled scoped worker threads.
///
/// # Panics
///
/// Panics if an internal worker panics.
#[must_use]
pub fn mandelbrot_render(
    view: &MandelbrotView,
    width: usize,
    height: usize,
    threads: usize,
) -> Framebuffer {
    let mut framebuffer = Framebuffer::new(width, height);
    if width == 0 || height == 0 {
        return framebuffer;
    }
    let aspect = width as f64 / height as f64;
    let half_width = view.scale * 0.5;
    let half_height = half_width / aspect;
    let real_minimum = view.center_re - half_width;
    let imaginary_maximum = view.center_im + half_height;
    let real_step = view.scale / width as f64;
    let imaginary_step = 2.0 * half_height / height as f64;
    let threads = if threads == 0 {
        default_threads()
    } else {
        threads
    }
    .max(1)
    .min(height);
    let rows_per_worker = height.div_ceil(threads);
    let row_bytes = width * 4;
    thread::scope(|scope| {
        let mut remaining = framebuffer.pixels.as_mut_slice();
        let mut handles = Vec::with_capacity(threads);
        for worker in 0..threads {
            let y0 = worker * rows_per_worker;
            if y0 >= height {
                break;
            }
            let y1 = (y0 + rows_per_worker).min(height);
            let length = (y1 - y0) * row_bytes;
            let (pixels, tail) = remaining.split_at_mut(length);
            remaining = tail;
            handles.push(scope.spawn(move || {
                for local_y in 0..(y1 - y0) {
                    let y = y0 + local_y;
                    let imaginary = imaginary_maximum - (y as f64 + 0.5) * imaginary_step;
                    for x in 0..width {
                        let real = real_minimum + (x as f64 + 0.5) * real_step;
                        let value = mandelbrot_smooth(real, imaginary, view.max_iter);
                        let (red, green, blue) = if value >= f64::from(view.max_iter) - 1e-9 {
                            (0, 0, 0)
                        } else {
                            let colour = (value * 0.05 + (value * 0.1).sin() * 0.1).fract().abs();
                            colormap_viridis(colour)
                        };
                        let offset = local_y * row_bytes + x * 4;
                        pixels[offset..offset + 4].copy_from_slice(&[red, green, blue, 255]);
                    }
                }
            }));
        }
        for handle in handles {
            handle.join().expect("Mandelbrot worker panicked");
        }
    });
    framebuffer
}

/// Return the deep-zoom Seahorse Valley view used by the diagnostic renderer.
#[must_use]
pub fn mandelbrot_seahorse_view(max_iter: u32) -> MandelbrotView {
    MandelbrotView {
        center_re: -0.743_643_887_037_151,
        center_im: 0.131_825_904_205_330,
        scale: 0.002_287_640_704_011_261_6,
        max_iter,
    }
}

/// Result of a diagnostic kernel benchmark.
#[derive(Clone, Debug)]
pub struct ChaosBenchmark {
    pub name: &'static str,
    pub steps_or_pixels: u64,
    pub elapsed_ns: u128,
    pub rate: f64,
}

/// Benchmark a parallel Lorenz ensemble.
#[must_use]
pub fn bench_lorenz(steps: usize, threads: usize) -> ChaosBenchmark {
    let threads = threads.max(1);
    let seeds = (0..threads)
        .map(|index| {
            let value = index as f64 * 0.017;
            Vec3::new(0.1 + value, value * 0.3, value * 0.1)
        })
        .collect::<Vec<_>>();
    let started = std::time::Instant::now();
    let points = lorenz_ensemble_parallel(LorenzParams::default(), &seeds, 0.005, steps, threads);
    let elapsed_ns = started.elapsed().as_nanos();
    let seconds = elapsed_ns as f64 / 1e9;
    ChaosBenchmark {
        name: "lorenz_rk4",
        steps_or_pixels: points.len() as u64,
        elapsed_ns,
        rate: if seconds > 0.0 {
            points.len() as f64 / seconds
        } else {
            0.0
        },
    }
}

/// Benchmark a Mandelbrot render.
#[must_use]
pub fn bench_mandelbrot(
    width: usize,
    height: usize,
    max_iter: u32,
    threads: usize,
) -> ChaosBenchmark {
    let started = std::time::Instant::now();
    let frame = mandelbrot_render(
        &MandelbrotView {
            max_iter,
            ..MandelbrotView::default()
        },
        width,
        height,
        threads,
    );
    let elapsed_ns = started.elapsed().as_nanos();
    let seconds = elapsed_ns as f64 / 1e9;
    let pixels = frame.width.saturating_mul(frame.height);
    ChaosBenchmark {
        name: "mandelbrot",
        steps_or_pixels: pixels as u64,
        elapsed_ns,
        rate: if seconds > 0.0 {
            pixels as f64 / seconds
        } else {
            0.0
        },
    }
}

/// Combine a Mandelbrot background with a Lorenz-density glow.
#[must_use]
pub fn composite_splash(width: usize, height: usize) -> Framebuffer {
    let mut base = mandelbrot_render(
        &MandelbrotView {
            max_iter: 192,
            ..MandelbrotView::default()
        },
        width,
        height,
        0,
    );
    let lorenz = lorenz_default_frame(width, height, 200_000);
    for (base_pixel, lorenz_pixel) in base
        .pixels
        .chunks_exact_mut(4)
        .zip(lorenz.pixels.chunks_exact(4))
    {
        let glow =
            (f32::from(lorenz_pixel[0]) + f32::from(lorenz_pixel[1]) + f32::from(lorenz_pixel[2]))
                / (3.0 * 255.0);
        if glow > 0.05 {
            for index in 0..3 {
                base_pixel[index] = (f32::from(base_pixel[index]) * (1.0 - glow)
                    + f32::from(lorenz_pixel[index]) * glow)
                    .clamp(0.0, 255.0) as u8;
            }
        }
    }
    base
}

/// Render and write a diagnostic splash image.
///
/// # Errors
///
/// Returns an I/O error when the PPM destination cannot be created or written.
pub fn run_splash_to(path: &str, width: usize, height: usize) -> std::io::Result<ChaosBenchmark> {
    let started = std::time::Instant::now();
    let frame = composite_splash(width, height);
    frame.write_ppm(path)?;
    Ok(ChaosBenchmark {
        name: "composite_splash",
        steps_or_pixels: width.saturating_mul(height) as u64,
        elapsed_ns: started.elapsed().as_nanos(),
        rate: 0.0,
    })
}

/// Render a journal-friendly ANSI Lorenz banner.
#[must_use]
pub fn journal_banner(columns: usize, rows: usize) -> String {
    let width = columns.clamp(16, 120);
    let height = rows.clamp(4, 40) * 2;
    let frame = lorenz_default_frame(width, height, 80_000);
    format!("rustd :: Lorenz attractor\n{}", frame.to_ansi_halfblocks())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lorenz_stays_bounded() {
        let parameters = LorenzParams::default();
        let mut state = Vec3::new(1.0, 1.0, 1.0);
        for _ in 0..50_000 {
            state = lorenz_rk4_step(&parameters, state, 0.01);
            assert!(state.x.is_finite() && state.y.is_finite() && state.z.is_finite());
            assert!(state.x.abs() < 100.0 && state.z.abs() < 100.0);
        }
    }

    #[test]
    fn mandelbrot_classifies_known_points() {
        assert!((mandelbrot_smooth(0.0, 0.0, 100) - 100.0).abs() < f64::EPSILON);
        assert!(mandelbrot_escape(2.0, 2.0, 100) < 5);
    }

    #[test]
    fn render_and_ensemble_smoke() {
        let frame = mandelbrot_render(&MandelbrotView::default(), 64, 48, 2);
        assert_eq!(frame.pixels.len(), 64 * 48 * 4);
        let lorenz = lorenz_default_frame(64, 48, 10_000);
        assert_eq!(lorenz.pixels.len(), 64 * 48 * 4);
        let seeds = [Vec3::new(0.1, 0.0, 0.0), Vec3::new(0.2, 0.0, 0.0)];
        assert_eq!(
            lorenz_ensemble_parallel(LorenzParams::default(), &seeds, 0.01, 100, 2).len(),
            200
        );
    }
}
