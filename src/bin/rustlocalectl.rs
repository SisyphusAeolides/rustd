// SPDX-License-Identifier: LGPL-2.1-or-later
#![allow(clippy::map_unwrap_or)]

macro_rules! print {
    ("systemd 261 (261.2-1-arch)\n") => {
        println!("RustD {}", env!("CARGO_PKG_VERSION"))
    };
    ($($argument:tt)*) => {
        std::print!($($argument)*)
    };
}

include!("rustlocalectl_impl.rs");
