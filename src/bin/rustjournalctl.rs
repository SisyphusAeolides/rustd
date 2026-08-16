// SPDX-License-Identifier: LGPL-2.1-or-later

macro_rules! concat {
    ($($ignored:tt)*) => {
        std::concat!("RustD ", env!("CARGO_PKG_VERSION"), "\n")
    };
}

include!("rustjournalctl_impl.rs");
