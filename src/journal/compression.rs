// SPDX-License-Identifier: LGPL-2.1-or-later
//! Safe decoding for compressed journal DATA payloads.
//!
//! Upstream reference: `src/basic/compress.c` and
//! `src/libsystemd/sd-journal/journal-def.h` (v261).

use crate::ffi::journal::rustd_journal_decompress_payload;

const DATA_SIZE_MAX: usize = 768 * 1024 * 1024;

fn negative_errno(errno: i32) -> libc::ssize_t {
    -libc::ssize_t::try_from(errno).expect("Linux errno fits in ssize_t")
}

/// Decode an upstream journal DATA payload whose object `flags` select XZ,
/// LZ4, or ZSTD compression.
///
/// # Errors
/// Returns an error for malformed streams, unsupported flag combinations,
/// missing runtime decoder libraries, allocation failure, or size overflow.
pub fn decompress_payload(flags: u8, source: &[u8]) -> anyhow::Result<Vec<u8>> {
    if source.is_empty() {
        anyhow::bail!("compressed journal payload is empty");
    }

    // Safety: source is valid for source.len() bytes; a null destination asks
    // the C decoder for an encoded output size when the format provides one.
    let queried = unsafe {
        rustd_journal_decompress_payload(
            flags,
            source.as_ptr(),
            source.len(),
            std::ptr::null_mut(),
            0,
        )
    };
    let mut capacity = if queried >= 0 {
        usize::try_from(queried).map_err(|_| anyhow::anyhow!("decoded size does not fit usize"))?
    } else if queried == negative_errno(libc::ENODATA) {
        source
            .len()
            .checked_mul(2)
            .unwrap_or(DATA_SIZE_MAX)
            .clamp(1024, DATA_SIZE_MAX)
    } else {
        anyhow::bail!(
            "compressed journal size query failed with errno {}",
            -queried
        );
    };

    if capacity > DATA_SIZE_MAX {
        anyhow::bail!("decoded journal payload exceeds upstream DATA_SIZE_MAX");
    }

    loop {
        let mut output = Vec::<u8>::new();
        output
            .try_reserve_exact(capacity)
            .map_err(|error| anyhow::anyhow!("cannot reserve {capacity} decoded bytes: {error}"))?;
        // Safety: output has at least `capacity` writable bytes of allocation;
        // the C decoder never writes beyond the supplied destination size.
        let decoded = unsafe {
            rustd_journal_decompress_payload(
                flags,
                source.as_ptr(),
                source.len(),
                output.as_mut_ptr(),
                capacity,
            )
        };
        if decoded >= 0 {
            let decoded = usize::try_from(decoded)
                .map_err(|_| anyhow::anyhow!("decoded length does not fit usize"))?;
            if decoded > capacity {
                anyhow::bail!("decoder returned a length larger than its destination");
            }
            // Safety: the decoder initialized exactly `decoded` bytes and the
            // value was checked not to exceed the vector allocation.
            unsafe { output.set_len(decoded) };
            return Ok(output);
        }
        if decoded != negative_errno(libc::ENOBUFS) {
            anyhow::bail!("compressed journal decode failed with errno {}", -decoded);
        }
        if capacity >= DATA_SIZE_MAX {
            anyhow::bail!("decoded journal payload exceeds upstream DATA_SIZE_MAX");
        }
        capacity = capacity.saturating_mul(2).min(DATA_SIZE_MAX);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_payload() {
        assert!(decompress_payload(1, &[]).is_err());
    }

    #[test]
    fn rejects_unknown_compression_flag() {
        assert!(decompress_payload(8, b"not-compressed").is_err());
    }
}
