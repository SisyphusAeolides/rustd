// SPDX-License-Identifier: LGPL-2.1-or-later
//! `systemd-reply-password` v261 compatibility helper.

use std::env;
use std::ffi::{OsStr, OsString};
use std::io::{self, Read, Write};
use std::os::linux::net::SocketAddrExt;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::{SocketAddr, UnixDatagram};
use std::path::Path;

const LONG_LINE_MAX: usize = 1024 * 1024;
const SUN_PATH_SIZE: usize = 108;

#[derive(Debug)]
struct SecretBytes(Vec<u8>);

impl Drop for SecretBytes {
    fn drop(&mut self) {
        for byte in &mut self.0 {
            // SAFETY: `byte` is a valid unique pointer. A volatile store ensures
            // password bytes are erased rather than optimized out.
            unsafe { std::ptr::write_volatile(byte, 0) };
        }
    }
}

fn main() {
    let arguments: Vec<OsString> = env::args_os().collect();
    if let Err(error) = run(&arguments, &mut io::stdin()) {
        let _ = io::stderr().lock().write_all(&error);
        std::process::exit(1);
    }
}

fn run(arguments: &[OsString], input: &mut impl Read) -> Result<(), Vec<u8>> {
    if arguments.len() != 3 {
        return Err(b"Wrong number of arguments.\n".to_vec());
    }

    let mode = arguments[1].as_os_str().as_bytes();
    let packet = match mode {
        b"1" => read_password(input)?,
        b"0" => SecretBytes(vec![b'-']),
        _ => {
            let mut error = b"Invalid first argument ".to_vec();
            error.extend_from_slice(mode);
            error.push(b'\n');
            return Err(error);
        }
    };

    send_packet(arguments[2].as_os_str(), &packet.0)
}

fn read_password(input: &mut impl Read) -> Result<SecretBytes, Vec<u8>> {
    let mut line = SecretBytes(Vec::new());
    let mut bytes_read = 0_usize;
    let mut previous_eol = 0_u8;

    loop {
        if line.0.len() >= LONG_LINE_MAX {
            return Err(b"Failed to read password: No buffer space available\n".to_vec());
        }

        let mut byte = [0_u8];
        let count = input.read(&mut byte).map_err(|error| {
            format!("Failed to read password: {}\n", io_error_text(&error)).into_bytes()
        })?;
        if count == 0 {
            break;
        }

        let eol = match byte[0] {
            b'\n' => 1,
            b'\r' => 2,
            0 => 4,
            _ => 0,
        };
        if previous_eol & 4 != 0
            || (eol == 0 && previous_eol != 0)
            || (eol != 0 && previous_eol & eol != 0)
        {
            break;
        }

        bytes_read += 1;
        if eol != 0 {
            previous_eol |= eol;
        } else {
            line.0.push(byte[0]);
        }
    }

    if bytes_read == 0 {
        return Err(b"Got EOF while reading password.\n".to_vec());
    }

    let mut packet = Vec::with_capacity(line.0.len() + 2);
    packet.push(b'+');
    packet.extend_from_slice(&line.0);
    packet.push(0);
    Ok(SecretBytes(packet))
}

fn send_packet(socket_name: &OsStr, packet: &[u8]) -> Result<(), Vec<u8>> {
    let name = socket_name.as_bytes();
    if name.len() < 2
        || name.len() + 1 > SUN_PATH_SIZE
        || !matches!(name.first(), Some(b'/' | b'@'))
    {
        let mut error = b"Specified socket path for AF_UNIX socket invalid, refusing: ".to_vec();
        error.extend_from_slice(name);
        error.push(b'\n');
        return Err(error);
    }

    let address = if name[0] == b'@' {
        SocketAddr::from_abstract_name(&name[1..])
    } else {
        SocketAddr::from_pathname(Path::new(socket_name))
    }
    .map_err(|_| {
        let mut error = b"Specified socket path for AF_UNIX socket invalid, refusing: ".to_vec();
        error.extend_from_slice(name);
        error.push(b'\n');
        error
    })?;

    let socket = UnixDatagram::unbound()
        .map_err(|error| format!("socket() failed: {}\n", io_error_text(&error)).into_bytes())?;
    socket
        .set_nonblocking(true)
        .map_err(|error| format!("socket() failed: {}\n", io_error_text(&error)).into_bytes())?;
    socket
        .send_to_addr(packet, &address)
        .map_err(|error| format!("Failed to send: {}\n", io_error_text(&error)).into_bytes())?;
    Ok(())
}

fn io_error_text(error: &io::Error) -> String {
    let text = error.to_string();
    text.rfind(" (os error ").map_or(text.clone(), |index| {
        if text.ends_with(')') {
            text[..index].to_owned()
        } else {
            text
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_line_recognizes_all_v261_delimiters() {
        for input in [
            b"password\nrest".as_slice(),
            b"password\rrest",
            b"password\0rest",
            b"password\r\nrest",
            b"password\n\r\0rest",
        ] {
            assert_eq!(read_password(&mut &*input).unwrap().0, b"+password\0");
        }
    }

    #[test]
    fn eof_and_limit_match_read_line_contract() {
        assert_eq!(
            read_password(&mut &[][..]).unwrap_err(),
            b"Got EOF while reading password.\n"
        );
        let input = vec![b'x'; LONG_LINE_MAX];
        assert_eq!(
            read_password(&mut &*input).unwrap_err(),
            b"Failed to read password: No buffer space available\n"
        );
    }
}
