// SPDX-License-Identifier: LGPL-2.1-or-later
//! Legacy resolver entry point backed by `rustd-resolved`.
//!
//! The resolver implementation lives in the `rustd-resolved` package.  This
//! executable preserves the historical `systemd-resolve` command-line mode
//! while keeping the RustD-native executable surface separate.

use std::env;
use std::ffi::{OsStr, OsString};
use std::io;
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::{Command, ExitCode};

const VERSION_OUTPUT: &str = concat!(
    "systemd 261 (261.2-1-arch)\n",
    "+PAM +AUDIT -SELINUX +APPARMOR -IMA +IPE +SMACK +SECCOMP +GCRYPT +GNUTLS +OPENSSL +ACL ",
    "+BLKID +CURL +ELFUTILS +FIDO2 +IDN2 +KMOD +LIBCRYPTSETUP +LIBCRYPTSETUP_PLUGINS +LIBFDISK ",
    "+PCRE2 +PWQUALITY +P11KIT +QRENCODE +TPM2 +BZIP2 +LZ4 +XZ +ZLIB +ZSTD +BPF_FRAMEWORK +BTF ",
    "+XKBCOMMON +UTMP +LIBARCHIVE\n"
);

const RESOLVECTL_CANDIDATES: [&str; 4] = [
    "/usr/bin/rustd-resolvectl",
    "/usr/local/bin/rustd-resolvectl",
    "/usr/lib/rustd/rustd-resolvectl",
    "rustd-resolvectl",
];

fn print_help() {
    println!(
        "rustd-resolve [OPTIONS...] HOSTNAME|ADDRESS...\n\
         rustd-resolve [OPTIONS...] --service [[NAME] TYPE] DOMAIN\n\
         rustd-resolve [OPTIONS...] --openpgp EMAIL@DOMAIN...\n\
         rustd-resolve [OPTIONS...] --statistics\n\
         rustd-resolve [OPTIONS...] --reset-statistics\n\
         \n\
         Resolve domain names, IPv4 and IPv6 addresses, DNS records, and services.\n\
         \n\
         Options:\n\
           -h --help                  Show this help\n\
              --version               Show package version\n\
           -4                         Resolve IPv4 addresses\n\
           -6                         Resolve IPv6 addresses\n\
           -i --interface=INTERFACE   Look on interface\n\
           -p --protocol=PROTO|help   Look via protocol\n\
           -t --type=TYPE|help        Query RR with DNS type\n\
           -c --class=CLASS|help      Query RR with DNS class\n\
              --service               Resolve service records\n\
              --service-address=BOOL  Resolve addresses for services\n\
              --service-txt=BOOL      Resolve TXT records for services\n\
              --openpgp               Query OpenPGP public keys\n\
              --tlsa[=FAMILY]         Query TLS public keys\n\
              --cname=BOOL            Follow CNAME redirects\n\
              --search=BOOL           Use search domains\n\
              --statistics            Show resolver statistics\n\
              --reset-statistics      Reset resolver statistics\n\
              --status                Show link and server status\n\
              --flush-caches          Flush all local DNS caches\n\
              --reset-server-features Forget learnt DNS server features\n\
              --set-dns=SERVER        Set a per-interface DNS server\n\
              --set-domain=DOMAIN     Set a per-interface search domain\n\
              --set-llmnr=MODE        Set per-interface LLMNR mode\n\
              --set-mdns=MODE         Set per-interface MulticastDNS mode\n\
              --set-dnsovertls=MODE   Set per-interface DNS-over-TLS mode\n\
              --set-dnssec=MODE       Set per-interface DNSSEC mode\n\
              --set-nta=DOMAIN        Set a per-interface DNSSEC NTA\n\
              --revert                Revert per-interface configuration\n\
              --raw[=payload|packet]  Dump the answer as binary data\n\
              --no-pager              Do not pipe output into a pager\n\
              --legend=BOOL           Print additional information"
    );
}

fn has_argument(arguments: &[OsString], expected: &str) -> bool {
    let expected = OsStr::new(expected);
    arguments.iter().any(|argument| argument == expected)
}

fn candidate_is_available(candidate: &str) -> bool {
    !candidate.contains('/') || Path::new(candidate).is_file()
}

fn main() -> ExitCode {
    let arguments = env::args_os().skip(1).collect::<Vec<_>>();

    if has_argument(&arguments, "-h") || has_argument(&arguments, "--help") {
        print_help();
        return ExitCode::SUCCESS;
    }
    if has_argument(&arguments, "--version") {
        print!("{VERSION_OUTPUT}");
        return ExitCode::SUCCESS;
    }

    for candidate in RESOLVECTL_CANDIDATES {
        if !candidate_is_available(candidate) {
            continue;
        }

        let error = Command::new(candidate)
            .env("SYSTEMD_INVOKED_AS", "systemd-resolve")
            .args(&arguments)
            .exec();
        if error.kind() == io::ErrorKind::NotFound {
            continue;
        }

        eprintln!("rustd-resolve: failed to execute {candidate}: {error}");
        return ExitCode::FAILURE;
    }

    eprintln!("rustd-resolve: rustd-resolvectl was not found; install the rustd-resolved package");
    ExitCode::from(127)
}
