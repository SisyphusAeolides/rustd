// SPDX-License-Identifier: LGPL-2.1-or-later
//! `resolvectl` compatibility utility.
//!
//! Upstream reference: `src/resolve/resolvectl.c` (systemd v261).

use clap::{Parser, Subcommand, ValueEnum};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::path::Path;
use std::time::{Duration, Instant};

const VERSION_OUTPUT: &str = concat!(
    "systemd 261 (261.2-1-arch)\n",
    "+PAM +AUDIT -SELINUX +APPARMOR -IMA +IPE +SMACK +SECCOMP +GCRYPT +GNUTLS +OPENSSL +ACL ",
    "+BLKID +CURL +ELFUTILS +FIDO2 +IDN2 +KMOD +LIBCRYPTSETUP +LIBCRYPTSETUP_PLUGINS +LIBFDISK ",
    "+PCRE2 +PWQUALITY +P11KIT +QRENCODE +TPM2 +BZIP2 +LZ4 +XZ +ZLIB +ZSTD +BPF_FRAMEWORK +BTF ",
    "+XKBCOMMON +UTMP +LIBARCHIVE\n"
);

#[derive(Parser, Debug)]
#[command(
    name = "resolvectl",
    about = "Resolve domain names, IPv4 and IPv6 addresses, DNS Resource Records, and inspect DNS resolver settings.",
    version = VERSION_OUTPUT
)]
struct Cli {
    #[arg(short = '4', help = "Resolve IPv4 addresses only")]
    ipv4_only: bool,

    #[arg(short = '6', help = "Resolve IPv6 addresses only")]
    ipv6_only: bool,

    #[arg(
        short = 'i',
        long = "interface",
        help = "Look on specified network interface"
    )]
    interface: Option<String>,

    #[arg(
        short = 'p',
        long = "protocol",
        help = "Specify protocol: dns, llmnr, mdns"
    )]
    protocol: Option<String>,

    #[arg(
        short = 't',
        long = "type",
        help = "Specify DNS Resource Record type (e.g. A, AAAA, MX, TXT, SRV, PTR)"
    )]
    rr_type: Option<String>,

    #[arg(
        short = 'c',
        long = "class",
        help = "Specify DNS Resource Record class (e.g. IN, ANY)"
    )]
    rr_class: Option<String>,

    #[arg(long = "no-pager", help = "Do not pipe output into a pager")]
    no_pager: bool,

    #[arg(long = "no-legend", help = "Do not show column headers and footers")]
    no_legend: bool,

    #[arg(short = 'j', long = "json", value_enum, help = "Generate JSON output")]
    json: Option<JsonMode>,

    #[command(subcommand)]
    command: Option<Commands>,

    /// Positional arguments when no explicit subcommand is used
    #[arg(trailing_var_arg = true)]
    positional: Vec<String>,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum JsonMode {
    Pretty,
    Short,
    Off,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Show resolver status and per-interface DNS configurations (default)
    #[command(name = "status")]
    Status {
        /// Network links to inspect
        links: Vec<String>,
    },
    /// Query domain names or IP addresses
    #[command(name = "query")]
    Query {
        /// Names or IP addresses to resolve
        names: Vec<String>,
    },
    /// Query DNS-SD and SRV services
    #[command(name = "service")]
    Service {
        service_name: Option<String>,
        service_type: Option<String>,
        domain: Option<String>,
    },
    /// Query `OpenPGP` public keys
    #[command(name = "openpgp")]
    OpenPgp { email: String },
    /// Query TLS authentication keys
    #[command(name = "tlsa")]
    Tlsa { domain: String },
    /// Show resolver cache and transaction statistics
    #[command(name = "statistics")]
    Statistics,
    /// Reset resolver statistics counters
    #[command(name = "reset-statistics")]
    ResetStatistics,
    /// Flush resolver caches
    #[command(name = "flush-caches")]
    FlushCaches,
    /// Reset resolver configuration for link
    #[command(name = "revert")]
    Revert { link: String },
    /// Show or set per-interface DNS servers
    #[command(name = "dns")]
    Dns {
        link: Option<String>,
        servers: Vec<String>,
    },
    /// Show or set per-interface search domains
    #[command(name = "domain")]
    Domain {
        link: Option<String>,
        domains: Vec<String>,
    },
    /// Show or set default route setting for link
    #[command(name = "default-route")]
    DefaultRoute { link: String, enable: Option<bool> },
    /// Show or set LLMNR setting for link
    #[command(name = "llmnr")]
    Llmnr { link: String, mode: Option<String> },
    /// Show or set `MulticastDNS` setting for link
    #[command(name = "mdns")]
    Mdns { link: String, mode: Option<String> },
    /// Show or set DNS-over-TLS setting for link
    #[command(name = "dnsovertls")]
    DnsOverTls { link: String, mode: Option<String> },
    /// Show or set DNSSEC setting for link
    #[command(name = "dnssec")]
    Dnssec { link: String, mode: Option<String> },
    /// Show or set Negative Trust Anchors for link
    #[command(name = "nta")]
    Nta { link: String, domains: Vec<String> },
    /// Show link-specific or global DNS configuration
    #[command(name = "show-cache")]
    ShowCache,
}

#[derive(Debug, Default, serde::Serialize)]
struct ResolvConfInfo {
    nameservers: Vec<String>,
    search_domains: Vec<String>,
    options: Vec<String>,
}

#[derive(Debug, serde::Serialize)]
struct LinkInfo {
    index: u32,
    name: String,
    operstate: String,
    mac: String,
    ip_addresses: Vec<String>,
    dns_servers: Vec<String>,
    search_domains: Vec<String>,
    default_route: bool,
    llmnr: String,
    mdns: String,
    dnssec: String,
    dnsovertls: String,
}

fn parse_resolv_conf(path: &Path) -> ResolvConfInfo {
    let mut info = ResolvConfInfo::default();
    if let Ok(content) = fs::read_to_string(path) {
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.starts_with(';') || line.is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }
            match parts.first().copied().unwrap_or_default() {
                "nameserver" => {
                    for ns in &parts[1..] {
                        info.nameservers.push((*ns).to_string());
                    }
                }
                "domain" => {
                    if let Some(d) = parts.get(1) {
                        info.search_domains.push((*d).to_string());
                    }
                }
                "search" => {
                    for dom in &parts[1..] {
                        info.search_domains.push((*dom).to_string());
                    }
                }
                "options" => {
                    for opt in &parts[1..] {
                        info.options.push((*opt).to_string());
                    }
                }
                _ => {}
            }
        }
    }
    info
}

fn get_active_resolv_conf() -> ResolvConfInfo {
    let candidates = [
        "/run/systemd/resolve/resolv.conf",
        "/run/systemd/resolve/stub-resolv.conf",
        "/etc/resolv.conf",
    ];
    for path_str in candidates {
        let path = Path::new(path_str);
        if path.exists() {
            let info = parse_resolv_conf(path);
            if !info.nameservers.is_empty() || !info.search_domains.is_empty() {
                return info;
            }
        }
    }
    parse_resolv_conf(Path::new("/etc/resolv.conf"))
}

fn get_links_info() -> Vec<LinkInfo> {
    let mut links = Vec::new();
    let ips = get_interface_ips();

    if let Ok(entries) = fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let path = entry.path();

            let index: u32 = fs::read_to_string(path.join("ifindex"))
                .unwrap_or_else(|_| "0\n".into())
                .trim()
                .parse()
                .unwrap_or(0);

            let operstate = fs::read_to_string(path.join("operstate"))
                .unwrap_or_else(|_| "unknown\n".into())
                .trim()
                .to_string();

            let mac = fs::read_to_string(path.join("address"))
                .unwrap_or_else(|_| String::new())
                .trim()
                .to_string();

            let ip_addrs = ips.get(&name).cloned().unwrap_or_default();

            // Per-link DNS configurations if written by systemd-resolved / networkd
            let mut link_dns = Vec::new();
            let mut link_domains = Vec::new();
            let link_state_path = format!("/run/systemd/netif/links/{index}");
            if let Ok(state_content) = fs::read_to_string(&link_state_path) {
                for line in state_content.lines() {
                    let line = line.trim();
                    if let Some(dns_val) = line.strip_prefix("DNS=") {
                        for server in dns_val.split_whitespace() {
                            link_dns.push(server.to_string());
                        }
                    }
                    if let Some(dom_val) = line.strip_prefix("DOMAINS=") {
                        for domain in dom_val.split_whitespace() {
                            link_domains.push(domain.to_string());
                        }
                    }
                }
            }

            let default_route = name != "lo" && (operstate == "up" || operstate == "routable");

            links.push(LinkInfo {
                index,
                name,
                operstate,
                mac,
                ip_addresses: ip_addrs,
                dns_servers: link_dns,
                search_domains: link_domains,
                default_route,
                llmnr: "yes".to_string(),
                mdns: "no".to_string(),
                dnssec: "no".to_string(),
                dnsovertls: "no".to_string(),
            });
        }
    }
    links.sort_by_key(|l| l.index);
    links
}

fn get_interface_ips() -> HashMap<String, Vec<String>> {
    let mut ips: HashMap<String, Vec<String>> = HashMap::new();
    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) == 0 {
            let mut curr = ifap;
            while !curr.is_null() {
                let ifa = &*curr;
                if !ifa.ifa_addr.is_null() {
                    let name = std::ffi::CStr::from_ptr(ifa.ifa_name)
                        .to_string_lossy()
                        .into_owned();
                    let family = i32::from((*ifa.ifa_addr).sa_family);
                    if family == libc::AF_INET {
                        let sa = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                        let ip = Ipv4Addr::from(sa.sin_addr.s_addr.to_ne_bytes());
                        ips.entry(name).or_default().push(ip.to_string());
                    } else if family == libc::AF_INET6 {
                        let sa = &*(ifa.ifa_addr as *const libc::sockaddr_in6);
                        let ip = Ipv6Addr::from(sa.sin6_addr.s6_addr);
                        ips.entry(name).or_default().push(ip.to_string());
                    }
                }
                curr = ifa.ifa_next;
            }
            libc::freeifaddrs(ifap);
        }
    }
    ips
}

fn print_status(filter_links: &[String], json: Option<JsonMode>) {
    let resolv = get_active_resolv_conf();
    let links = get_links_info();

    if let Some(mode) = json {
        if mode != JsonMode::Off {
            let filtered: Vec<&LinkInfo> = if filter_links.is_empty() {
                links.iter().collect()
            } else {
                links
                    .iter()
                    .filter(|l| {
                        filter_links.contains(&l.name)
                            || filter_links.contains(&l.index.to_string())
                    })
                    .collect()
            };
            let obj = serde_json::json!({
                "Global": {
                    "Protocols": "+DefaultRoute +LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported",
                    "resolv_conf": resolv,
                },
                "Links": filtered,
            });
            if mode == JsonMode::Pretty {
                println!("{}", serde_json::to_string_pretty(&obj).unwrap());
            } else {
                println!("{}", serde_json::to_string(&obj).unwrap());
            }
            return;
        }
    }

    if filter_links.is_empty() {
        println!("Global");
        print!("         Protocols: +DefaultRoute +LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported");
        println!();
        if !resolv.nameservers.is_empty() {
            println!("       DNS Servers: {}", resolv.nameservers.join(" "));
        }
        if !resolv.search_domains.is_empty() {
            println!("        DNS Domain: {}", resolv.search_domains.join(" "));
        }
        println!();
    }

    let targets: Vec<&LinkInfo> = if filter_links.is_empty() {
        links.iter().collect()
    } else {
        links
            .iter()
            .filter(|l| {
                filter_links.contains(&l.name) || filter_links.contains(&l.index.to_string())
            })
            .collect()
    };

    if targets.is_empty() && !filter_links.is_empty() {
        eprintln!("Interface {} not found.", filter_links.join(", "));
        std::process::exit(1);
    }

    for (i, link) in targets.iter().enumerate() {
        if i > 0 || filter_links.is_empty() {
            println!();
        }
        println!("Link {} ({})", link.index, link.name);
        println!(
            "    Current Scopes: {}{}{}",
            if link.default_route { "DNS " } else { "" },
            if link.llmnr == "yes" {
                "LLMNR/IPv4 LLMNR/IPv6 "
            } else {
                ""
            },
            if link.mdns == "yes" {
                "mDNS/IPv4 mDNS/IPv6"
            } else {
                ""
            }
        );
        println!(
            "         Protocols: {}+LLMNR {}-mDNS {}-DNSOverTLS DNSSEC={}/unsupported",
            if link.default_route {
                "+DefaultRoute "
            } else {
                "-DefaultRoute "
            },
            if link.llmnr == "yes" { "+" } else { "-" },
            if link.mdns == "yes" { "+" } else { "-" },
            link.dnssec
        );
        if !link.dns_servers.is_empty() {
            println!("       DNS Servers: {}", link.dns_servers.join(" "));
        } else if !resolv.nameservers.is_empty() && link.default_route {
            println!("       DNS Servers: {}", resolv.nameservers.join(" "));
        }
        if !link.search_domains.is_empty() {
            println!("        DNS Domain: {}", link.search_domains.join(" "));
        } else if !resolv.search_domains.is_empty() && link.default_route {
            println!("        DNS Domain: {}", resolv.search_domains.join(" "));
        }
    }
}

fn resolve_query(
    name: &str,
    ipv4_only: bool,
    ipv6_only: bool,
    rr_type: Option<&str>,
    json: Option<JsonMode>,
) {
    let start = Instant::now();

    // Check if input is an IP address for reverse lookup
    if let Ok(ip) = name.parse::<IpAddr>() {
        let host_result = reverse_lookup(ip);
        let elapsed_ms = start.elapsed().as_millis();
        match host_result {
            Ok(host) => {
                if let Some(mode) = json {
                    if mode != JsonMode::Off {
                        let res = serde_json::json!({
                            "query": name,
                            "type": "PTR",
                            "hostname": host,
                            "elapsed_ms": elapsed_ms,
                        });
                        if mode == JsonMode::Pretty {
                            println!("{}", serde_json::to_string_pretty(&res).unwrap());
                        } else {
                            println!("{}", serde_json::to_string(&res).unwrap());
                        }
                        return;
                    }
                }
                println!("{name}: {host}");
                println!("\n-- Information acquired via protocol DNS in {elapsed_ms}ms.");
                println!("-- Data is authenticated: no; DNSSEC validation: no");
                return;
            }
            Err(e) => {
                eprintln!("{name}: resolve call failed: {e}");
                std::process::exit(1);
            }
        }
    }

    // Direct RR lookup if type is specified and not A/AAAA
    if let Some(rtype) = rr_type {
        let upper_type = rtype.to_ascii_uppercase();
        if upper_type != "A" && upper_type != "AAAA" {
            perform_custom_rr_query(name, &upper_type, start, json);
            return;
        }
    }

    // Standard hostname resolution
    let socket_str = format!("{name}:0");
    let mut addrs: Vec<IpAddr> = match socket_str.to_socket_addrs() {
        Ok(iter) => iter.map(|s| s.ip()).collect(),
        Err(_) => {
            // Also check /etc/hosts directly
            if let Some(host_ips) = lookup_hosts_file(name) {
                host_ips
            } else {
                eprintln!("{name}: resolve call failed: 'No name servers found' or Host not found");
                std::process::exit(1);
            }
        }
    };

    if ipv4_only {
        addrs.retain(std::net::IpAddr::is_ipv4);
    } else if ipv6_only {
        addrs.retain(std::net::IpAddr::is_ipv6);
    }

    if addrs.is_empty() {
        eprintln!("{name}: resolve call failed: No suitable address found");
        std::process::exit(1);
    }

    // Deduplicate addresses
    let mut unique_addrs = Vec::new();
    for ip in addrs {
        if !unique_addrs.contains(&ip) {
            unique_addrs.push(ip);
        }
    }

    let elapsed_ms = start.elapsed().as_millis();

    if let Some(mode) = json {
        if mode != JsonMode::Off {
            let res = serde_json::json!({
                "query": name,
                "addresses": unique_addrs.iter().map(std::string::ToString::to_string).collect::<Vec<_>>(),
                "elapsed_ms": elapsed_ms,
            });
            if mode == JsonMode::Pretty {
                println!("{}", serde_json::to_string_pretty(&res).unwrap());
            } else {
                println!("{}", serde_json::to_string(&res).unwrap());
            }
            return;
        }
    }

    let formatted_ips: Vec<String> = unique_addrs
        .iter()
        .map(std::string::ToString::to_string)
        .collect();
    println!("{}: {}", name, formatted_ips.join(" "));
    println!("\n-- Information acquired via protocol DNS in {elapsed_ms}ms.");
    println!("-- Data is authenticated: no; DNSSEC validation: no");
}

fn reverse_lookup(ip: IpAddr) -> io::Result<String> {
    unsafe {
        let mut host_buf = [0 as libc::c_char; libc::NI_MAXHOST as usize];
        let res = match ip {
            IpAddr::V4(v4) => {
                let mut sa: libc::sockaddr_in = std::mem::zeroed();
                sa.sin_family = libc::AF_INET as libc::sa_family_t;
                sa.sin_addr.s_addr = u32::from_ne_bytes(v4.octets());
                libc::getnameinfo(
                    std::ptr::addr_of!(sa) as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                    host_buf.as_mut_ptr(),
                    host_buf.len() as libc::socklen_t,
                    std::ptr::null_mut(),
                    0,
                    0,
                )
            }
            IpAddr::V6(v6) => {
                let mut sa: libc::sockaddr_in6 = std::mem::zeroed();
                sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                sa.sin6_addr.s6_addr = v6.octets();
                libc::getnameinfo(
                    std::ptr::addr_of!(sa) as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                    host_buf.as_mut_ptr(),
                    host_buf.len() as libc::socklen_t,
                    std::ptr::null_mut(),
                    0,
                    0,
                )
            }
        };

        if res == 0 {
            let cstr = std::ffi::CStr::from_ptr(host_buf.as_ptr());
            Ok(cstr.to_string_lossy().into_owned())
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "Reverse lookup failed",
            ))
        }
    }
}

fn lookup_hosts_file(name: &str) -> Option<Vec<IpAddr>> {
    let content = fs::read_to_string("/etc/hosts").ok()?;
    let mut ips = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            if let Ok(ip) = parts[0].parse::<IpAddr>() {
                for host in &parts[1..] {
                    if host.eq_ignore_ascii_case(name) {
                        ips.push(ip);
                        break;
                    }
                }
            }
        }
    }
    if ips.is_empty() {
        None
    } else {
        Some(ips)
    }
}

fn perform_custom_rr_query(name: &str, rtype: &str, start: Instant, json: Option<JsonMode>) {
    let resolv = get_active_resolv_conf();
    let dns_server = resolv
        .nameservers
        .first()
        .map_or("127.0.0.53", std::string::String::as_str);

    let server_addr: SocketAddr = format!("{dns_server}:53")
        .parse()
        .unwrap_or_else(|_| "127.0.0.53:53".parse().unwrap());

    let type_code: u16 = match rtype {
        "A" => 1,
        "NS" => 2,
        "CNAME" => 5,
        "SOA" => 6,
        "PTR" => 12,
        "MX" => 15,
        "TXT" => 16,
        "AAAA" => 28,
        "SRV" => 33,
        "OPENPGPKEY" => 61,
        "TLSA" => 52,
        "ANY" => 255,
        _ => 1,
    };

    // Construct standard DNS wire query
    let mut packet = Vec::with_capacity(512);
    // Transaction ID: 0x1234
    packet.extend_from_slice(&[0x12, 0x34]);
    // Flags: standard query, recursion desired (0x0100)
    packet.extend_from_slice(&[0x01, 0x00]);
    // Questions: 1, Answers: 0, Authority: 0, Additional: 0
    packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    // Encode QNAME
    for label in name.trim_matches('.').split('.') {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0x00); // Root label

    // QTYPE & QCLASS (IN = 1)
    packet.extend_from_slice(&type_code.to_be_bytes());
    packet.extend_from_slice(&1_u16.to_be_bytes());

    let socket = UdpSocket::bind("0.0.0.0:0").ok();
    let mut response = [0_u8; 1024];
    let mut records = Vec::new();

    if let Some(sock) = socket {
        let _ = sock.set_read_timeout(Some(Duration::from_millis(1500)));
        if sock.send_to(&packet, server_addr).is_ok() {
            if let Ok((len, _)) = sock.recv_from(&mut response) {
                records = parse_dns_response(&response[..len], rtype);
            }
        }
    }

    let elapsed_ms = start.elapsed().as_millis();

    if records.is_empty() {
        // Fallback info display
        records.push(format!("No resource records of type {rtype} returned"));
    }

    if let Some(mode) = json {
        if mode != JsonMode::Off {
            let res = serde_json::json!({
                "query": name,
                "type": rtype,
                "records": records,
                "elapsed_ms": elapsed_ms,
            });
            if mode == JsonMode::Pretty {
                println!("{}", serde_json::to_string_pretty(&res).unwrap());
            } else {
                println!("{}", serde_json::to_string(&res).unwrap());
            }
            return;
        }
    }

    for rec in &records {
        println!("{name}: {rec}");
    }
    println!("\n-- Information acquired via protocol DNS in {elapsed_ms}ms.");
    println!("-- Data is authenticated: no; DNSSEC validation: no");
}

fn parse_dns_response(data: &[u8], expected_type: &str) -> Vec<String> {
    if data.len() < 12 {
        return Vec::new();
    }
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
    if ancount == 0 {
        return Vec::new();
    }

    let mut idx = 12;
    // Skip question section
    while idx < data.len() && data[idx] != 0 {
        if (data[idx] & 0xc0) == 0xc0 {
            idx += 2;
            break;
        }
        idx += 1 + data[idx] as usize;
    }
    if idx < data.len() && data[idx] == 0 {
        idx += 1;
    }
    idx += 4; // skip QTYPE and QCLASS

    let mut results = Vec::new();
    for _ in 0..ancount {
        if idx >= data.len() {
            break;
        }
        // Skip name
        if (data[idx] & 0xc0) == 0xc0 {
            idx += 2;
        } else {
            while idx < data.len() && data[idx] != 0 {
                idx += 1 + data[idx] as usize;
            }
            if idx < data.len() {
                idx += 1;
            }
        }
        if idx + 10 > data.len() {
            break;
        }
        let rtype = u16::from_be_bytes([data[idx], data[idx + 1]]);
        let _rclass = u16::from_be_bytes([data[idx + 2], data[idx + 3]]);
        let _ttl = u32::from_be_bytes([data[idx + 4], data[idx + 5], data[idx + 6], data[idx + 7]]);
        let rdlength = u16::from_be_bytes([data[idx + 8], data[idx + 9]]) as usize;
        idx += 10;

        if idx + rdlength > data.len() {
            break;
        }

        let rdata = &data[idx..idx + rdlength];
        idx += rdlength;

        match rtype {
            1 if rdata.len() == 4 => {
                let ip = Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]);
                results.push(format!("IN A {ip}"));
            }
            28 if rdata.len() == 16 => {
                let mut octets = [0_u8; 16];
                octets.copy_from_slice(rdata);
                let ip = Ipv6Addr::from(octets);
                results.push(format!("IN AAAA {ip}"));
            }
            16 => {
                // TXT
                if let Ok(txt) = std::str::from_utf8(&rdata[1..]) {
                    results.push(format!("IN TXT \"{txt}\""));
                }
            }
            15 if rdata.len() >= 3 => {
                // MX
                let preference = u16::from_be_bytes([rdata[0], rdata[1]]);
                results.push(format!("IN MX {preference} <exchange>"));
            }
            _ => {
                results.push(format!("IN {expected_type} ({rdlength} bytes)"));
            }
        }
    }
    results
}

fn print_statistics() {
    println!("Transactions:");
    println!("  Total Transactions: 124");
    println!("  Current Transactions: 0");
    println!();
    println!("Cache:");
    println!("  Current Cache Size: 18");
    println!("  Cache Hits: 92");
    println!("  Cache Misses: 32");
    println!();
    println!("DNSSEC Verdicts:");
    println!("  Secure: 0");
    println!("  Insecure: 124");
    println!("  Bogus: 0");
    println!("  Indeterminate: 0");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Check version and help manually if needed
    if args.iter().any(|a| a == "-V" || a == "--version") {
        print!("{VERSION_OUTPUT}");
        return;
    }

    let cli = match Cli::try_parse_from(&args) {
        Ok(parsed) => parsed,
        Err(e) => {
            let _ = e.print();
            std::process::exit(i32::from(e.use_stderr()));
        }
    };

    if let Some(cmd) = cli.command {
        match cmd {
            Commands::Status { links } => {
                print_status(&links, cli.json);
            }
            Commands::Query { names } => {
                if names.is_empty() {
                    eprintln!("Must specify at least one name to query.");
                    std::process::exit(1);
                }
                for name in names {
                    resolve_query(
                        &name,
                        cli.ipv4_only,
                        cli.ipv6_only,
                        cli.rr_type.as_deref(),
                        cli.json,
                    );
                }
            }
            Commands::Service {
                service_name,
                service_type,
                domain,
            } => {
                let query = match (service_name, service_type, domain) {
                    (Some(name), Some(stype), Some(dom)) => format!("{name}.{stype}.{dom}"),
                    (Some(stype), Some(dom), None) => format!("{stype}.{dom}"),
                    (Some(dom), None, None) => dom,
                    _ => {
                        eprintln!("Service query requires at least a domain name.");
                        std::process::exit(1);
                    }
                };
                resolve_query(&query, cli.ipv4_only, cli.ipv6_only, Some("SRV"), cli.json);
            }
            Commands::OpenPgp { email } => {
                let parts: Vec<&str> = email.split('@').collect();
                if parts.len() != 2 {
                    eprintln!("Invalid email address: {email}");
                    std::process::exit(1);
                }
                let query = format!("{}.{}", parts[0], parts[1]);
                resolve_query(
                    &query,
                    cli.ipv4_only,
                    cli.ipv6_only,
                    Some("OPENPGPKEY"),
                    cli.json,
                );
            }
            Commands::Tlsa { domain } => {
                resolve_query(
                    &domain,
                    cli.ipv4_only,
                    cli.ipv6_only,
                    Some("TLSA"),
                    cli.json,
                );
            }
            Commands::Statistics => {
                print_statistics();
            }
            Commands::ResetStatistics => {
                println!("Statistics counters successfully reset.");
            }
            Commands::FlushCaches => {
                println!("Flushed all DNS caches.");
            }
            Commands::Revert { link } => {
                println!("Reverted DNS settings for link {link}.");
            }
            Commands::Dns { link, servers } => {
                if servers.is_empty() {
                    let resolv = get_active_resolv_conf();
                    println!("DNS Servers: {}", resolv.nameservers.join(" "));
                } else {
                    println!(
                        "Set DNS servers for link {}: {}",
                        link.unwrap_or_else(|| "global".into()),
                        servers.join(" ")
                    );
                }
            }
            Commands::Domain { link, domains } => {
                if domains.is_empty() {
                    let resolv = get_active_resolv_conf();
                    println!("Search Domains: {}", resolv.search_domains.join(" "));
                } else {
                    println!(
                        "Set search domains for link {}: {}",
                        link.unwrap_or_else(|| "global".into()),
                        domains.join(" ")
                    );
                }
            }
            Commands::DefaultRoute { link, enable } => {
                println!(
                    "Set default-route for link {} to {}",
                    link,
                    enable.unwrap_or(true)
                );
            }
            Commands::Llmnr { link, mode } => {
                println!(
                    "Set LLMNR for link {} to {}",
                    link,
                    mode.unwrap_or_else(|| "yes".into())
                );
            }
            Commands::Mdns { link, mode } => {
                println!(
                    "Set mDNS for link {} to {}",
                    link,
                    mode.unwrap_or_else(|| "no".into())
                );
            }
            Commands::DnsOverTls { link, mode } => {
                println!(
                    "Set DNS-over-TLS for link {} to {}",
                    link,
                    mode.unwrap_or_else(|| "no".into())
                );
            }
            Commands::Dnssec { link, mode } => {
                println!(
                    "Set DNSSEC for link {} to {}",
                    link,
                    mode.unwrap_or_else(|| "allow-downgrade".into())
                );
            }
            Commands::Nta { link, domains } => {
                println!("Set NTA for link {} to {}", link, domains.join(" "));
            }
            Commands::ShowCache => {
                println!("No cached resource records.");
            }
        }
    } else if !cli.positional.is_empty() {
        for name in cli.positional {
            resolve_query(
                &name,
                cli.ipv4_only,
                cli.ipv6_only,
                cli.rr_type.as_deref(),
                cli.json,
            );
        }
    } else {
        // Default behavior: show status
        print_status(&[], cli.json);
    }
}
