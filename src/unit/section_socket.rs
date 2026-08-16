// SPDX-License-Identifier: LGPL-2.1-or-later
//! Typed `[Socket]` section.
//!
//! Upstream reference: `src/core/socket.c`, `systemd.socket(5)` (v261)

use crate::unit::duration::parse_duration;
use std::time::Duration;

fn parse_bool(s: &str) -> bool {
    matches!(s.to_ascii_lowercase().as_str(), "yes" | "true" | "1" | "on")
}

/// A `Listen*=` directive with the socket type and address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenSpec {
    /// The listen type: `"Stream"`, `"Datagram"`, `"SequentialPacket"`,
    /// `"Netlink"`, `"Special"`, `"MessageQueue"`, `"FIFO"`, `"USB"`.
    pub kind: String,
    /// The address, path, or port.
    pub address: String,
}

/// Parsed `[Socket]` section.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Default, Clone)]
pub struct SocketSection {
    pub listen: Vec<ListenSpec>,
    pub accept: bool,
    pub writable: bool,
    pub flush_pending: bool,
    pub max_connections: Option<u32>,
    pub max_connections_per_source: Option<u32>,
    pub keep_alive: bool,
    pub keep_alive_time_sec: Option<Duration>,
    pub keep_alive_interval_sec: Option<Duration>,
    pub keep_alive_probes: Option<u32>,
    pub no_delay: bool,
    pub priority: Option<i32>,
    pub defer_accept_sec: Option<Duration>,
    pub receive_buffer: Option<u64>,
    pub send_buffer: Option<u64>,
    pub iptos: String,
    pub ipttl: Option<i32>,
    pub mark: Option<u32>,
    pub reuse_port: bool,
    pub smack_label: String,
    pub smack_label_ip_in: String,
    pub smack_label_ip_out: String,
    pub se_linux_context_from_net: bool,
    pub pipe_size: Option<u64>,
    pub message_queue_max_messages: Option<i64>,
    pub message_queue_message_size: Option<i64>,
    pub free_bind: bool,
    pub transparent: bool,
    pub broadcast: bool,
    pub pass_credentials: bool,
    pub pass_security: bool,
    pub pass_packet_info: bool,
    pub timestamping: String,
    pub tcp_congestion: String,
    pub exec_start_pre: Vec<String>,
    pub exec_start_post: Vec<String>,
    pub exec_stop_pre: Vec<String>,
    pub exec_stop_post: Vec<String>,
    pub timeout_sec: Option<Duration>,
    pub service: String,
    pub remove_on_stop: bool,
    pub symlinks: Vec<String>,
    pub file_descriptor_name: String,
    pub trigger_limit_interval_sec: Option<Duration>,
    pub trigger_limit_burst: Option<u32>,
    pub socket_mode: String,
    pub directory_mode: String,
    pub socket_user: String,
    pub socket_group: String,
    pub defer_trigger: bool,
}

impl SocketSection {
    /// Apply a single `(key, value)` pair from the `[Socket]` section.
    pub fn apply(&mut self, key: &str, value: &str) {
        let bv = || parse_bool(value);
        let dv = || parse_duration(value);

        match key {
            k if k.starts_with("Listen") => {
                let kind = k.strip_prefix("Listen").unwrap_or("").to_owned();
                if value.is_empty() {
                    self.listen.retain(|l| l.kind != kind);
                } else {
                    self.listen.push(ListenSpec {
                        kind,
                        address: value.to_owned(),
                    });
                }
            }
            "Accept" => self.accept = bv(),
            "Writable" => self.writable = bv(),
            "FlushPending" => self.flush_pending = bv(),
            "MaxConnections" => self.max_connections = value.parse().ok(),
            "MaxConnectionsPerSource" => self.max_connections_per_source = value.parse().ok(),
            "KeepAlive" => self.keep_alive = bv(),
            "KeepAliveTimeSec" => self.keep_alive_time_sec = dv(),
            "KeepAliveIntervalSec" => self.keep_alive_interval_sec = dv(),
            "KeepAliveProbes" => self.keep_alive_probes = value.parse().ok(),
            "NoDelay" => self.no_delay = bv(),
            "Priority" => self.priority = value.parse().ok(),
            "DeferAcceptSec" => self.defer_accept_sec = dv(),
            "ReceiveBuffer" => self.receive_buffer = value.parse().ok(),
            "SendBuffer" => self.send_buffer = value.parse().ok(),
            "IPTOS" => value.clone_into(&mut self.iptos),
            "IPTTL" => self.ipttl = value.parse().ok(),
            "Mark" => self.mark = value.parse().ok(),
            "ReusePort" => self.reuse_port = bv(),
            "SmackLabel" => value.clone_into(&mut self.smack_label),
            "SmackLabelIPIn" => value.clone_into(&mut self.smack_label_ip_in),
            "SmackLabelIPOut" => value.clone_into(&mut self.smack_label_ip_out),
            "SELinuxContextFromNet" => self.se_linux_context_from_net = bv(),
            "PipeSize" => self.pipe_size = value.parse().ok(),
            "MessageQueueMaxMessages" => self.message_queue_max_messages = value.parse().ok(),
            "MessageQueueMessageSize" => self.message_queue_message_size = value.parse().ok(),
            "FreeBind" => self.free_bind = bv(),
            "Transparent" => self.transparent = bv(),
            "Broadcast" => self.broadcast = bv(),
            "PassCredentials" => self.pass_credentials = bv(),
            "PassSecurity" => self.pass_security = bv(),
            "PassPacketInfo" => self.pass_packet_info = bv(),
            "Timestamping" => value.clone_into(&mut self.timestamping),
            "TCPCongestion" => value.clone_into(&mut self.tcp_congestion),
            "ExecStartPre" => {
                if value.is_empty() {
                    self.exec_start_pre.clear();
                } else {
                    self.exec_start_pre.push(value.to_owned());
                }
            }
            "ExecStartPost" => {
                if value.is_empty() {
                    self.exec_start_post.clear();
                } else {
                    self.exec_start_post.push(value.to_owned());
                }
            }
            "ExecStopPre" => {
                if value.is_empty() {
                    self.exec_stop_pre.clear();
                } else {
                    self.exec_stop_pre.push(value.to_owned());
                }
            }
            "ExecStopPost" => {
                if value.is_empty() {
                    self.exec_stop_post.clear();
                } else {
                    self.exec_stop_post.push(value.to_owned());
                }
            }
            "TimeoutSec" => self.timeout_sec = dv(),
            "Service" => value.clone_into(&mut self.service),
            "RemoveOnStop" => self.remove_on_stop = bv(),
            "Symlinks" => {
                if value.is_empty() {
                    self.symlinks.clear();
                } else {
                    self.symlinks
                        .extend(value.split_whitespace().map(str::to_owned));
                }
            }
            "FileDescriptorName" => value.clone_into(&mut self.file_descriptor_name),
            "TriggerLimitIntervalSec" => self.trigger_limit_interval_sec = dv(),
            "TriggerLimitBurst" => self.trigger_limit_burst = value.parse().ok(),
            "SocketMode" => value.clone_into(&mut self.socket_mode),
            "DirectoryMode" => value.clone_into(&mut self.directory_mode),
            "SocketUser" => value.clone_into(&mut self.socket_user),
            "SocketGroup" => value.clone_into(&mut self.socket_group),
            "DeferTrigger" => self.defer_trigger = bv(),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unit::ini::parse_unit_text;

    #[test]
    fn journald_socket() {
        let path = "/usr/lib/systemd/system/systemd-journald.socket";
        let Ok(text) = std::fs::read_to_string(path) else {
            return;
        };
        let entries = parse_unit_text(&text);
        let mut s = SocketSection::default();
        for e in entries.iter().filter(|e| e.section == "Socket") {
            s.apply(&e.key, &e.value);
        }
        assert!(s.listen.iter().any(|l| l.kind == "Datagram"));
        assert!(s.listen.iter().any(|l| l.kind == "Stream"));
        assert_ne!(s.service, "");
        assert!(s.pass_credentials);
    }
}
