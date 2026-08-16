// SPDX-License-Identifier: LGPL-2.1-or-later
//! Process-isolated runtime regressions for service timeout escalation.

use std::time::Duration;

use rustd::event::child::{reap_children, ChildExit};
use rustd::event::EventLoop;
use rustd::restart::{arm_start_timeout, arm_stop_timeout};

fn fork_term_ignoring_child() -> libc::pid_t {
    let mut ready_pipe = [-1; 2];
    // Safety: `ready_pipe` points to two writable descriptor slots.
    assert_eq!(
        unsafe { libc::pipe2(ready_pipe.as_mut_ptr(), libc::O_CLOEXEC) },
        0
    );

    // Safety: tests immediately separate parent/child control flow.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        // Safety: the child owns the write side and no longer needs the reader.
        unsafe {
            libc::close(ready_pipe[0]);
            libc::signal(libc::SIGTERM, libc::SIG_IGN);
            let ready = [1u8; 1];
            let _ = libc::write(ready_pipe[1], ready.as_ptr().cast(), ready.len());
            libc::close(ready_pipe[1]);
            loop {
                libc::pause();
            }
        }
    }

    // Wait until the child has installed SIG_IGN before returning.
    unsafe { libc::close(ready_pipe[1]) };
    let mut ready = [0u8; 1];
    let read = unsafe { libc::read(ready_pipe[0], ready.as_mut_ptr().cast(), ready.len()) };
    unsafe { libc::close(ready_pipe[0]) };
    assert_eq!(read, 1);
    assert_eq!(ready[0], 1);
    pid
}

fn drive_until_exit(loop_: &mut EventLoop, pid: libc::pid_t) -> ChildExit {
    for _ in 0..40 {
        if let Some(exit) = reap_children().into_iter().find(|exit| exit.pid == pid) {
            return exit;
        }
        loop_.run_once_timeout(100).unwrap();
        if let Some(exit) = loop_
            .drain_child_exits()
            .into_iter()
            .find(|exit| exit.pid == pid)
        {
            return exit;
        }
        if let Some(exit) = reap_children().into_iter().find(|exit| exit.pid == pid) {
            return exit;
        }
    }
    panic!("child {pid} did not exit before timeout");
}

#[test]
fn timeout_escalation_runtime() {
    let mut event_loop = EventLoop::new().unwrap();
    let start_pid = fork_term_ignoring_child();
    arm_start_timeout(
        &mut event_loop,
        start_pid,
        Duration::from_millis(10),
        Duration::from_millis(10),
    )
    .unwrap();
    let start_exit = drive_until_exit(&mut event_loop, start_pid);
    assert_eq!(start_exit.code, libc::CLD_KILLED);
    assert_eq!(start_exit.status, libc::SIGKILL);

    let mut event_loop = EventLoop::new().unwrap();
    let stop_pid = fork_term_ignoring_child();
    // Safety: this is the same initial stop signal the service path sends.
    unsafe { libc::kill(stop_pid, libc::SIGTERM) };
    arm_stop_timeout(&mut event_loop, stop_pid, Duration::from_millis(10)).unwrap();
    let stop_exit = drive_until_exit(&mut event_loop, stop_pid);
    assert_eq!(stop_exit.code, libc::CLD_KILLED);
    assert_eq!(stop_exit.status, libc::SIGKILL);
}
