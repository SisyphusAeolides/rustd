#!/usr/bin/env python3
"""Apply the current validated parity-repair tranche."""

from pathlib import Path
import re


def repair_systemctl_isolate_build() -> None:
    path = Path("src/bin/systemctl.rs")
    source = path.read_text(encoding="utf-8")
    if "IpcRequest::Isolate" not in source:
        return

    start = re.search(
        r"IpcRequest::StartUnit\s*\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*:",
        source,
    )
    if start is None:
        raise RuntimeError("unable to determine StartUnit field")
    field = start.group(1)
    pattern = re.compile(
        r"IpcRequest::Isolate\s*\{\s*[A-Za-z_][A-Za-z0-9_]*\s*:\s*([^,}]+),?\s*\}",
        re.MULTILINE,
    )
    source, count = pattern.subn(
        lambda match: f"IpcRequest::StartUnit {{ {field}: {match.group(1).strip()} }}",
        source,
    )
    if count != 1:
        raise RuntimeError(f"expected one isolate request, found {count}")
    path.write_text(source, encoding="utf-8")


def repair_journal_calendar() -> None:
    path = Path("src/bin/journalctl.rs")
    source = path.read_text(encoding="utf-8")
    source = source.replace("std::fs::read_dir(&dir)", "std::fs::read_dir(dir)")
    source = re.sub(r"\bdht_size\b", "data_hash_table_size", source)
    source = re.sub(r"\bfht_size\b", "field_hash_table_size", source)
    source = re.sub(r"\bdoy\b", "day_of_year", source)

    if "fn civil_from_days_since_unix_epoch" not in source:
        lines = source.splitlines()
        day_line = next(
            (
                index
                for index, line in enumerate(lines)
                if re.search(r"let\s+days\s*=\s*secs\s*/\s*86_?400\s*;", line)
            ),
            None,
        )
        if day_line is None:
            raise RuntimeError("unable to locate journal day calculation")

        function_line = next(
            (
                index
                for index in range(day_line, -1, -1)
                if re.match(r"\s*(?:pub\s+)?fn\s+", lines[index])
            ),
            None,
        )
        if function_line is None:
            raise RuntimeError("unable to locate journal timestamp function")

        helper = [
            "/// Convert whole days since 1970-01-01 to a Gregorian date.",
            "#[must_use]",
            "fn civil_from_days_since_unix_epoch(epoch_days: u64) -> (i64, u32, u32) {",
            "    let epoch_days = i64::try_from(epoch_days).unwrap_or(i64::MAX - 719_468);",
            "    let shifted = epoch_days + 719_468;",
            "    let era =",
            "        (if shifted >= 0 { shifted } else { shifted - 146_096 }) / 146_097;",
            "    let era_ordinal = shifted - era * 146_097;",
            "    let era_year =",
            "        (era_ordinal - era_ordinal / 1_460 + era_ordinal / 36_524",
            "            - era_ordinal / 146_096)",
            "            / 365;",
            "    let mut calendar_year = era_year + era * 400;",
            "    let ordinal = era_ordinal - (365 * era_year + era_year / 4 - era_year / 100);",
            "    let march_index = (5 * ordinal + 2) / 153;",
            "    let calendar_day = ordinal - (153 * march_index + 2) / 5 + 1;",
            "    let calendar_month = march_index + if march_index < 10 { 3 } else { -9 };",
            "    if calendar_month <= 2 {",
            "        calendar_year += 1;",
            "    }",
            "    (",
            "        calendar_year,",
            "        u32::try_from(calendar_month).expect(\"Gregorian month fits u32\"),",
            "        u32::try_from(calendar_day).expect(\"Gregorian day fits u32\"),",
            "    )",
            "}",
            "",
        ]
        lines[function_line:function_line] = helper

        day_line = next(
            index
            for index, line in enumerate(lines)
            if re.search(r"let\s+days\s*=\s*secs\s*/\s*86_?400\s*;", line)
        )
        first_calendar = None
        end_calendar = None
        for index in range(day_line + 1, min(len(lines), day_line + 18)):
            if first_calendar is None and re.search(r"let\s+year\s*=", lines[index]):
                first_calendar = index
            if re.search(r"let\s+(?:day|day_of_month)\s*=", lines[index]):
                end_calendar = index
                break
        if first_calendar is None or end_calendar is None:
            raise RuntimeError("unable to locate approximate journal calendar block")

        indent = re.match(r"\s*", lines[first_calendar]).group(0)
        lines[first_calendar : end_calendar + 1] = [
            f"{indent}let (year, month, day_of_month) =",
            f"{indent}    civil_from_days_since_unix_epoch(days);",
        ]
        for index in range(day_line, min(len(lines), day_line + 40)):
            lines[index] = re.sub(r"\bday\b", "day_of_month", lines[index])
        source = "\n".join(lines) + "\n"

    if "civil_date_unix_epoch" not in source:
        source = source.rstrip() + (
            "\n\n#[cfg(test)]\n"
            "mod calendar_tests {\n"
            "    use super::civil_from_days_since_unix_epoch;\n\n"
            "    #[test]\n"
            "    fn civil_date_unix_epoch() {\n"
            "        assert_eq!(civil_from_days_since_unix_epoch(0), (1970, 1, 1));\n"
            "    }\n\n"
            "    #[test]\n"
            "    fn civil_date_century_leap_day() {\n"
            "        assert_eq!(civil_from_days_since_unix_epoch(11_016), (2000, 2, 29));\n"
            "    }\n\n"
            "    #[test]\n"
            "    fn civil_date_modern_leap_day() {\n"
            "        assert_eq!(civil_from_days_since_unix_epoch(19_782), (2024, 2, 29));\n"
            "    }\n"
            "}\n"
        )

    path.write_text(source, encoding="utf-8")


def repair_manager_lifecycle() -> None:
    path = Path("src/manager.rs")
    source = path.read_text(encoding="utf-8")
    if "fn run_with_idle_exit" in source:
        return

    signature = re.compile(
        r"(?m)^    pub fn run\(&mut self\) -> anyhow::Result<LoopResult> \{\n        loop \{"
    )
    source, count = signature.subn(
        "    pub fn run(&mut self) -> anyhow::Result<LoopResult> {\n"
        "        self.run_with_idle_exit(false)\n"
        "    }\n\n"
        "    #[cfg(test)]\n"
        "    fn run_until_idle(&mut self) -> anyhow::Result<LoopResult> {\n"
        "        self.run_with_idle_exit(true)\n"
        "    }\n\n"
        "    fn run_with_idle_exit(\n"
        "        &mut self,\n"
        "        exit_when_idle: bool,\n"
        "    ) -> anyhow::Result<LoopResult> {\n"
        "        loop {",
        source,
        count=1,
    )
    if count != 1:
        raise RuntimeError("unable to refactor Manager::run")

    idle = re.compile(
        r"(?m)^(?P<indent>\s*)if self\.job_queue\.is_empty\(\) && self\.all_settled\(\) \{\n"
        r"(?P=indent)    return Ok\(LoopResult::Exit\);\n"
        r"(?P=indent)\}"
    )
    source, count = idle.subn(
        lambda match: (
            f"{match.group('indent')}if exit_when_idle\n"
            f"{match.group('indent')}    && self.job_queue.is_empty()\n"
            f"{match.group('indent')}    && self.all_settled()\n"
            f"{match.group('indent')}{{\n"
            f"{match.group('indent')}    return Ok(LoopResult::Exit);\n"
            f"{match.group('indent')}}}"
        ),
        source,
        count=1,
    )
    if count != 1:
        raise RuntimeError("unable to locate manager idle exit")

    source = source.replace(
        "let result = m.run().unwrap();",
        "let result = m.run_until_idle().unwrap();",
    )
    path.write_text(source, encoding="utf-8")


def repair_service_deactivation() -> None:
    path = Path("src/service.rs")
    source = path.read_text(encoding="utf-8")
    old = re.compile(
        r"pub fn deactivate\(record: &mut UnitRecord\) \{\n"
        r"    if let Some\(pid\) = record\.active_pid \{\n"
        r"        // Safety: kill with a valid pid and SIGTERM is always safe\.\n"
        r"        unsafe \{ libc::kill\(pid, libc::SIGTERM\) \};\n"
        r"    \}\n"
        r"    record\.state = UnitState::Deactivating;\n"
        r"\}"
    )
    if old.search(source):
        source = old.sub(
            "pub fn deactivate(record: &mut UnitRecord) {\n"
            "    if let Some(pid) = record.active_pid {\n"
            "        // Safety: kill with a valid pid and SIGTERM is always safe.\n"
            "        unsafe { libc::kill(pid, libc::SIGTERM) };\n"
            "        record.state = UnitState::Deactivating;\n"
            "    } else {\n"
            "        record.state = UnitState::Inactive;\n"
            "    }\n"
            "}",
            source,
            count=1,
        )

    if "fn deactivate_without_pid_settles_inactive" not in source:
        marker = "    #[test]\n    fn ignore_failure_flag_marks_success() {"
        if marker not in source:
            raise RuntimeError("unable to insert deactivation regression test")
        test = (
            "    #[test]\n"
            "    fn deactivate_without_pid_settles_inactive() {\n"
            "        let mut record =\n"
            "            make_service(\"test.service\", \"/bin/true\", ServiceType::Simple);\n"
            "        record.state = UnitState::Active;\n"
            "        record.active_pid = None;\n"
            "        deactivate(&mut record);\n"
            "        assert_eq!(record.state, UnitState::Inactive);\n"
            "    }\n\n"
        )
        source = source.replace(marker, test + marker, 1)
    path.write_text(source, encoding="utf-8")


def repair_notify_credentials() -> None:
    path = Path("src/notify.rs")
    source = path.read_text(encoding="utf-8")
    if "fn enable_passcred(" in source:
        return

    marker = "/// Create and bind the abstract Unix domain socket.\n"
    if marker not in source:
        raise RuntimeError("unable to insert SO_PASSCRED helper")
    helper = (
        "/// Enable sender credentials for datagrams received on `fd`.\n"
        "fn enable_passcred(fd: libc::c_int) -> anyhow::Result<()> {\n"
        "    let enabled: libc::c_int = 1;\n"
        "    let option_len = libc::socklen_t::try_from(std::mem::size_of_val(&enabled))\n"
        "        .expect(\"SO_PASSCRED option length fits socklen_t\");\n"
        "    // Safety: `enabled` is a valid integer socket option value.\n"
        "    let result = unsafe {\n"
        "        libc::setsockopt(\n"
        "            fd,\n"
        "            libc::SOL_SOCKET,\n"
        "            libc::SO_PASSCRED,\n"
        "            std::ptr::addr_of!(enabled).cast(),\n"
        "            option_len,\n"
        "        )\n"
        "    };\n"
        "    if result < 0 {\n"
        "        let error = unsafe { *libc::__errno_location() };\n"
        "        return Err(anyhow::anyhow!(\n"
        "            \"setsockopt(SO_PASSCRED) failed: errno {error}\"\n"
        "        ));\n"
        "    }\n"
        "    Ok(())\n"
        "}\n\n"
    )
    source = source.replace(marker, helper + marker, 1)

    socket_check = (
        "    if fd < 0 {\n"
        "        return Err(anyhow::anyhow!(\n"
        "            \"socket(AF_UNIX) failed: errno {}\",\n"
        "            unsafe { *libc::__errno_location() }\n"
        "        ));\n"
        "    }\n"
    )
    if socket_check not in source:
        raise RuntimeError("unable to locate notify socket creation")
    source = source.replace(
        socket_check,
        socket_check
        + "    if let Err(error) = enable_passcred(fd) {\n"
        + "        unsafe { libc::close(fd) };\n"
        + "        return Err(error);\n"
        + "    }\n",
        1,
    )

    fallback = (
        "            if fd2 >= 0 {\n"
        "                return Ok(unsafe { OwnedFd::from_raw_fd(fd2) });\n"
        "            }"
    )
    if fallback in source:
        source = source.replace(
            fallback,
            "            if fd2 >= 0 {\n"
            "                if let Err(error) = enable_passcred(fd2) {\n"
            "                    unsafe { libc::close(fd2) };\n"
            "                    return Err(error);\n"
            "                }\n"
            "                return Ok(unsafe { OwnedFd::from_raw_fd(fd2) });\n"
            "            }",
            1,
        )
    path.write_text(source, encoding="utf-8")


def main() -> None:
    repair_systemctl_isolate_build()
    repair_journal_calendar()
    repair_manager_lifecycle()
    repair_service_deactivation()
    repair_notify_credentials()


if __name__ == "__main__":
    main()
