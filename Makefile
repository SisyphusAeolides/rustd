SHELL := /bin/sh
CC ?= cc
undefine FC
FC ?= gfortran
CFLAGS ?= -O2 -g -std=c17 -Wall -Wextra -Werror -fstack-protector-strong -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3
# -iquote keeps local headers from shadowing the system <spawn.h>.
CPPFLAGS ?= -iquote ffi
FFLAGS ?= -O2 -g -std=f2018 -Wall -Wextra -Werror -fimplicit-none
PREFIX ?= /usr
RUSTLIBEXECDIR ?= $(PREFIX)/lib/rustd
RUSTUNITDIR ?= $(PREFIX)/lib/rustd/system
TMPFILESDIR ?= $(PREFIX)/lib/tmpfiles.d
MANDIR ?= $(PREFIX)/share/man
BASHCOMPDIR ?= $(PREFIX)/share/bash-completion/completions
ZSHCOMPDIR ?= $(PREFIX)/share/zsh/site-functions
DBUS_SYSTEM_SERVICEDIR ?= $(PREFIX)/share/dbus-1/system-services
DBUS_SYSTEM_POLICYDIR ?= $(PREFIX)/share/dbus-1/system.d
POLKIT_ACTIONDIR ?= $(PREFIX)/share/polkit-1/actions
PAMLIBDIR ?= $(PREFIX)/lib/security
TARGET_DIR ?= target
RELEASE_DIR := $(TARGET_DIR)/release
PAM_MODULE := build/pam_rustd.so
IDRIS2 ?= $(shell command -v idris2 2>/dev/null || find $(HOME)/.local/state/pack -name idris2 -type f -executable 2>/dev/null | head -1)

.PHONY: all build pam-module test check-native check-rust check-formal check-packaging check-reproducible clean install release boot-smoke certify installed-certification performance-promotion

all: build

build:
	CARGO_TARGET_DIR=$(TARGET_DIR) cargo build --release --all-features --locked

pam-module:
	mkdir -p build
	$(CC) $(CFLAGS) -fPIC -shared pam/pam_rustd.c -o $(PAM_MODULE) $$(pkg-config --cflags --libs dbus-1) -lpam

check-native:
	mkdir -p build
	$(FC) $(FFLAGS) -Jbuild -c ffi/sched.f90 -o build/sched.o
	$(CC) $(CPPFLAGS) $(CFLAGS) -c ffi/native.c -o build/native.o
	$(CC) $(CPPFLAGS) $(CFLAGS) -c ffi/notify.c -o build/notify.o
	$(CC) $(CPPFLAGS) $(CFLAGS) -c ffi/interface.c -o build/interface.o
	$(CC) $(CPPFLAGS) $(CFLAGS) -c ffi/cgroup.c -o build/cgroup.o
	$(CC) $(CPPFLAGS) $(CFLAGS) -c ffi/signal.c -o build/signal.o
	$(CC) $(CPPFLAGS) $(CFLAGS) -c ffi/journal.c -o build/journal.o
	$(CC) $(CPPFLAGS) $(CFLAGS) -c ffi/event.c -o build/event.o
	$(CC) $(CPPFLAGS) $(CFLAGS) -c ffi/spawn.c -o build/spawn.o
	$(CC) $(CPPFLAGS) $(CFLAGS) -c ffi/spawn_helper.c -o build/spawn_helper.o
	$(CC) $(CPPFLAGS) $(CFLAGS) -c ffi/sandbox.c -o build/sandbox.o
	$(CC) $(CPPFLAGS) $(CFLAGS) -c ffi/socket_activation.c -o build/socket_activation.o
	$(CC) $(CPPFLAGS) $(CFLAGS) -c ffi/kexec.c -o build/kexec.o
	$(CC) $(CPPFLAGS) $(CFLAGS) -c ffi/mute_console.c -o build/mute_console.o
	$(CC) $(CPPFLAGS) $(CFLAGS) -c ffi/seccomp.c -o build/seccomp.o
	$(CC) $(CPPFLAGS) $(CFLAGS) -c ffi/capability.c -o build/capability.o
	$(CC) $(CPPFLAGS) $(CFLAGS) -c ffi/test_native.c -o build/test_native.o
	$(CC) $(CPPFLAGS) $(CFLAGS) -c ffi/test_event.c -o build/test_event.o
	$(CC) $(CPPFLAGS) $(CFLAGS) -c ffi/test_spawn.c -o build/test_spawn.o
	$(FC) build/test_native.o build/native.o build/notify.o build/interface.o build/cgroup.o build/signal.o build/journal.o build/event.o build/sched.o build/sandbox.o build/socket_activation.o build/kexec.o build/mute_console.o build/seccomp.o build/capability.o -o build/test_native -ldl
	./build/test_native
	$(CC) build/test_event.o build/event.o -o build/test_event -lrt
	./build/test_event
	$(CC) build/test_spawn.o build/spawn.o build/spawn_helper.o build/sandbox.o build/socket_activation.o build/seccomp.o build/capability.o -o build/test_spawn -ldl -lpthread -Wl,--wrap=fork
	./build/test_spawn
	python3 scripts/check-spawn-no-fork.py

check-rust:
	cargo fmt --all -- --check
	cargo clippy --all-targets --all-features --locked -- -D warnings
	cargo test --all-targets --all-features --locked -- --test-threads=1

check-formal:
	@test -n "$(IDRIS2)" || (echo "idris2 compiler not found; set IDRIS2=/path/to/idris2" >&2; exit 1)
	$(IDRIS2) --build formal/idris/rustd-policy.ipkg
	agda -i formal/agda formal/agda/RustD/Unit/State.agda
	agda -i formal/agda formal/agda/RustD/Unit/Transition.agda
	agda -i formal/agda formal/agda/RustD/Cgroup/Bound.agda
	agda -i formal/agda formal/agda/RustD/Job/Ordering.agda

check-packaging:
	bash -n scripts/boot-smoke.sh scripts/install-rustd-names.sh scripts/check-reproducible-release.sh scripts/installed-certification.sh scripts/performance-promotion.sh scripts/exclusive-cutover-gate.sh scripts/ci-pid1-initramfs.sh
	python3 -m py_compile scripts/executable_contract.py scripts/install-executable-surfaces.py
	@set -eu; \
	work=$$(mktemp -d); \
	trap 'rm -rf "$$work"' EXIT HUP INT TERM; \
	cargo metadata --locked --no-deps --format-version 1 >"$$work/cargo-metadata.json"; \
	python3 -c 'import json, sys; data=json.load(open(sys.argv[1], encoding="utf-8")); package=next(p for p in data["packages"] if p["name"]=="rustd-daemon"); bins={t["name"] for t in package["targets"] if "bin" in t["kind"]}; required={"rustd", "rustctl"}; missing=sorted(required-bins); assert not missing, f"missing native RustD binaries: {missing}"' "$$work/cargo-metadata.json"; \
	test -x scripts/boot-smoke.sh; \
	grep -Fq 'RUSTCTL="$${RUSTCTL:-/usr/bin/rustctl}"' scripts/boot-smoke.sh; \
	grep -Fq 'PID 1 executable is rustd' scripts/boot-smoke.sh; \
	grep -Fq 'rustd-journald.service' scripts/boot-smoke.sh; \
	grep -Fq '/run/rustd/ctl.sock' scripts/boot-smoke.sh; \
	grep -Fq '/run/rustd/journal/socket' scripts/boot-smoke.sh; \
	! grep -E -q 'systemctl|systemd-journald|/run/systemd' scripts/boot-smoke.sh; \
	test -f packaging/tmpfiles/rustd.conf; \
	grep -Fq '/run/rustd' packaging/tmpfiles/rustd.conf; \
	! grep -Fq '/run/systemd' packaging/tmpfiles/rustd.conf; \
	test -d packaging/rustd; \
	test ! -e packaging/systemd; \
	for unit in default.target graphical.target sysinit.target basic.target multi-user.target rescue.target emergency.target shutdown.target getty.target getty@.service serial-getty@.service container-getty@.service console-getty.service dbus.service display-manager.service rustd-journald.service rustd-logind.service rustd-udevd.service rustd-udev-trigger.service rustd-udev-settle.service rustd-user-sessions.service user@.service; do test -f "packaging/rustd/$$unit"; done; \
	grep -Fq 'ExecStart=/usr/lib/rustd/rustd-journald --runtime-directory /run/rustd/journal' packaging/rustd/rustd-journald.service; \
	grep -Fq 'ExecStart=/usr/lib/rustd/rustd-logind' packaging/rustd/rustd-logind.service; \
	grep -Fq 'ExecStart=/usr/lib/rustd/rustd --user' packaging/rustd/user@.service; \
	grep -Fq 'ExecStart=/usr/bin/dbus-daemon' packaging/rustd/dbus.service; \
	test -f packaging/dbus/org.freedesktop.login1.service; \
	test -f packaging/dbus/org.freedesktop.login1.conf; \
	test -f packaging/rustd/systemd-udevd.service; \
	! grep -R -Fq '/usr/lib/systemd/' packaging/rustd; \
	! grep -R -Fq '/run/systemd' packaging/rustd

check-reproducible:
	bash scripts/check-reproducible-release.sh

test: check-native check-rust check-packaging

install: build pam-module
	@test -n "$(DESTDIR)" && test "$(DESTDIR)" != "/" || (echo "DESTDIR must name a non-root staging directory" >&2; exit 64)
	DESTDIR="$(DESTDIR)" PREFIX="$(PREFIX)" RUSTLIBEXECDIR="$(RUSTLIBEXECDIR)" BUILDDIR="$(RELEASE_DIR)" bash scripts/install-rustd-names.sh
	for file in packaging/rustd/*; do install -Dm0644 "$$file" "$(DESTDIR)$(RUSTUNITDIR)/$$(basename "$$file")"; done
	for file in packaging/dbus/*.service; do install -Dm0644 "$$file" "$(DESTDIR)$(DBUS_SYSTEM_SERVICEDIR)/$$(basename "$$file")"; done
	for file in packaging/dbus/*.conf; do install -Dm0644 "$$file" "$(DESTDIR)$(DBUS_SYSTEM_POLICYDIR)/$$(basename "$$file")"; done
	for file in packaging/polkit/*.policy; do install -Dm0644 "$$file" "$(DESTDIR)$(POLKIT_ACTIONDIR)/$$(basename "$$file")"; done
	install -Dm0644 packaging/tmpfiles/rustd.conf $(DESTDIR)$(TMPFILESDIR)/rustd.conf
	install -Dm0755 $(PAM_MODULE) "$(DESTDIR)$(PAMLIBDIR)/pam_rustd.so"
	ln -sf pam_rustd.so "$(DESTDIR)$(PAMLIBDIR)/pam_systemd.so"

clean:
	rm -rf build $(TARGET_DIR)

release: build test check-formal check-reproducible

boot-smoke:
	bash scripts/boot-smoke.sh

installed-certification:
	bash scripts/installed-certification.sh

performance-promotion:
	bash scripts/performance-promotion.sh

certify: release boot-smoke installed-certification
