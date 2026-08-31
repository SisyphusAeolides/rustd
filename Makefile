SHELL := /bin/sh
CC ?= cc
undefine FC
FC ?= gfortran
CFLAGS ?= -O2 -g -std=c17 -Wall -Wextra -Werror -Wno-error=cpp -fstack-protector-strong -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3
# -iquote keeps local headers from shadowing the system <spawn.h>.
CPPFLAGS ?= -iquote ffi
FFLAGS ?= -O2 -g -std=f2018 -Wall -Wextra -Werror -fimplicit-none
PREFIX ?= /usr
LIBDIR ?= $(PREFIX)/lib
INCLUDEDIR ?= $(PREFIX)/include
PKGCONFIGDIR ?= $(LIBDIR)/pkgconfig
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
LIBS_DIR := build/libs
LIB_CPPFLAGS := -Iinclude -iquote ffi
LIB_LDFLAGS := -Wl,-z,relro,-z,now
COMPAT_CFLAGS := $(shell pkg-config --cflags dbus-1 json-c 2>/dev/null)
IDRIS2 ?= $(shell command -v idris2 2>/dev/null || find $(HOME)/.local/state/pack -name idris2 -type f -executable 2>/dev/null | head -1)

SHARED_LIBS := \
	$(LIBS_DIR)/librustd_service.so.1 \
	$(LIBS_DIR)/librustd_journal.so.1 \
	$(LIBS_DIR)/librustd_device.so.1 \
	$(LIBS_DIR)/librustd_login.so.1 \
	$(LIBS_DIR)/librustd_manager.so.1

COMPAT_LIBS := \
	$(LIBS_DIR)/libudev.so.1 \
	$(LIBS_DIR)/libsystemd.so.0

.PHONY: all build pam-module libs compat check-libs check-compat check-compat-closure check-logind test check-native check-rust check-formal check-packaging check-reproducible clean install release boot-smoke certify installed-certification performance-promotion

all: build libs

build:
	CARGO_TARGET_DIR=$(TARGET_DIR) cargo build --release --all-features --locked

pam-module:
	mkdir -p build
	$(CC) $(CFLAGS) -fPIC -shared pam/pam_rustd.c -o $(PAM_MODULE) $$(pkg-config --cflags --libs dbus-1) -lpam

libs: $(SHARED_LIBS)
	ln -sfn librustd_service.so.1 $(LIBS_DIR)/librustd_service.so
	ln -sfn librustd_journal.so.1 $(LIBS_DIR)/librustd_journal.so
	ln -sfn librustd_device.so.1 $(LIBS_DIR)/librustd_device.so
	ln -sfn librustd_login.so.1 $(LIBS_DIR)/librustd_login.so
	ln -sfn librustd_manager.so.1 $(LIBS_DIR)/librustd_manager.so

compat: libs $(COMPAT_LIBS)
	ln -sfn libudev.so.1 $(LIBS_DIR)/libudev.so
	ln -sfn libsystemd.so.0 $(LIBS_DIR)/libsystemd.so

$(LIBS_DIR)/libudev.so.1: libs/compat/udev.c libs/maps/libudev.map include/rustd/device.h $(LIBS_DIR)/librustd_device.so.1
	mkdir -p $(LIBS_DIR)
	$(CC) $(CFLAGS) -fPIC $(LIB_CPPFLAGS) -shared \
		libs/compat/udev.c \
		-Wl,--version-script=libs/maps/libudev.map \
		-Wl,-soname,libudev.so.1 $(LIB_LDFLAGS) \
		-Wl,-rpath,'$$ORIGIN' -L$(LIBS_DIR) -l:librustd_device.so.1 \
		-o $@

$(LIBS_DIR)/libsystemd.so.0: libs/compat/systemd.c libs/compat/journal_send_impl.c \
		libs/compat/sd_bus_impl.c libs/compat/sd_json_varlink_impl.c \
		libs/compat/sd_varlink_idl_impl.c libs/compat/sd_bus_abi.h \
		libs/compat/sd_json_varlink_abi.h libs/maps/libsystemd.map \
		include/rustd/service.h include/rustd/journal.h include/rustd/login.h include/rustd/device.h \
		$(LIBS_DIR)/librustd_service.so.1 $(LIBS_DIR)/librustd_journal.so.1 \
		$(LIBS_DIR)/librustd_login.so.1 $(LIBS_DIR)/librustd_device.so.1
	mkdir -p $(LIBS_DIR)
	$(CC) $(CFLAGS) $(COMPAT_CFLAGS) -fPIC $(LIB_CPPFLAGS) -shared \
		libs/compat/systemd.c libs/compat/journal_send_impl.c \
		libs/compat/sd_bus_impl.c libs/compat/sd_json_varlink_impl.c \
		libs/compat/sd_varlink_idl_impl.c \
		-Wl,--version-script=libs/maps/libsystemd.map \
		-Wl,-soname,libsystemd.so.0 $(LIB_LDFLAGS) \
		-Wl,-rpath,'$$ORIGIN' -L$(LIBS_DIR) \
		-l:librustd_service.so.1 -l:librustd_journal.so.1 -l:librustd_login.so.1 -l:librustd_device.so.1 \
		-ldbus-1 -ljson-c \
		-o $@

$(LIBS_DIR)/librustd_service.so.1: ffi/native.c ffi/notify.c libs/service/abi.c libs/maps/librustd_service.map include/rustd/service.h
	mkdir -p $(LIBS_DIR)
	$(CC) $(CFLAGS) -fPIC $(LIB_CPPFLAGS) -shared \
		ffi/native.c ffi/notify.c libs/service/abi.c \
		-Wl,--version-script=libs/maps/librustd_service.map \
		-Wl,-soname,librustd_service.so.1 $(LIB_LDFLAGS) \
		-o $@

$(LIBS_DIR)/librustd_journal.so.1: libs/journal/journal.c libs/maps/librustd_journal.map include/rustd/journal.h
	mkdir -p $(LIBS_DIR)
	$(CC) $(CFLAGS) -fPIC $(LIB_CPPFLAGS) -shared \
		libs/journal/journal.c \
		-Wl,--version-script=libs/maps/librustd_journal.map \
		-Wl,-soname,librustd_journal.so.1 $(LIB_LDFLAGS) \
		-o $@

$(LIBS_DIR)/librustd_device.so.1: libs/device/device.c libs/maps/librustd_device.map include/rustd/device.h
	mkdir -p $(LIBS_DIR)
	$(CC) $(CFLAGS) -fPIC $(LIB_CPPFLAGS) -shared \
		libs/device/device.c \
		-Wl,--version-script=libs/maps/librustd_device.map \
		-Wl,-soname,librustd_device.so.1 $(LIB_LDFLAGS) \
		-o $@

$(LIBS_DIR)/librustd_login.so.1: libs/login/login.c libs/maps/librustd_login.map include/rustd/login.h
	mkdir -p $(LIBS_DIR)
	$(CC) $(CFLAGS) -fPIC $(LIB_CPPFLAGS) -shared \
		libs/login/login.c \
		-Wl,--version-script=libs/maps/librustd_login.map \
		-Wl,-soname,librustd_login.so.1 $(LIB_LDFLAGS) \
		-o $@

$(LIBS_DIR)/librustd_manager.so.1: libs/manager/manager.c libs/maps/librustd_manager.map include/rustd/manager.h
	mkdir -p $(LIBS_DIR)
	$(CC) $(CFLAGS) -fPIC $(LIB_CPPFLAGS) -shared \
		libs/manager/manager.c \
		-Wl,--version-script=libs/maps/librustd_manager.map \
		-Wl,-soname,librustd_manager.so.1 $(LIB_LDFLAGS) \
		-o $@

check-libs: libs
	$(CC) $(CFLAGS) $(LIB_CPPFLAGS) libs/tests/test_libs_smoke.c \
		-Wl,-rpath,$(abspath $(LIBS_DIR)) -L$(LIBS_DIR) \
		-lrustd_service -lrustd_journal -lrustd_device -lrustd_login -lrustd_manager \
		-o build/test_libs_smoke
	./build/test_libs_smoke
	@set -eu; \
	for lib in librustd_service librustd_journal librustd_device librustd_login librustd_manager; do \
		readelf -d "$(LIBS_DIR)/$$lib.so.1" | grep -Fq "Library soname: [$$lib.so.1]"; \
		! nm -D --defined-only "$(LIBS_DIR)/$$lib.so.1" | awk '{print $$3}' | grep -E '^(sd_|udev_)'; \
	done

check-compat: compat
	$(CC) $(CFLAGS) libs/tests/test_compat_abi.c \
		-Wl,-rpath,$(abspath $(LIBS_DIR)) -L$(LIBS_DIR) \
		-ludev -lsystemd -o build/test_compat_abi
	./build/test_compat_abi
	@set -eu; \
	readelf -d "$(LIBS_DIR)/libudev.so.1" | grep -Fq "Library soname: [libudev.so.1]"; \
	readelf -d "$(LIBS_DIR)/libsystemd.so.0" | grep -Fq "Library soname: [libsystemd.so.0]"; \
	nm -D --defined-only "$(LIBS_DIR)/libudev.so.1" | grep -Eq '[[:space:]]T udev_new(@@|$$)'; \
	nm -D --defined-only "$(LIBS_DIR)/libsystemd.so.0" | grep -Eq '[[:space:]]T sd_notify(@@|$$)'; \
	nm -D --defined-only "$(LIBS_DIR)/libsystemd.so.0" | grep -Eq '[[:space:]]T sd_booted(@@|$$)'; \
	! nm -D --defined-only "$(LIBS_DIR)/librustd_service.so.1" | awk '{print $$3}' | grep -E '^(sd_|udev_)'; \
	missing=0; \
	while read -r sym; do \
		[ -n "$$sym" ] || continue; \
		case "$$sym" in \
			udev_*) lib="$(LIBS_DIR)/libudev.so.1" ;; \
			sd_*) lib="$(LIBS_DIR)/libsystemd.so.0" ;; \
			*) continue ;; \
		esac; \
		if ! nm -D --defined-only "$$lib" | grep -Eq "[[:space:]][TDRB] $${sym}(@@|$$)"; then \
			echo "missing compat symbol: $$sym" >&2; missing=1; \
		fi; \
	done < libs/compat/needed_syms.txt; \
	if [ "$$missing" = 1 ]; then exit 1; fi; \
	echo "compat SONAMEs and symbol policy OK"
	$(CC) $(CFLAGS) $(COMPAT_CFLAGS) -DRUSTD_TEST_EVENT_ATTACHMENT -Ilibs/compat libs/tests/test_sd_bus_impl.c \
		-Wl,-rpath,$(abspath $(LIBS_DIR)) -L$(LIBS_DIR) -lsystemd -ldbus-1 \
		-o build/test_sd_bus_impl
	dbus-run-session -- ./build/test_sd_bus_impl
	$(CC) $(CFLAGS) $(COMPAT_CFLAGS) -Ilibs/compat libs/tests/test_sd_json_varlink_impl.c \
		-Wl,-rpath,$(abspath $(LIBS_DIR)) -L$(LIBS_DIR) -lsystemd \
		-o build/test_sd_json_varlink_impl
	./build/test_sd_json_varlink_impl
	$(CC) $(CFLAGS) -Ilibs/compat libs/tests/test_sd_varlink_idl_impl.c \
		-Wl,-rpath,$(abspath $(LIBS_DIR)) -L$(LIBS_DIR) -lsystemd \
		-o build/test_sd_varlink_idl_impl
	./build/test_sd_varlink_idl_impl
	$(CC) $(CFLAGS) -Iinclude libs/tests/test_journal_send_impl.c \
		libs/compat/journal_send_impl.c -o build/test_journal_send_impl
	./build/test_journal_send_impl
	$(CC) $(CFLAGS) -Iinclude libs/tests/test_journal_filters.c \
		-Wl,-rpath,$(abspath $(LIBS_DIR)) -L$(LIBS_DIR) -lrustd_journal \
		-o build/test_journal_filters
	./build/test_journal_filters

check-logind: pam-module
	bash tests/pam_logind_integration.sh

check-compat-closure: compat
	@test -n "$(REPORT)" || (echo "REPORT=<systemd closure audit JSON> is required" >&2; exit 64)
	python3 scripts/check-compat-closure.py \
		--report "$(REPORT)" \
		--libsystemd "$(LIBS_DIR)/libsystemd.so.0" \
		--libudev "$(LIBS_DIR)/libudev.so.1"

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
	$(MAKE) check-libs

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
	bash -n scripts/boot-smoke.sh scripts/install-rustd-names.sh scripts/check-reproducible-release.sh scripts/installed-certification.sh scripts/performance-promotion.sh scripts/exclusive-cutover-gate.sh scripts/ci-pid1-initramfs.sh scripts/check-native-libs.sh tests/pam_logind_integration.sh
	python3 -m py_compile scripts/executable_contract.py scripts/check-executable-inventory.py scripts/install-executable-surfaces.py scripts/validate-resolver-certification-report.py
	@set -eu; \
	work=$$(mktemp -d); \
	trap 'rm -rf "$$work"' EXIT HUP INT TERM; \
	cargo metadata --locked --no-deps --format-version 1 >"$$work/cargo-metadata.json"; \
	python3 scripts/check-executable-inventory.py "$$work/cargo-metadata.json"; \
	test -x scripts/boot-smoke.sh; \
	grep -Fq 'RUSTCTL="$${RUSTCTL:-/usr/bin/rustctl}"' scripts/boot-smoke.sh; \
	grep -Fq 'PID 1 executable is rustd' scripts/boot-smoke.sh; \
	grep -Fq 'rustd-journald.service' scripts/boot-smoke.sh; \
	grep -Fq '/run/rustd/ctl.sock' scripts/boot-smoke.sh; \
	grep -Fq '/run/rustd/journal/socket' scripts/boot-smoke.sh; \
	! grep -E -q 'systemctl|systemd-journald|/run/systemd' scripts/boot-smoke.sh; \
	test -f packaging/tmpfiles/rustd.conf; \
	grep -Fq '/run/rustd' packaging/tmpfiles/rustd.conf; \
	grep -Fq '/run/user' packaging/tmpfiles/rustd.conf; \
	! grep -Fq '/run/systemd' packaging/tmpfiles/rustd.conf; \
	test -d packaging/rustd; \
	test ! -e packaging/systemd; \
	for unit in default.target graphical.target sysinit.target basic.target multi-user.target rescue.target emergency.target shutdown.target umount.target getty.target getty@.service serial-getty@.service container-getty@.service console-getty.service dbus.service display-manager.service plasmalogin.service rustd-journald.service rustd-logind.service rustd-udevd.service rustd-tmpfiles-setup.service rustd-tmpfiles-setup-dev.service rustd-udev-trigger.service rustd-udev-settle.service rustd-user-sessions.service user@.service; do test -f "packaging/rustd/$$unit"; done; \
	grep -Fq 'ExecStart=/usr/lib/rustd/rustd-journald --runtime-directory /run/rustd/journal' packaging/rustd/rustd-journald.service; \
	grep -Fq 'ExecStart=/usr/lib/rustd/rustd-logind' packaging/rustd/rustd-logind.service; \
	grep -Fq 'ConditionPathExists=/sys' packaging/rustd/rustd-udevd.service; \
	! grep -Fq 'ConditionPathIsReadWrite=/sys' packaging/rustd/rustd-udevd.service; \
	grep -Fq 'ExecStart=/usr/lib/rustd/rustd --user' packaging/rustd/user@.service; \
	grep -Fq 'ExecStart=/usr/bin/dbus-daemon' packaging/rustd/dbus.service; \
	test -f packaging/dbus/io.rustd.Login1.service; \
	grep -Fq 'Exec=/usr/lib/rustd/rustd-logind' packaging/dbus/io.rustd.Login1.service; \
	test -f packaging/dbus/org.freedesktop.login1.service; \
	grep -Fq 'Exec=/usr/lib/rustd/rustd-logind' packaging/dbus/org.freedesktop.login1.service; \
	test -f packaging/dbus/io.rustd.Login1.conf; \
	test -f packaging/dbus/io.rustd.Hostname1.service; \
	test -f packaging/dbus/io.rustd.Locale1.service; \
	grep -Fq '<allow own="io.rustd.Login1"/>' packaging/dbus/io.rustd.Login1.conf; \
	test -f include/rustd/service.h; \
	test -f include/rustd/journal.h; \
	test -f include/rustd/device.h; \
	test -f include/rustd/login.h; \
	test -f include/rustd/manager.h; \
	test -f packaging/pkgconfig/rustd-service.pc; \
	test -f packaging/pkgconfig/rustd-device.pc; \
	if grep -R -E -q 'org\.freedesktop\.systemd1|/usr/lib/systemd|/run/systemd|systemd-udevd|systemd-libs' packaging; then exit 1; fi; \
	if find packaging -type f -o -type l | grep -E '/(systemd|systemctl|journalctl|udevadm)([^/]*$$|/)'; then exit 1; fi; \
	if grep -R -E -q 'libsystemd\.so|libudev\.so|Provides:.*systemd-libs' packaging include; then exit 1; fi; \
	if grep -R -E -q 'libsystemd\.so|libudev\.so' libs --exclude-dir=compat --exclude='libudev.map' --exclude='libsystemd.map'; then exit 1; fi

check-reproducible:
	bash scripts/check-reproducible-release.sh

test: check-native check-packaging

install: build pam-module libs
	@test -n "$(DESTDIR)" && test "$(DESTDIR)" != "/" || (echo "DESTDIR must name a non-root staging directory" >&2; exit 64)
	DESTDIR="$(DESTDIR)" PREFIX="$(PREFIX)" RUSTLIBEXECDIR="$(RUSTLIBEXECDIR)" BUILDDIR="$(RELEASE_DIR)" bash scripts/install-rustd-names.sh
	for file in packaging/rustd/*; do \
		[ -f "$$file" ] || continue; \
		install -Dm0644 "$$file" "$(DESTDIR)$(RUSTUNITDIR)/$$(basename "$$file")"; \
	done
	for file in packaging/dbus/*.service; do install -Dm0644 "$$file" "$(DESTDIR)$(DBUS_SYSTEM_SERVICEDIR)/$$(basename "$$file")"; done
	for file in packaging/dbus/*.conf; do install -Dm0644 "$$file" "$(DESTDIR)$(DBUS_SYSTEM_POLICYDIR)/$$(basename "$$file")"; done
	for file in packaging/polkit/*.policy; do install -Dm0644 "$$file" "$(DESTDIR)$(POLKIT_ACTIONDIR)/$$(basename "$$file")"; done
	install -Dm0644 packaging/tmpfiles/rustd.conf $(DESTDIR)$(TMPFILESDIR)/rustd.conf
	install -Dm0755 $(PAM_MODULE) "$(DESTDIR)$(PAMLIBDIR)/pam_rustd.so"
	for hdr in include/rustd/*.h; do \
		install -Dm0644 "$$hdr" "$(DESTDIR)$(INCLUDEDIR)/rustd/$$(basename "$$hdr")"; \
	done
	for lib in librustd_service librustd_journal librustd_device librustd_login librustd_manager; do \
		install -Dm0755 "$(LIBS_DIR)/$$lib.so.1" "$(DESTDIR)$(LIBDIR)/$$lib.so.1"; \
		ln -sfn "$$lib.so.1" "$(DESTDIR)$(LIBDIR)/$$lib.so"; \
	done
	for pc in packaging/pkgconfig/*.pc; do \
		install -Dm0644 "$$pc" "$(DESTDIR)$(PKGCONFIGDIR)/$$(basename "$$pc")"; \
	done
	bash scripts/check-native-libs.sh "$(DESTDIR)$(PREFIX)"

clean:
	rm -rf build $(TARGET_DIR)

release: build libs test check-formal check-reproducible

boot-smoke:
	bash scripts/boot-smoke.sh

installed-certification:
	bash scripts/installed-certification.sh

performance-promotion:
	bash scripts/performance-promotion.sh

certify: release boot-smoke installed-certification
