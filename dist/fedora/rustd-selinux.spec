%global selinuxtype targeted
%global moduletype contrib
%global modulename rustd_fedora

Name:           rustd-selinux
Version:        0.1.2
Release:        7%{?dist}
Summary:        SELinux policy labels and resolver state rules for RustD on Fedora
License:        LGPL-2.1-or-later
URL:            https://github.com/SisyphusAeolides/rustd
Source0:        rustd-%{version}.tar.gz

BuildArch:      noarch
BuildRequires:  make
BuildRequires:  bzip2
BuildRequires:  selinux-policy
BuildRequires:  selinux-policy-devel
Requires(post): selinux-policy-%{selinuxtype} >= %{_selinux_policy_version}
Requires(post): libselinux-utils
Requires(post): policycoreutils
Requires(postun): policycoreutils
Requires:       rustd = %{version}-%{release}

%description
Fedora SELinux policy extension for RustD. RustD reuses Fedora's mature init,
logind, udev, and resolved confinement domains for equivalent executables and
adds only a dedicated writable type for RFC5011 resolver state. This package
does not create permissive or unconfined RustD domains.

%prep
%autosetup -n rustd-%{version}

%build
mkdir -p selinux-build
cp dist/fedora/selinux/%{modulename}.te selinux-build/
cp dist/fedora/selinux/%{modulename}.fc selinux-build/
make -C selinux-build -f %{_datadir}/selinux/devel/Makefile %{modulename}.pp
bzip2 -9 selinux-build/%{modulename}.pp

%check
test -s selinux-build/%{modulename}.pp.bz2
bzip2 -t selinux-build/%{modulename}.pp.bz2
# Fedora's SELinux devel Makefile expands the reference-policy interfaces and
# validates all referenced types against the installed Fedora policy. A raw
# checkmodule invocation is deliberately not used here because it cannot
# compile reference-policy interface macros in isolation.

%install
install -D -m0644 selinux-build/%{modulename}.pp.bz2 \
    %{buildroot}%{_datadir}/selinux/packages/%{selinuxtype}/%{modulename}.pp.bz2

%files
%license LICENSE*
%{_datadir}/selinux/packages/%{selinuxtype}/%{modulename}.pp.bz2
%ghost %{_selinux_store_path}/%{selinuxtype}/active/modules/200/%{modulename}

%pre
%selinux_relabel_pre -s %{selinuxtype}

%post
%selinux_modules_install -s %{selinuxtype} %{_datadir}/selinux/packages/%{selinuxtype}/%{modulename}.pp.bz2
%selinux_relabel_post -s %{selinuxtype}

%postun
%selinux_modules_uninstall -s %{selinuxtype} %{modulename}
%selinux_relabel_post -s %{selinuxtype}

%changelog
* Mon Aug 31 2026 Sisyphus Aeolides <SisyphusAeolides@pm.me> - 0.1.2-8
- Coordinate the live-media udev condition fix

* Mon Aug 31 2026 Sisyphus Aeolides <SisyphusAeolides@pm.me> - 0.1.2-7
- Label /run/user and permit the confined D-Bus logind activation pipe

* Mon Aug 31 2026 Sisyphus Aeolides <SisyphusAeolides@pm.me> - 0.1.2-6
- Add the confined D-Bus to logind domain transition

* Mon Aug 31 2026 Sisyphus Aeolides <SisyphusAeolides@pm.me> - 0.1.2-5
- Coordinate the standard D-Bus logind activation fix

* Mon Aug 31 2026 Sisyphus Aeolides <SisyphusAeolides@pm.me> - 0.1.2-4
- Bump the coordinated RustD package release for live dracut compatibility

* Sun Aug 30 2026 Sisyphus Aeolides <SisyphusAeolides@pm.me> - 0.1.2-3
- Bump the coordinated RustD package release for the dracut compatibility module

* Sun Aug 30 2026 Kenny Glowner <SisyphusAeolides@pm.me> - 0.1.2-2
- Bump the coordinated RustD package release for the initramfs udev fix

* Tue Aug 18 2026 Kenny Glowner <SisyphusAeolides@pm.me> - 0.1.2-1
- Add Fedora enforcing-mode RustD SELinux policy extension
