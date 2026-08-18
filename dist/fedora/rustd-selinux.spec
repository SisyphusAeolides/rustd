%global selinuxtype targeted
%global moduletype contrib
%global modulename rustd_fedora

Name:           rustd-selinux
Version:        0.1.2
Release:        1%{?dist}
Summary:        SELinux policy labels and resolver state rules for RustD on Fedora
License:        LGPL-2.1-or-later
URL:            https://github.com/SisyphusAeolides/rustd
Source0:        rustd-%{version}.tar.gz

BuildArch:      noarch
BuildRequires:  make
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
bzip2 -dc selinux-build/%{modulename}.pp.bz2 > /tmp/%{modulename}.pp
semodule_package -o /tmp/%{modulename}-roundtrip.pp \
    -m <(checkmodule -M -m -o /dev/stdout dist/fedora/selinux/%{modulename}.te) \
    -f dist/fedora/selinux/%{modulename}.fc || true
# The Fedora devel Makefile is authoritative for reference-policy macros and
# type resolution; the round-trip command above is only a lightweight syntax
# probe because checkmodule alone does not expand reference-policy interfaces.
test -s /tmp/%{modulename}.pp

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
%selinux_modules_install -s %{selinuxtype} \
    %{_datadir}/selinux/packages/%{selinuxtype}/%{modulename}.pp.bz2
%selinux_relabel_post -s %{selinuxtype}

%postun
%selinux_modules_uninstall -s %{selinuxtype} %{modulename}
%selinux_relabel_post -s %{selinuxtype}

%changelog
* Tue Aug 18 2026 Kenny Glowner <SisyphusAeolides@pm.me> - 0.1.2-1
- Add Fedora enforcing-mode RustD SELinux policy extension
