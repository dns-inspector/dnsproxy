Name:           dnsproxy
Version:        %{_version}
Release:        1
Summary:        DNS Proxy for DNS over HTTPS, DNS over TLS, and DNS over Quic
License:        GPL-3.0
Source0:        %{name}-%{version}.tar.gz
BuildRequires:  systemd-rpm-macros
Provides:       %{name} = %{version}
Prefix:         /etc
URL:            https://github.com/dns-inspector/dnsproxy
BugURL:         https://github.com/dns-inspector/dnsproxy/issues

%description
dnsproxy is a server that proxies DNS over TLS, DNS over HTTPS, and DNS over Quic requests to a standard DNS server.

%global debug_package %{nil}

%prep
%autosetup

%build

%install
mkdir -p %{buildroot}/etc/dnsproxy
install -Dpm 0755 dnsproxy %{buildroot}/usr/sbin/dnsproxy
install -Dpm 644 dnsproxy.conf %{buildroot}/etc/dnsproxy/dnsproxy.conf.example
install -Dpm 644 dnsproxy.service %{buildroot}%{_unitdir}/dnsproxy.service
install -Dpm 644 10-udpbuf.conf %{buildroot}/etc/sysctl.d/10-udpbuf.conf

%check

%post
%systemd_post dnsproxy.service
getent group dnsproxy >/dev/null 2>&1 || groupadd -r -g 172 dnsproxy
id dnsproxy >/dev/null 2>&1 || useradd -M -g dnsproxy -r -s /sbin/nologin dnsproxy
mkdir -p /var/log/dnsproxy
chown root:dnsproxy /var/log/dnsproxy
chmod 0775 /var/log/dnsproxy
sysctl --system >/dev/null

%posttrans
if test $(readlink /proc/*/exe | grep /etc/dnsproxy/dnsproxy | wc -l) = 1; then
    systemctl restart dnsproxy.service
fi

%preun
%systemd_preun dnsproxy.service
if [ $1 -eq 0 ]; then
    userdel -f dnsproxy >/dev/null 2>&1 || true
    groupdel -f dnsproxy >/dev/null 2>&1 || true
fi

%files
/usr/sbin/dnsproxy
/etc/dnsproxy/dnsproxy.conf.example
/etc/sysctl.d/10-udpbuf.conf
%{_unitdir}/dnsproxy.service
