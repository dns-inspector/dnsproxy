Name:           dnsproxy
Version:        %{_version}
Release:        1
Summary:        DNS Proxy for DNS over HTTPS and DNS over TLS
License:        GPL-3.0
Source0:        %{name}-%{version}.tar.gz
BuildRequires:  systemd-rpm-macros
Provides:       %{name} = %{version}
Prefix:         /etc
URL:            https://github.com/dns-inspector/dnsproxy
BugURL:         https://github.com/dns-inspector/dnsproxy/issues

%description
dnsproxy is a server that proxies DNS over TLS and DNS over HTTPS requests to a standard DNS server.

%global debug_package %{nil}

%prep
%autosetup

%build
cd cmd/dnsproxy
CGO_ENABLED=0 GOAMD64=v2 go build -v -buildmode=exe -trimpath -ldflags="-s -w -X 'dnsproxy.Version=%{version}' -X 'dnsproxy.BuiltOn=%{_date}' -X 'dnsproxy.Revision=%{_revision}'"
./dnsproxy -v

%install
mkdir -p %{buildroot}/etc/dnsproxy
install -Dpm 0755 cmd/dnsproxy/dnsproxy %{buildroot}/usr/sbin/dnsproxy
install -Dpm 644 dnsproxy.conf %{buildroot}/etc/dnsproxy/dnsproxy.conf
install -Dpm 644 dnsproxy.service %{buildroot}%{_unitdir}/dnsproxy.service

%check
CGO_ENABLED=0 GOAMD64=v2 go build -v ./...

%post
%systemd_post dnsproxy.service

%posttrans
if test $(readlink /proc/*/exe | grep /etc/dnsproxy/dnsproxy | wc -l) = 1; then
    systemctl restart dnsproxy.service
fi

%preun
%systemd_preun dnsproxy.service

%files
/usr/sbin/dnsproxy
/etc/dnsproxy/dnsproxy.conf
%{_unitdir}/dnsproxy.service
