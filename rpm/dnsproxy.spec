Name:           dnsproxy
Version:        %{_version}
Release:        1
Summary:        DNS Proxy for DNS over HTTPS and DNS over TLS
License:        GPL-3.0
Source0:        %{name}-%{version}.tar.gz
BuildRequires:  systemd-rpm-macros
Provides:       %{name} = %{version}
Prefix:         /opt

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
mkdir -p %{buildroot}/opt/%{name}
install -Dpm 0700 cmd/dnsproxy/dnsproxy %{buildroot}/opt/%{name}/dnsproxy
install -Dpm 644 %{name}.service %{buildroot}%{_unitdir}/%{name}.service

%check
CGO_ENABLED=0 GOAMD64=v2 go build -v ./...

%post
%systemd_post %{name}.service

%posttrans
if test $(readlink /proc/*/exe | grep /opt/%{name}/dnsproxy | wc -l) = 1; then
    systemctl restart %{name}.service
fi

%preun
%systemd_preun %{name}.service

%files
/opt/%{name}/dnsproxy
%{_unitdir}/%{name}.service
