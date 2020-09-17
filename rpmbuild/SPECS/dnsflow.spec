Name:           dnsflow
Version:        1.4
Release:        1%{?dist}
Summary:        Convert DNS pcap to compressed DNSFlow

License:        GPL
URL:            https://github.com/deepfield/dnsflow
Source0:        dnsflow-1.4.tar.gz

Requires: ldns-devel libpcap-devel libevent-devel openssl-devel
Requires(post): info
Requires(preun): info

%description
Convert DNS pcap to compressed DNSFlow

%prep
%setup

%build
make PREFIX=/usr %{?_smp_mflags}

%install
make PREFIX=/usr DESTDIR=%{?buildroot} install
make DESTDIR=%{?buildroot} install-service

%clean
rm -rf %{buildroot}

%files
%{_bindir}/dnsflow
%{_usr}/lib/systemd/system/dnsflow.service
