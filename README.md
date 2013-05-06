This is DNSFlow - 
Lightweight DNS telemetry

# Quick start
 * [Download the latest release](https://github.com/deepfield/dnsflow/archive/master.tar.gz).
 * Install Dependencies
 * Build dnsflow

# Building
```
cd dnsflow
make
make install  # optional
```

# Dependencies

## Ubuntu/Debian install
```
sudo apt-get install build-essential libpcap-dev libevent-dev libldns-dev
```

## Manual Install
You may need to install the dependencies for your distribution manually.

For redhat, you may have to install flex/bison first (for pcap):
```
yum install flex bison
```

### ldns

```
curl -O http://nlnetlabs.nl/downloads/ldns/ldns-1.6.16.tar.gz
tar xvf ldns-1.6.16.tar.gz
cd ldns-1.6.16
./configure --disable-gost --disable-ecdsa --disable-sha2 --without-ssl --prefix=/usr
make; make install; ldconfig
```

### libpcap

```
curl -O http://www.tcpdump.org/release/libpcap-1.3.0.tar.gz
tar xf libpcap-1.3.0.tar.gz
cd libpcap-1.3.0
./configure
make; make install; ldconfig
```

### libevent
```
curl -L -O https://github.com/downloads/libevent/libevent/libevent-2.0.21-stable.tar.gz
tar xf libevent-2.0.21-stable.tar.gz
cd libevent-2.0.21-stable
./configure
make; make install; ldconfig
```

# Dependency Links

ldns
http://nlnetlabs.nl/projects/ldns/

libevent
http://monkey.org/~provos/libevent/

pcap
http://www.tcpdump.org/


