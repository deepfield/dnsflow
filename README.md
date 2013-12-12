# DNSFlow &mdash; Lightweight DNS telemetry

## Quick start
 * [Download the latest release](https://github.com/deepfield/dnsflow/archive/master.tar.gz)
 * [Install Dependencies](#dependencies)
 * [Install Reader Dependencies](#install dnsflow reader dependencies)
 * [Build DNSFlow](#building dnsflow daemon)
 * [Running](#running)

## Running 
After you get it built, start the daemon that will forward the DNS (to the localhost in this case):
```
./dnsflow -i eth0 -u 127.0.0.1 -P /tmp/dnsflow.pid
```

Read the packets being sent to the local host:
```
./dnsflow_read.py -i eth0
```

## Install DNSFlow Reader Dependencies
The dnsflow reader is python module that has a few dependencies.

Install python pip modules.
```
sudo pip install dpkt ipaddr
```

Download [python-libpcap](http://sourceforge.net/projects/pylibpcap/files/pylibpcap/0.6.4).
```
tar xvfz pylibpcap-0.6.4.tar.gz
cd pylibpcap-0.6.4
sudo python ./setup.py install
```

## Building DNSFlow daemon
```
cd dnsflow
make
make install  # optional
```

## Dependencies

### Ubuntu/Debian Install
```
sudo apt-get install build-essential libpcap-dev libevent-dev libldns-dev
```

### Manual Install
You may need to install the dependencies for your distribution manually.

For RedHat, you may have to install flex/bison first (for pcap):
```
yum install flex bison
```

#### ldns

```
curl -O http://nlnetlabs.nl/downloads/ldns/ldns-1.6.16.tar.gz
tar xvf ldns-1.6.16.tar.gz
cd ldns-1.6.16
./configure --disable-gost --disable-ecdsa --disable-sha2 --without-ssl --prefix=/usr
make; make install; ldconfig
```

#### libpcap

```
curl -O http://www.tcpdump.org/release/libpcap-1.3.0.tar.gz
tar xf libpcap-1.3.0.tar.gz
cd libpcap-1.3.0
./configure
make; make install; ldconfig
```

#### libevent
```
curl -L -O https://github.com/downloads/libevent/libevent/libevent-2.0.21-stable.tar.gz
tar xf libevent-2.0.21-stable.tar.gz
cd libevent-2.0.21-stable
./configure
make; make install; ldconfig
```

## Dependency Links

- [ldns](http://nlnetlabs.nl/projects/ldns/)
- [libevent](http://monkey.org/~provos/libevent/)
- [pcap](http://www.tcpdump.org/)
