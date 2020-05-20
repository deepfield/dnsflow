# DNSFlow &mdash; Lightweight DNS telemetry

## Quick start
 * [Download the latest release](https://github.com/deepfield/dnsflow/archive/master.tar.gz)
 * [Install Dependencies](#dependencies)
 * [Install Reader Dependencies](#install-dnsflow-reader-dependencies)
 * [Build DNSFlow](#building-dnsflow-daemon)
 * [Running](#running)
 * [Running as an Upstart job](#running-as-an-upstart-job)
 * [High-Flow Multi-Process Performance](#high-flow-multi-process-performance)

## Running
After you get it built, start the daemon that will forward the DNS (to the localhost in this case):
```
./dnsflow -i eth0 -u 127.0.0.1 -P /tmp/dnsflow.pid
```

The daemon can also run in multi-process mode to take advantage of multiple cores. Use the -M option. In this case, dnsflow will run as 4 processes.
```
./dnsflow -i eth0 -u 127.0.0.1 -P /tmp/dnsflow.pid -M 4
```

Use the -s option to randomly sample 1 out of N DNS packets. For highest accuracy, use this as a last resort, and keep the rate as low as possible. For example, to sample 1 out of 2 (50%).
```
./dnsflow -i eth0 -u 127.0.0.1 -P /tmp/dnsflow.pid -M 4 -s 2
```

Read the packets being sent to the local host:
```
./dnsflow_read.py -i lo
```

## Running as an Upstart job
Running as an Upstart job requires DNSFlow to be installed on a Ubuntu/Debian deployment. These commands should be run with root privileges.

Starting DNSFlow.
```
service dnsflow start
```

Stopping DNSFlow.
```
service dnsflow stop
```

Restarting DNSFlow.
```
service dnsflow restart
```

Command line options, pid file location, and DNSFlow binary location can be specified in the following location:
```
/etc/default/dnsflow
```

## High-Flow Multi-Process Performance

When running in multi-process mode (using -M <nprocs>), it is
important to consider both the hardware capabilities of the machine
you are running on and the characteristics of the processes that are
running. For this application, although processes must wait for
packets to arrive over the network, in high-flow situations these
dnsflow processes are CPU hungry. Thus, in the common case of running
on multi-core, shared-memory, commodity-hardware machine (e.g., 32
cores, 64 GB of RAM), it does not make sense to set the number of
processes to more than the number of CPUs. Typically, the ideal number
of processes is roughly **half of the number of CPUs**, as the CPUs
themselves also share hardware resources. This can be set
automatically with `-M 0`.

Along with the number processes, the share of packets consumed by each
process is important. The default multi-processing filter distributes
packets based on a modulo of the DNS response destination for ipv4
addresses, and the UDP checksum for ipv6 DNS responses. This can be
good enough in moderate flow situations, but may result in packets
being lost if flow is high and not evenly distributed over client ipv4
addresses. The `-c` option activates a new multi-process filter that
utilizes the ipv4 checksum when it is available, falling back to the
default ipv4 filter when it is not. This balancing mode tends to
provide better load balance over many processes, which may result in
fewer packets being dropped.

If you would like automatically apply the recommended high-performance
settings discussed above, launch the application with the following
two additional options:
```
sudo ./dnsflow .. -c -M 0
```

If you suspect additional speedup is possible by utilizing more than
half of the available CPUs, we recommend you verify this by examining
the total time to process a large pcap file under different -M
settings on the target machine. A good procedure is to start with a
small setting for M, then doubling it until the total processing time no
longer decreases.

## Install DNSFlow Reader Dependencies
The dnsflow reader is a python script with the following dependencies:

Install the python package installer pip (via apt on Ubuntu).
```
sudo apt-get install python-pip
```

Install python pip modules for dpkt and ipaddr.
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



## Installing Source RPM

In additional to installing from source code, you can choose to build
the CentOS / RedHat 7 RPM

```
> yum-config-manager --enable rhui-REGION-rhel-server-extras rhui-REGION-rhel-server-optional
> sudo yum install /tmp/dnsflow-1.1-1.el7.x86_64.rpm
> sudo vi /lib/systemd/system/dnsflow.service
   edit destination IP and interface
> sudo service dnsflow start
```
