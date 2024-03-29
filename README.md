DISCONTINUATION OF PROJECT

This project will no longer be maintained by Intel.

Intel has ceased development and contributions including, but not limited to, maintenance, bug fixes, new releases, or updates, to this project.  

Intel no longer accepts patches to this project.

If you have an ongoing need to use this project, are interested in independently developing it, or would like to maintain patches for the open source software community, please create your own fork of this project.  

Contact: webadmin@linux.intel.com

# Net-test-tools

## Introduction

This package contains the slipcat, a testing utility that can connect
protocol test suites and systems under test in a flexible and configurable way.

Slipcat can understand Serial Line IP protocol (SLIP) on one side,
and can act similarly to other Linux network utilities like netcat or socat.

- Slipcat consists of a set of protocol modules that are chained serially.
- Each module is a simple task, performing encapsulation/decapsulation
  of a specific protocol.

The utility is very basic and still work in progress.

## Usage with Zephyr TCP/IP stack and protocol test suites (net-test-suites) 

Currently, the slipcat is suitable for connecting [net-test-suites]
(https://github.com/intel/net-test-suites) and Zephyr OS echo-server
sample application running under QEMU.

With no parameters, the slipcat defaults to AF_UNIX stream socket
(/tmp/slip.sock), waiting for connection from QEMU.

Input data from AF_UNIX socket is passed through the SLIP protocol module,
sent to trace interface and then forwarded to the UDP socket.

Reverse operations are applied on input from the UDP socket.

Protocol test suites are expected to communicate with the UDP socket.

The UDP encapsulation is ensuring that:

- The communication is isolated from the host's TCP/IP stack, so there's
  no interference with the host's system (it's safe to send malformed data)
  and there's no intrusion from the host's TCP/IP stack into protocol
  communication procedures.
- No admin privileges are required in order to configure extra virtual
  network interfaces or access them.

Expected input data on both sockets are Ethernet frames.

## Building and Running

### Install the dependencies

```
    # sudo apt-get install libglib2.0-dev
```

### Build

```
    # ./autogen.sh
    # make
```

### Run

```
    # ./loop-slipcat.sh
```

## Observing the Communication

By default, the trace module duplicates traffic and sends it over
UDP/IPv4 to localhost:7777.

The communication can be observed and analyzed with Wireshark:

```
    # sudo apt-get install wireshark
    # wireshark -p -i lo -f "udp port 7777" -d udp.port==7777,eth -k &
```

### Enhancement Plans

- Make it possible to insert, remove, change the order of the protocol modules,
  insert a module at any specific position.

See also TODO.txt.

#### Reporting a Security Issue

If you have information about a security issue or vulnerability,
please follow the process at [https://01.org/security](https://01.org/security)

