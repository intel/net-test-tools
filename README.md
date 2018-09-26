
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
sent to trace interface and then forwared to the UDP socket.

Revervse operations are applied on input from the UDP socket.

Protocol test suites are expected to communicate with the UDP socket.

The UDP encapsulation is ensuring that:

- The communication is isolated from the host's TCP/IP stack, so there's
  no interference with the host's system (it's safe to send malformed data)
  and there's no intrusion from the host's TCP/IP stack into protocol
  communication procedures.
- No admin privieges are required in order to configure extra virtual
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
UDP/IPv4 to localhost:5555.

The communication can be observed and analyzed with Wireshark:

```
    # sudo apt-get install wireshark-gtk
    # wireshark-gtk -p -i lo -f "udp port 5555" -d udp.port==5555,eth -k &
```

### Enhancement Plans

- Make it possible to insert, remove, change the order of the protocl modules,
  insert a module at any specific position.

See also TODO.txt.

#### Reporting a Security Issue

If you have information about a security issue or vulnerability,
please follow the process at [https://01.org/security](https://01.org/security)

