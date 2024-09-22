# ipvs-tcpstate

An implementation of [tcpstates.py](https://github.com/iovisor/bcc/blob/master/tools/tcpstates.py) using Aya, in Rust.

This repository will also de-reference the virtual IP from IPVS connections to the real server's address.

Running the example, you get something like this

```
# TCP transition 1 Close -> SynSent -- `dst` is virtual; unclear what the real IP is
got = TcpSocketEvent { oldstate: Close, newstate: SynSent, sport: 0, dport: 33, dst: 1.2.3.4, svc: None }
# TCP Transition 2 SynSent -> Established -- `dst` is virtual, but `svc.daddr` contains the real IP
got = TcpSocketEvent { oldstate: SynSent, newstate: Established, sport: 36572, dport: 33, dst: 1.2.3.4, svc: Some(IpvsDest { daddr: 192.168.2.1, dport: 22 }) }
got = TcpSocketEvent { oldstate: Established, newstate: FinWait1, sport: 36572, dport: 33, dst: 1.2.3.4, svc: Some(IpvsDest { daddr: 192.168.2.1, dport: 22 }) }
got = TcpSocketEvent { oldstate: FinWait1, newstate: FinWait2, sport: 36572, dport: 33, dst: 1.2.3.4, svc: Some(IpvsDest { daddr: 192.168.2.1, dport: 22 }) }
got = TcpSocketEvent { oldstate: FinWait2, newstate: Close, sport: 36572, dport: 33, dst: 1.2.3.4, svc: Some(IpvsDest { daddr: 192.168.2.1, dport: 22 }) }
```

## Prerequisites

1. Install bpf-linker: `cargo install bpf-linker`

## Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag.

## Build Userspace

```bash
cargo build
```

## Build eBPF and Userspace

```bash
cargo xtask build
```

## Run

```bash
RUST_LOG=info cargo xtask run
```


## Generate headers

```bash
$ aya-tool generate trace_event_raw_inet_sock_set_state > tracepoint.rs
```
