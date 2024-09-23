# ipvs-tcpstate

An implementation of [tcpstates.py](https://github.com/iovisor/bcc/blob/master/tools/tcpstates.py) using Aya, in Rust.

This repository will also de-reference the virtual IP from IPVS connections to the real server's address.

Running the example, you get something like this

```
# TCP transition 1 Close -> SynSent -- `dst` is virtual; unclear what the real IP is
TcpSocketEvent { oldstate: Close, newstate: SynSent, sport: 0, dport: 33, dst: 1.2.3.4, svc: None }
# TCP Transition 2 SynSent -> Established -- `dst` is virtual, but `svc.daddr` contains the real IP
TcpSocketEvent { oldstate: SynSent, newstate: Established, sport: 36572, dport: 33, dst: 1.2.3.4, svc: Some(IpvsDest { daddr: 192.168.2.1, dport: 22 }) }
TcpSocketEvent { oldstate: Established, newstate: FinWait1, sport: 36572, dport: 33, dst: 1.2.3.4, svc: Some(IpvsDest { daddr: 192.168.2.1, dport: 22 }) }
TcpSocketEvent { oldstate: FinWait1, newstate: FinWait2, sport: 36572, dport: 33, dst: 1.2.3.4, svc: Some(IpvsDest { daddr: 192.168.2.1, dport: 22 }) }
TcpSocketEvent { oldstate: FinWait2, newstate: Close, sport: 36572, dport: 33, dst: 1.2.3.4, svc: Some(IpvsDest { daddr: 192.168.2.1, dport: 22 }) }
```

For a connection that's timing out before establishing, a `TcpSocketEvent` will be sent per TCP retransmit, including the real server's address
```
# Open connection, svc is not known yet, as sport is not yet determined
TcpSocketEvent { oldstate: Close, newstate: SynSent, sport: 0, dport: 33, dst: 1.2.3.4, svc: None }
# Retransmit, includes real address, 1s later by default
TcpSocketEvent { oldstate: SynSent, newstate: SynSent, sport: 43782, dport: 33, dst: 1.2.3.4, svc: Some(IpvsDest { daddr: 8.8.8.8, dport: 33 }) }
TcpSocketEvent { oldstate: SynSent, newstate: SynSent, sport: 43782, dport: 33, dst: 1.2.3.4, svc: Some(IpvsDest { daddr: 8.8.8.8, dport: 33 }) }
TcpSocketEvent { oldstate: SynSent, newstate: SynSent, sport: 43782, dport: 33, dst: 1.2.3.4, svc: Some(IpvsDest { daddr: 8.8.8.8, dport: 33 }) }
TcpSocketEvent { oldstate: SynSent, newstate: SynSent, sport: 43782, dport: 33, dst: 1.2.3.4, svc: Some(IpvsDest { daddr: 8.8.8.8, dport: 33 }) }
TcpSocketEvent { oldstate: SynSent, newstate: Close, sport: 43782, dport: 33, dst: 1.2.3.4, svc: Some(IpvsDest { daddr: 8.8.8.8, dport: 33 }) }
```

This library does *not* return TcpSocketEvents where the svc is unknown, which filters out all non-IPVS events, but also the `Close->SynSent` transition.

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
$ aya-tool generate trace_event_raw_inet_sock_set_state trace_event_raw_tcp_event_sk_skb > tracepoint.rs
```

`trace_event_raw_inet_sock_set_state` comes from

```
$ grep inet_sock_set_state /proc/kallsyms    | grep trace_ev
0000000000000000 t __pfx_trace_event_raw_event_inet_sock_set_state
0000000000000000 t trace_event_raw_event_inet_sock_set_state
```

where `trace_event_raw_event_inet_sock_set_state` (kallsym output) has the word `event` removed (`trace_event_raw_event...` -> `trace_event_raw...`)

Similarly, `trace_event_raw_event_tcp_event_sk_skb` (kallsym output) becomes `trace_event_raw_tcp_event_sk_skb`
