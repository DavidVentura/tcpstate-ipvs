# ipvs-tcpstate

An implementation of [tcpstates.py](https://github.com/iovisor/bcc/blob/master/tools/tcpstates.py) using Aya, in Rust.

This repository will also de-reference the virtual IP from IPVS connections to the real server's address.

Running the example, you get something like this

```
got = TcpSocketEvent { oldstate: Close, newstate: SynSent, sport: 0, dport: 33, dst: 1.2.3.4 }
[2024-09-22T17:26:35Z INFO  ipvs_tcpstate] cport 47758 vport 33 dport 22
[2024-09-22T17:26:35Z INFO  ipvs_tcpstate] daddr args 16951488
[2024-09-22T17:26:35Z INFO  ipvs_tcpstate] caddr param 2432870592
got = TcpSocketEvent { oldstate: SynSent, newstate: Established, sport: 47758, dport: 33, dst: 1.2.3.4 }

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
