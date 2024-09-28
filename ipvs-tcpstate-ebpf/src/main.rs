#![no_std]
#![no_main]
// asd
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
include!(concat!(env!("OUT_DIR"), "/ipvs_bindings.rs"));

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod tracepoint_gen;

use crate::tracepoint_gen::{
    trace_event_raw_inet_sock_set_state, trace_event_raw_tcp_event_sk,
    trace_event_raw_tcp_event_sk_skb,
};
use aya_ebpf::maps::PerfEventArray;
use aya_ebpf::EbpfContext;
use aya_ebpf::{
    helpers, macros::kprobe, macros::map, macros::tracepoint, maps::HashMap,
    programs::ProbeContext, programs::TracePointContext,
};
use aya_log_ebpf::info;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use ipvs_tcpstate_common::{Family, IpvsDest, TcpSocketEvent, TcpState, AF_INET, AF_INET6};

#[map]
static IPVS_TCP_MAP: HashMap<TcpKey, IpvsDest> = HashMap::with_max_entries(1024, 0);

const IPPROTO_TCP: u16 = 6;

// rustc marks these as deadcode but they are definitely
// used for keying the hashmap
#[allow(dead_code)]
struct TcpKey {
    // TCP source port
    sport: u16,
    // TCP dest port  (virtual)
    vport: u16,
    // TCP source address
    saddr: u32,
    // TCP dest address (virtual)
    vaddr: u32,
}

#[map]
pub static mut TCP_EVENTS: PerfEventArray<TcpSocketEvent> =
    PerfEventArray::with_max_entries(1024, 0);

#[tracepoint]
pub fn tcp_retransmit_skb(ctx: TracePointContext) -> i64 {
    match try_tcp_retransmit_skb(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}
fn try_tcp_retransmit_skb(ctx: &TracePointContext) -> Result<i64, i64> {
    let evt_ptr = ctx.as_ptr() as *const trace_event_raw_tcp_event_sk_skb;
    let evt = unsafe { evt_ptr.as_ref().ok_or(1i64)? };
    let state: TcpState = evt.state.into();
    // We only care about connection opening, to detect timeouts
    if let TcpState::SynSent = state {
        let key = TcpKey {
            sport: evt.sport,
            vport: evt.dport,
            saddr: u32::from_be_bytes(evt.saddr),
            vaddr: u32::from_be_bytes(evt.daddr),
        };
        if let Ok(Some(evt)) = make_retrans_ev(evt, &key) {
            unsafe {
                #[allow(static_mut_refs)]
                TCP_EVENTS.output(ctx, &evt, 0);
            }
        }
    }
    Ok(0)
}

fn make_retrans_ev(
    evt: &trace_event_raw_tcp_event_sk_skb,
    key: &TcpKey,
) -> Result<Option<TcpSocketEvent>, i64> {
    let v = unsafe { IPVS_TCP_MAP.get(&key) }.copied();
    if v.is_none() {
        // This is a null-pointer check - the verifier does not
        // approve this program without it, even though
        // it should be fine to return svc: None
        return Ok(None);
    }

    let ip = Ipv4Addr::from(u32::from_be_bytes(evt.daddr));
    // This is always SynSent
    let state: TcpState = TcpState::SynSent;
    let ev = TcpSocketEvent {
        oldstate: state,
        newstate: state,
        sport: evt.sport,
        dport: evt.dport,
        dst: IpAddr::V4(ip),
        svc: Some(v.unwrap()),
    };
    Ok(Some(ev))
}
#[tracepoint]
pub fn tcp_receive_reset(ctx: TracePointContext) -> i64 {
    match try_tcp_receive_reset(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

// Update the entry in IPVS_TCP_MAP to set `received_rst` flag
// This event executes before `tcp_set_state`
fn try_tcp_receive_reset(ctx: &TracePointContext) -> Result<i64, i64> {
    let evt_ptr = ctx.as_ptr() as *const trace_event_raw_tcp_event_sk;
    let evt = unsafe { evt_ptr.as_ref().ok_or(1i64)? };
    let key = &TcpKey {
        sport: evt.sport,
        vport: evt.dport,
        saddr: u32::from_be_bytes(evt.saddr),
        vaddr: u32::from_be_bytes(evt.daddr),
    };
    let v = unsafe { IPVS_TCP_MAP.get(key) }.copied();
    if v.is_none() {
        return Ok(0);
    }
    let mut v = v.unwrap();
    v.received_rst = true;
    IPVS_TCP_MAP.insert(key, &v, 0).unwrap();
    Ok(0)
}

#[tracepoint]
pub fn tcp_set_state(ctx: TracePointContext) -> i64 {
    match try_tcp_set_state(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_tcp_set_state(ctx: TracePointContext) -> Result<i64, i64> {
    let evt_ptr = ctx.as_ptr() as *const trace_event_raw_inet_sock_set_state;
    let evt = unsafe { evt_ptr.as_ref().ok_or(1i64)? };
    if evt.protocol != IPPROTO_TCP {
        return Ok(0);
    }
    if let Some(ev) = make_ev(&ctx, evt)? {
        unsafe {
            #[allow(static_mut_refs)]
            TCP_EVENTS.output(&ctx, &ev, 0);
        }
    }

    Ok(0)
}
fn make_ev(
    ctx: &TracePointContext,
    evt: &trace_event_raw_inet_sock_set_state,
) -> Result<Option<TcpSocketEvent>, i32> {
    let key = &TcpKey {
        sport: evt.sport,
        vport: evt.dport,
        saddr: u32::from_be_bytes(evt.saddr),
        vaddr: u32::from_be_bytes(evt.daddr),
    };
    // Only push out events if we know about the connection
    // from an IPVS perspective
    let v = unsafe { IPVS_TCP_MAP.get(key) }.copied();
    if v.is_none() {
        return Ok(None);
    }
    let v = v.unwrap();

    let family = match evt.family {
        AF_INET => Family::IPv4,
        AF_INET6 => Family::IPv6,
        other => {
            info!(ctx, "unknown family {}", other);
            return Err(-999);
        }
    };
    let mut ip_bytes: [u8; 16] = [0; 16];

    if let Family::IPv6 = family {
        ip_bytes[..16].copy_from_slice(&evt.daddr_v6);
    }

    // The verifier can't verify this if i put it inside a `match` :'(
    // if family != Ipv6, `ip6` contains garbage, but is not returned
    let ip6 = IpAddr::V6(Ipv6Addr::from_bits(
        (ip_bytes[0] as u128) << 120
            | (ip_bytes[1] as u128) << 112
            | (ip_bytes[2] as u128) << 104
            | (ip_bytes[3] as u128) << 96
            | (ip_bytes[4] as u128) << 88
            | (ip_bytes[5] as u128) << 80
            | (ip_bytes[6] as u128) << 72
            | (ip_bytes[7] as u128) << 64
            | (ip_bytes[8] as u128) << 56
            | (ip_bytes[9] as u128) << 48
            | (ip_bytes[10] as u128) << 40
            | (ip_bytes[11] as u128) << 32
            | (ip_bytes[12] as u128) << 24
            | (ip_bytes[13] as u128) << 16
            | (ip_bytes[14] as u128) << 8
            | (ip_bytes[15] as u128) << 0,
    ));
    let ip = match family {
        Family::IPv4 => {
            ip_bytes[..4].copy_from_slice(&evt.daddr);
            let ip4 = IpAddr::V4(Ipv4Addr::new(
                ip_bytes[0],
                ip_bytes[1],
                ip_bytes[2],
                ip_bytes[3],
            ));
            ip4
        }
        Family::IPv6 => ip6,
    };

    let newstate: TcpState = evt.newstate.into();

    if let TcpState::Close = newstate {
        IPVS_TCP_MAP.remove(key).unwrap();
    }

    let ev = TcpSocketEvent {
        oldstate: evt.oldstate.into(),
        newstate,
        sport: evt.sport,
        dport: evt.dport,
        dst: ip,
        svc: Some(v),
    };
    Ok(Some(ev))
}
#[kprobe]
pub fn tcp_connect(ctx: ProbeContext) -> u32 {
    match try_tcp_connect(&ctx) {
        Ok(ev) => {
            unsafe {
                #[allow(static_mut_refs)]
                TCP_EVENTS.output(&ctx, &ev, 0);
            }
            0
        }
        Err(ret) => {
            info!(&ctx, "tcp_conn err code {}", ret);
            ret
        }
    }
}

// This function is only useful to trace the precise moment on which a connection
// _attempts_ establishment.
// This is because `tcp_set_state` with newstate=SynSent is called _before_
// establishing the identity of the connection (ie: assigning a source port)
// See:
// https://github.com/torvalds/linux/blob/v6.11/net/ipv4/tcp_ipv4.c#L294
// tcp_connect is called here:
// https://github.com/torvalds/linux/blob/v6.11/net/ipv4/tcp_ipv4.c#L337
// critically, after `inet_hash_connect`, which assigns the source port.
fn try_tcp_connect(ctx: &ProbeContext) -> Result<TcpSocketEvent, u32> {
    let conn_ptr: *const sock = ctx.arg(0).ok_or(0u32)?;

    let sk_comm = unsafe {
        helpers::bpf_probe_read_kernel(&((*conn_ptr).__sk_common)).map_err(|x| {
            info!(ctx, "got err {}", x);
            1u32
        })?
    };
    // By definition, `tcp_connect` is called with SynSent state
    // This `if` will never trigger -- it is here only to make the
    // expected precondition explicit
    if sk_comm.skc_state != TcpState::SynSent as u8 {
        return Err(1);
    }

    let sport = unsafe { sk_comm.__bindgen_anon_3.__bindgen_anon_1.skc_num };
    let dport = unsafe { sk_comm.__bindgen_anon_3.__bindgen_anon_1.skc_dport };

    let ip4daddr = unsafe { sk_comm.__bindgen_anon_1.__bindgen_anon_1.skc_daddr };

    let ip = IpAddr::V4(Ipv4Addr::from_bits(u32::from_be(ip4daddr)));
    let ev = TcpSocketEvent {
        oldstate: TcpState::Close,
        newstate: TcpState::SynSent,
        sport,
        dport: u16::from_be(dport),
        dst: ip,
        svc: None,
    };
    Ok(ev)
}

#[kprobe]
pub fn ip_vs_conn_new(ctx: ProbeContext) -> u32 {
    match try_ip_vs_conn_new(&ctx) {
        Ok(ret) => ret,
        Err(ret) => {
            info!(&ctx, "err code {}", ret);
            ret
        }
    }
}

fn try_ip_vs_conn_new(ctx: &ProbeContext) -> Result<u32, u32> {
    let conn_ptr: *const ip_vs_conn_param = ctx.arg(0).ok_or(0u32)?;

    let conn = unsafe {
        helpers::bpf_probe_read_kernel(&(*conn_ptr)).map_err(|x| {
            info!(ctx, "got err {}", x);
            1u32
        })?
    };
    if conn.protocol != IPPROTO_TCP {
        return Ok(0);
    }
    let dport: u16 = ctx.arg(3).ok_or(0u32)?;

    let daddr_ptr: *const nf_inet_addr = ctx.arg(2).ok_or(0u32)?;
    let daddr = unsafe {
        helpers::bpf_probe_read_kernel(&(*daddr_ptr)).map_err(|x| {
            info!(ctx, "got err {}", x);
            1u32
        })?
    };

    let caddr = unsafe {
        helpers::bpf_probe_read_kernel(&(*conn.caddr)).map_err(|x| {
            info!(ctx, "got err {}", x);
            1u32
        })?
    };
    let vaddr = unsafe {
        helpers::bpf_probe_read_kernel(&(*conn.vaddr)).map_err(|x| {
            info!(ctx, "got err {}", x);
            1u32
        })?
    };
    let key = &TcpKey {
        sport: u16::from_be(conn.cport),
        vport: u16::from_be(conn.vport),
        saddr: u32::from_be(unsafe { caddr.ip }),
        vaddr: u32::from_be(unsafe { vaddr.ip }),
    };
    let value = &IpvsDest {
        daddr: IpAddr::V4(Ipv4Addr::from_bits(u32::from_be(unsafe { daddr.ip }))),
        dport: u16::from_be(dport),
        received_rst: false,
    };
    IPVS_TCP_MAP.insert(key, value, 0).unwrap();

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
