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
mod tracepoint;

use crate::tracepoint::trace_event_raw_inet_sock_set_state;
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
    let ev = make_ev(&ctx, evt)?;
    unsafe {
        #[allow(static_mut_refs)]
        TCP_EVENTS.output(&ctx, &ev, 0);
    }

    Ok(0)
}
fn make_ev(
    ctx: &TracePointContext,
    evt: &trace_event_raw_inet_sock_set_state,
) -> Result<TcpSocketEvent, i32> {
    //let pid = helpers::bpf_get_current_pid_tgid() >> 32;
    //let comm = helpers::bpf_get_current_comm();
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

    let key = &TcpKey {
        sport: evt.sport,
        vport: evt.dport,
        saddr: u32::from_be_bytes(evt.saddr),
        vaddr: u32::from_be_bytes(evt.daddr),
    };

    info!(
        ctx,
        "getting sp {} vp {} sa {} va {}", key.sport, key.vport, key.saddr, key.vaddr
    );

    let newstate: TcpState = evt.newstate.into();
    let v = unsafe { IPVS_TCP_MAP.get(key) }.copied();

    if let TcpState::Close = newstate {
        IPVS_TCP_MAP.remove(key).unwrap();
    }

    let ev = TcpSocketEvent {
        oldstate: evt.oldstate.into(),
        newstate,
        sport: evt.sport,
        dport: evt.dport,
        dst: ip,
        svc: v, //None, // unsafe { IPVS_TCP_MAP.get(key) }
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
    info!(
        ctx,
        "cport {} vport {} dport {}",
        u16::from_be(conn.cport),
        u16::from_be(conn.vport),
        u16::from_be(dport)
    );

    let daddr_ptr: *const nf_inet_addr = ctx.arg(2).ok_or(0u32)?;
    /*
    let daddr: *const nf_inet_addr = ctx.arg(2).ok_or(0u32)?;
    info!(ctx, "daddr ipv4 {}", unsafe { (*daddr).ip });
    */
    let daddr = unsafe {
        helpers::bpf_probe_read_kernel(&(*daddr_ptr)).map_err(|x| {
            info!(ctx, "got err {}", x);
            1u32
        })?
    };

    info!(ctx, "daddr args {}", unsafe { daddr.ip });

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
    };
    IPVS_TCP_MAP.insert(key, value, 0).unwrap();

    info!(ctx, "caddr param {}", unsafe { (caddr).ip });
    info!(
        ctx,
        "inserting sp {} vp {} sa {} va {}", key.sport, key.vport, key.saddr, key.vaddr
    );

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
