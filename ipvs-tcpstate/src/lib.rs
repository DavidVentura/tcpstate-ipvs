use aya::maps::{AsyncPerfEventArray, MapData};
use aya::programs::{KProbe, TracePoint};
use aya::{include_bytes_aligned, util::online_cpus, Bpf};
use aya_log::BpfLogger;
use bytes::BytesMut;
use ipvs_tcpstate_common::TcpSocketEvent;
use log::{debug, warn};
use tokio::spawn;
use tokio::sync::mpsc;

pub struct ConnectionWatcher {
    bpf: Bpf,
}

impl ConnectionWatcher {
    pub fn new() -> Result<ConnectionWatcher, anyhow::Error> {
        Ok(ConnectionWatcher {
            bpf: get_program()?,
        })
    }
    pub async fn get_events(&mut self) -> Result<mpsc::Receiver<TcpSocketEvent>, anyhow::Error> {
        let program: &mut TracePoint = self.bpf.program_mut("tcp_set_state").unwrap().try_into()?;
        program.load()?;
        program.attach("sock", "inet_sock_set_state")?;
        let events: AsyncPerfEventArray<_> = self.bpf.take_map("TCP_EVENTS").unwrap().try_into()?;

        let ipvs_conn: &mut KProbe = self.bpf.program_mut("ip_vs_conn_new").unwrap().try_into()?;
        ipvs_conn.load()?;
        ipvs_conn.attach("ip_vs_conn_new", 0)?;

        let tcp_retrans: &mut TracePoint = self
            .bpf
            .program_mut("tcp_retransmit_skb")
            .unwrap()
            .try_into()?;
        tcp_retrans.load()?;
        tcp_retrans.attach("tcp", "tcp_retransmit_skb")?;

        let tcp_rcv_reset: &mut TracePoint = self
            .bpf
            .program_mut("tcp_receive_reset")
            .unwrap()
            .try_into()?;
        tcp_rcv_reset.load()?;
        tcp_rcv_reset.attach("tcp", "tcp_receive_reset")?;

        watch_tcp_events(events).await
    }
}
/// Will spawn `online_cpus()` coroutines to watch for TCP events
/// on their respective cores.
/// If you close the returned Receiver, then they will all stop.
async fn watch_tcp_events(
    mut events: AsyncPerfEventArray<MapData>,
) -> Result<mpsc::Receiver<TcpSocketEvent>, anyhow::Error> {
    let (tx, rx) = mpsc::channel::<TcpSocketEvent>(32);
    for cpu_id in online_cpus()? {
        let mut cpu_buf = events.open(cpu_id, None)?;
        let tx = tx.clone();
        spawn(async move {
            loop {
                let mut bufs = (0..10)
                    // unsure what these buffers and their size do
                    // shouldn't they be sizeof(TcpSocketEvent) ?
                    .map(|_| BytesMut::with_capacity(1024))
                    .collect::<Vec<_>>();
                let events = cpu_buf.read_events(&mut bufs).await.unwrap();
                for i in 0..events.read {
                    let buf = &mut bufs[i];
                    let ptr = buf.as_ptr() as *const TcpSocketEvent;
                    let event = unsafe { ptr.read_unaligned() };
                    // if channel is closed, stop listening for events
                    if let Err(_) = tx.send(event).await {
                        return;
                    }
                }
            }
        });
    }
    Ok(rx)
}

fn get_program() -> Result<Bpf, anyhow::Error> {
    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    // This got merged in ~2020
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/ipvs-tcpstate"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/ipvs-tcpstate"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    Ok(bpf)
}
