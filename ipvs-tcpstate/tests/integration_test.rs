use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use ipvs::{self, AddressFamily, Destination, Flags, ForwardTypeFull, Netmask};
use ipvs_tcpstate::ConnectionWatcher;
use ipvs_tcpstate_common::{Event, TcpSocketEvent, TcpState};
use tokio::net::{TcpListener, TcpSocket};
use tokio::spawn;
use tokio::time::timeout;

struct IpvsConfig {
    accept_port: u16,
    refuse_port: u16,
    drop_port: u16,

    /// forward to
    accept_port_dest: u16,
    /// forward to
    refuse_port_dest: u16,
    /// forward to
    drop_port_dest: u16,
}

/// Sets up IPVS services which forward data
/// accept_port -> accept_port_dest
/// refuse_port -> refuse_port_dest
/// drop_port -> drop_port_dest
fn setup_ipvs() -> IpvsConfig {
    let conf = IpvsConfig {
        accept_port: 33,
        refuse_port: 44,
        drop_port: 55,

        accept_port_dest: 1234,
        refuse_port_dest: 2345,
        drop_port_dest: 3456,
    };
    let c = ipvs::IpvsClient::new().unwrap();
    let accepted = ipvs::Service {
        address: std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        netmask: Netmask::new(32, AddressFamily::IPv4),
        scheduler: ipvs::Scheduler::RoundRobin,
        flags: Flags(0),
        port: Some(conf.accept_port),
        fw_mark: None,
        persistence_timeout: None,
        family: AddressFamily::IPv4,
        protocol: ipvs::Protocol::TCP,
    };
    let refused = ipvs::Service {
        port: Some(conf.refuse_port),
        ..accepted
    };
    let dropped = ipvs::Service {
        port: Some(conf.drop_port),
        ..accepted
    };

    let _ = c.delete_service(&accepted);
    let _ = c.delete_service(&refused);
    let _ = c.delete_service(&dropped);

    c.create_service(&accepted).unwrap();
    c.create_service(&refused).unwrap();
    c.create_service(&dropped).unwrap();

    let accept_dest = Destination {
        address: std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        fwd_method: ForwardTypeFull::Masquerade,
        weight: 1,
        upper_threshold: None,
        lower_threshold: None,
        port: conf.accept_port_dest,
        family: AddressFamily::IPv4,
    };
    let refused_dest = ipvs::Destination {
        port: conf.refuse_port_dest,
        ..accept_dest
    };
    // unroutable address, TEST-NET-3
    let dropped_dest = ipvs::Destination {
        address: std::net::IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2)),
        port: conf.drop_port_dest,
        ..accept_dest
    };

    let _ = c.delete_destination(&accepted, &accept_dest);
    let _ = c.delete_destination(&refused, &refused_dest);
    let _ = c.delete_destination(&dropped, &dropped_dest);

    let _ = c.create_destination(&accepted, &accept_dest).unwrap();
    let _ = c.create_destination(&refused, &refused_dest).unwrap();
    let _ = c.create_destination(&dropped, &dropped_dest).unwrap();

    conf
}

/// Sets up a TCP connection with optional port rewrites for IPVS testing
async fn setup_tcp_test<F, Fut>(
    listen_port: Option<u16>,  // Port server listens on
    connect_port: Option<u16>, // Optional different port to connect to (for IPVS tests)
    callback: F,               // Callback that receives the events receiver
) -> std::io::Result<()>
where
    F: FnOnce(tokio::sync::mpsc::Receiver<TcpSocketEvent>, SocketAddr) -> Fut,
    Fut: Future<Output = ()>,
{
    // Setup connection watcher
    let mut watcher = ConnectionWatcher::new().unwrap();
    let rx = watcher.get_events().await.unwrap();

    // If no port is passed, listen on a random port, which we won't use
    let server = TcpListener::bind(format!("127.0.0.1:{}", listen_port.unwrap_or(0)))
        .await
        .expect("Could not bind to localhost. is loopback interface up?");
    let server_addr = server.local_addr().unwrap();
    // println!("Listening on {server_addr:?}");

    tokio::time::sleep(Duration::from_millis(1)).await;
    spawn(async move {
        spawn(async move {
            let client = TcpSocket::new_v4().unwrap();
            let connect_addr = SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(127, 0, 0, 1),
                connect_port.unwrap_or(server_addr.port()),
            ));
            println!("Connecting to {connect_addr:?}");

            let fut = client.connect(connect_addr);
            // Linux sends a retransmission on the first 1s interval
            let wrapped = tokio::time::timeout(Duration::from_millis(1500), fut);
            let _c = match wrapped.await {
                Ok(r) => match r {
                    Ok(_) => println!("client connected"),
                    Err(e) => println!("client failed to connect {e:?}"),
                },
                Err(_) => println!("client timed out"),
            };
        });

        loop {
            let (_, _) = server.accept().await.unwrap();
        }
    });

    // Run the callback with the events receiver
    callback(rx, server_addr).await;

    Ok(())
}
#[tokio::test]
#[ignore]
async fn trace_direct_connection() {
    let _conf = setup_ipvs();
    setup_tcp_test(None, None, |mut rx, server_addr| async move {
        let event = rx.recv().await.unwrap();
        assert_eq!(event.oldstate, TcpState::Close);
        assert_eq!(event.newstate, TcpState::SynSent);
        assert_eq!(event.dport, server_addr.port());
        // On TCP Open we don't know what service it will map to yet
        assert_eq!(event.svc, None);
        assert_eq!(event.interpret(), Some(Event::Open));
    })
    .await
    .unwrap();
}

#[tokio::test]
#[ignore]
async fn trace_ipvs_connection_accepted() {
    let conf = setup_ipvs();
    setup_tcp_test(
        Some(conf.accept_port_dest),
        Some(conf.accept_port),
        |mut rx, server_addr| async move {
            let event = rx.recv().await.unwrap();
            assert_eq!(event.oldstate, TcpState::Close);
            assert_eq!(event.newstate, TcpState::SynSent);
            assert_eq!(event.dport, conf.accept_port); // Destination port, as seen by the client

            // On TCP Open we don't know what service it will map to yet
            assert_eq!(event.svc, None);
            assert_eq!(event.interpret(), Some(Event::Open));

            let event = rx.recv().await.unwrap();
            assert_eq!(event.oldstate, TcpState::SynSent);
            assert_eq!(event.newstate, TcpState::Established);
            assert_eq!(event.dport, conf.accept_port); // Destination port, as seen by the client

            // When the connection is Established, we know it maps to the actual destination port
            assert!(event.svc.is_some());
            let svc = event.svc.unwrap();
            assert_eq!(svc.dport, conf.accept_port_dest);
            assert_eq!(svc.dport, server_addr.port());
            assert_eq!(svc.received_rst, false);
            assert_eq!(event.interpret(), None);
            // client closes connection
            let event = rx.recv().await.unwrap();
            assert_eq!(event.oldstate, TcpState::Established);
            assert_eq!(event.newstate, TcpState::CloseWait);
        },
    )
    .await
    .unwrap();
}

#[tokio::test]
#[ignore]
async fn trace_ipvs_connection_refused() {
    let conf = setup_ipvs();
    // Nothing listens on the port, should get refused
    setup_tcp_test(
        None,
        Some(conf.accept_port),
        |mut rx, _server_addr| async move {
            let event = rx.recv().await.unwrap();
            assert_eq!(event.oldstate, TcpState::Close);
            assert_eq!(event.newstate, TcpState::SynSent);
            assert_eq!(event.dport, conf.accept_port); // Destination port, as seen by the client

            // On TCP Open we don't know what service it will map to yet
            assert_eq!(event.svc, None);
            assert_eq!(event.interpret(), Some(Event::Open));

            let event = match timeout(Duration::from_millis(100), rx.recv()).await {
                Ok(ev) => ev.unwrap(),
                Err(_) => panic!("Timed out waiting"),
            };
            // refused vvv the important part of the test
            assert_eq!(event.oldstate, TcpState::SynSent);
            assert_eq!(event.newstate, TcpState::Close);
            // ^^ the important part of the test
            assert_eq!(event.dport, conf.accept_port); // Destination port, as seen by the client

            assert!(event.svc.is_some());
            let svc = event.svc.unwrap();
            assert_eq!(svc.dport, conf.accept_port_dest);
            assert_eq!(svc.received_rst, true);
            assert_eq!(event.interpret(), Some(Event::ServerRefused));
        },
    )
    .await
    .unwrap();
}

#[tokio::test]
#[ignore]
async fn trace_ipvs_connection_not_responding() {
    let conf = setup_ipvs();
    setup_tcp_test(
        None,
        Some(conf.drop_port),
        |mut rx, _server_addr| async move {
            let event = rx.recv().await.unwrap();
            assert_eq!(event.oldstate, TcpState::Close);
            assert_eq!(event.newstate, TcpState::SynSent);
            assert_eq!(event.dport, conf.drop_port); // Destination port, as seen by the client

            // On TCP Open we don't know what service it will map to yet
            assert_eq!(event.svc, None);
            assert_eq!(event.interpret(), Some(Event::Open));

            let event = rx.recv().await.unwrap();
            // slow
            assert_eq!(event.oldstate, TcpState::SynSent);
            assert_eq!(event.newstate, TcpState::SynSent);
            assert_eq!(event.dport, conf.drop_port); // Destination port, as seen by the client

            // When the connection is Established, we know it maps to the actual destination port
            assert!(event.svc.is_some());
            let svc = event.svc.unwrap();
            assert_eq!(svc.dport, conf.drop_port_dest);
            assert_eq!(svc.received_rst, false);
            assert_eq!(event.interpret(), Some(Event::SlowEstablishing));

            let event = rx.recv().await.unwrap();
            // client gave up
            assert!(event.svc.is_some());
            let svc = event.svc.unwrap();
            assert_eq!(svc.dport, conf.drop_port_dest);
            assert_eq!(svc.received_rst, false);
            assert_eq!(
                event.interpret(),
                Some(Event::ClientClosedWithoutEstablishing)
            );
        },
    )
    .await
    .unwrap();
}
