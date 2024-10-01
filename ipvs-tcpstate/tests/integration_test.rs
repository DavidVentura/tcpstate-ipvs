use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use ipvs::{self, AddressFamily, Destination, Flags, ForwardTypeFull, Netmask};
use ipvs_tcpstate::ConnectionWatcher;
use ipvs_tcpstate_common::{Event, TcpState};
use tokio::net::{TcpListener, TcpSocket};
use tokio::spawn;

// requires
// Connection will be accepted
// sudo ipvsadm -A -t 127.0.0.1:33 -s rr
// sudo ipvsadm -a -t 127.0.0.1:33 -r 127.0.0.1:1234 --masquerading
// which redirects traffic from 127.0.0.1:33 to 127.0.0.1:1234
// Connection will be refused
// <don't start the server>
// Connection will be not acknowledged
// sudo ipvsadm -A -t 127.0.0.1:44 -s rr
// sudo ipvsadm -a -t 127.0.0.1:44 -r 203.0.113.2:1234 --masquerading
fn setup_ipvs() {
    let c = ipvs::IpvsClient::new().unwrap();
    let accepted = ipvs::Service {
        address: std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        netmask: Netmask::new(32, AddressFamily::IPv4),
        scheduler: ipvs::Scheduler::RoundRobin,
        flags: Flags(0),
        port: Some(33),
        fw_mark: None,
        persistence_timeout: None,
        family: AddressFamily::IPv4,
        protocol: ipvs::Protocol::TCP,
    };
    let refused = ipvs::Service {
        port: Some(44),
        ..accepted
    };
    let dropped = ipvs::Service {
        port: Some(55),
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
        port: 1234,
        family: AddressFamily::IPv4,
    };
    let refused_dest = ipvs::Destination {
        port: 2345,
        ..accept_dest
    };
    // unroutable address, TEST-NET-3
    let dropped_dest = ipvs::Destination {
        address: std::net::IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2)),
        ..accept_dest
    };

    let _ = c.delete_destination(&accepted, &accept_dest);
    let _ = c.delete_destination(&refused, &refused_dest);
    let _ = c.delete_destination(&dropped, &dropped_dest);

    // FIXME !!!
    let _ = c.create_destination(&accepted, &accept_dest); //.unwrap();
    let _ = c.create_destination(&refused, &refused_dest); //.unwrap();
    let _ = c.create_destination(&dropped, &dropped_dest); //.unwrap();
}

#[tokio::test]
#[ignore]
async fn trace_direct_connection() {
    setup_ipvs();
    let handle = spawn(async move {
        let mut watcher = ConnectionWatcher::new().unwrap();
        let mut rx = watcher.get_events().await.unwrap();
        let ev = rx.recv().await.unwrap();
        ev
    });

    let server = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Could not bind to localhost. is loopback interface up?");
    let server_addr = server.local_addr().unwrap();
    spawn(async move {
        spawn(async move {
            let client = TcpSocket::new_v4().unwrap();
            let _ = client.connect(server_addr).await.unwrap();
        });
        loop {
            let (_, _) = server.accept().await.unwrap();
        }
    });
    let event = handle.await.unwrap();
    assert_eq!(event.oldstate, TcpState::Close);
    assert_eq!(event.newstate, TcpState::SynSent);
    assert_eq!(event.dport, server_addr.port());
    // On TCP Open we don't know what service it will map to yet
    assert_eq!(event.svc, None);
    assert_eq!(event.interpret(), Some(Event::Open));
}

#[tokio::test]
#[ignore]
async fn trace_ipvs_connection_accepted() {
    setup_ipvs();
    let mut watcher = ConnectionWatcher::new().unwrap();
    let mut rx = watcher.get_events().await.unwrap();

    let server = TcpListener::bind("127.0.0.1:1234").await.unwrap();
    spawn(async move {
        spawn(async move {
            let client = TcpSocket::new_v4().unwrap();
            let _c = client
                .connect(std::net::SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::new(127, 0, 0, 1),
                    33,
                )))
                .await
                .unwrap();
        });
        loop {
            let (_, _) = server.accept().await.unwrap();
        }
    });
    let event = rx.recv().await.unwrap();
    assert_eq!(event.oldstate, TcpState::Close);
    assert_eq!(event.newstate, TcpState::SynSent);
    assert_eq!(event.dport, 33); // Destination port, as seen by the client, is 33

    // On TCP Open we don't know what service it will map to yet
    assert_eq!(event.svc, None);
    assert_eq!(event.interpret(), Some(Event::Open));

    let event = rx.recv().await.unwrap();
    assert_eq!(event.oldstate, TcpState::SynSent);
    assert_eq!(event.newstate, TcpState::Established);
    assert_eq!(event.dport, 33); // Destination port, as seen by the client, is 33

    // When the connection is Established, we know it maps to the actual destination port
    assert!(event.svc.is_some());
    let svc = event.svc.unwrap();
    assert_eq!(svc.dport, 1234);
    assert_eq!(svc.received_rst, false);
    assert_eq!(event.interpret(), None);
    // client closes connection
    let event = rx.recv().await.unwrap();
    assert_eq!(event.oldstate, TcpState::Established);
    assert_eq!(event.newstate, TcpState::CloseWait);
}

#[tokio::test]
#[ignore]
async fn trace_ipvs_connection_refused() {
    setup_ipvs();
    let mut watcher = ConnectionWatcher::new().unwrap();
    let mut rx = watcher.get_events().await.unwrap();

    // no server = refused
    spawn(async move {
        let client = TcpSocket::new_v4().unwrap();
        let _c = client
            .connect(std::net::SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(127, 0, 0, 1),
                33,
            )))
            .await
            .unwrap_err();
    });
    let event = rx.recv().await.unwrap();
    assert_eq!(event.oldstate, TcpState::Close);
    assert_eq!(event.newstate, TcpState::SynSent);
    assert_eq!(event.dport, 33); // Destination port, as seen by the client, is 33

    // On TCP Open we don't know what service it will map to yet
    assert_eq!(event.svc, None);
    assert_eq!(event.interpret(), Some(Event::Open));

    let event = rx.recv().await.unwrap();
    // refused
    assert_eq!(event.oldstate, TcpState::SynSent);
    assert_eq!(event.newstate, TcpState::Close);
    assert_eq!(event.dport, 33); // Destination port, as seen by the client, is 33

    // When the connection is Established, we know it maps to the actual destination port
    assert!(event.svc.is_some());
    let svc = event.svc.unwrap();
    assert_eq!(svc.dport, 1234);
    assert_eq!(svc.received_rst, true);
    assert_eq!(event.interpret(), Some(Event::ServerRefused));
}

#[tokio::test]
#[ignore]
async fn trace_ipvs_connection_not_responding() {
    setup_ipvs();
    let mut watcher = ConnectionWatcher::new().unwrap();
    let mut rx = watcher.get_events().await.unwrap();

    // no server = refused
    spawn(async move {
        let client = TcpSocket::new_v4().unwrap();
        let fut = client.connect(std::net::SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(127, 0, 0, 1),
            55,
        )));
        // expect to give up
        tokio::time::timeout(Duration::from_millis(1500), fut)
            .await
            .unwrap_err();
    });
    let event = rx.recv().await.unwrap();
    assert_eq!(event.oldstate, TcpState::Close);
    assert_eq!(event.newstate, TcpState::SynSent);
    assert_eq!(event.dport, 55); // Destination port, as seen by the client

    // On TCP Open we don't know what service it will map to yet
    assert_eq!(event.svc, None);
    assert_eq!(event.interpret(), Some(Event::Open));

    let event = rx.recv().await.unwrap();
    // slow
    assert_eq!(event.oldstate, TcpState::SynSent);
    assert_eq!(event.newstate, TcpState::SynSent);
    assert_eq!(event.dport, 55); // Destination port, as seen by the client

    // When the connection is Established, we know it maps to the actual destination port
    assert!(event.svc.is_some());
    let svc = event.svc.unwrap();
    assert_eq!(svc.dport, 1234);
    assert_eq!(svc.received_rst, false);
    assert_eq!(event.interpret(), Some(Event::SlowEstablishing));

    let event = rx.recv().await.unwrap();
    // client gave up
    assert!(event.svc.is_some());
    let svc = event.svc.unwrap();
    assert_eq!(svc.dport, 1234);
    assert_eq!(svc.received_rst, false);
    assert_eq!(
        event.interpret(),
        Some(Event::ClientClosedWithoutEstablishing)
    );
}
