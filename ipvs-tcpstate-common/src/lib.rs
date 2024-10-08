#![no_std]
use core::net::IpAddr;

#[derive(Debug, PartialEq)]
pub struct TcpSocketEvent {
    pub oldstate: TcpState,
    pub newstate: TcpState,
    pub sport: u16,
    pub dport: u16,
    pub dst: IpAddr,
    pub svc: Option<IpvsDest>,
    // would it be useful to have comm (16 chars of task name) here?
}

#[derive(Debug, PartialEq)]
pub enum Event {
    Open,
    ClientClosed,
    ClientClosedWithoutEstablishing,
    ServerClosed,
    ServerRefused,
    SlowEstablishing,
}

impl TcpSocketEvent {
    pub fn interpret(&self) -> Option<Event> {
        match (self.oldstate, self.newstate) {
            (TcpState::Close, TcpState::SynSent) => Some(Event::Open),
            (TcpState::SynSent, TcpState::SynSent) => Some(Event::SlowEstablishing),
            (TcpState::Established, TcpState::CloseWait) => Some(Event::ServerClosed),
            // maybe finwait1/finwait2 as well? if we miss this event somehow
            (TcpState::Established, TcpState::FinWait1) => Some(Event::ClientClosed),
            // svc is only None on Close -> SynSent
            (TcpState::SynSent, TcpState::Close) => match self.svc.unwrap().received_rst {
                true => Some(Event::ServerRefused),
                false => Some(Event::ClientClosedWithoutEstablishing),
            },
            (_, _) => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct IpvsDest {
    pub daddr: IpAddr,
    pub dport: u16,
    pub received_rst: bool,
}

#[derive(Debug)]
pub enum Family {
    IPv4,
    // Not supporting IPv6 for now
}

pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;

#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum TcpState {
    Established = 1,
    SynSent = 2,
    SynRecv = 3,
    FinWait1 = 4,
    FinWait2 = 5,
    TimeWait = 6,
    Close = 7,
    CloseWait = 8,
    LastAck = 9,
    Listen = 10,
    Closing = 11,
    NewSynRecv = 12,
    Unknown,
}

impl From<i32> for TcpState {
    fn from(value: i32) -> Self {
        match value {
            1 => TcpState::Established,
            2 => TcpState::SynSent,
            3 => TcpState::SynRecv,
            4 => TcpState::FinWait1,
            5 => TcpState::FinWait2,
            6 => TcpState::TimeWait,
            7 => TcpState::Close,
            8 => TcpState::CloseWait,
            9 => TcpState::LastAck,
            10 => TcpState::Listen,
            11 => TcpState::Closing,
            12 => TcpState::NewSynRecv,
            _ => TcpState::Unknown,
        }
    }
}
