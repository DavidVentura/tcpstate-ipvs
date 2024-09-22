#![no_std]
use core::net::IpAddr;
#[derive(Debug)]
pub struct TcpSocketEvent {
    pub oldstate: TcpState,
    pub newstate: TcpState,
    pub sport: u16,
    pub dport: u16,
    pub dst: IpAddr,
    // would it be useful to have comm (16 chars of task name) here?
}

#[repr(u8)]
#[derive(Debug)]
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

#[derive(Debug)]
pub enum Family {
    IPv4,
    IPv6,
}

pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;

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
