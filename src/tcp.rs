use etherparse::{Ipv4HeaderSlice, TcpHeaderSlice};
use std::net::Ipv4Addr;

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct Tcp4Tuple {
    pub src: (Ipv4Addr, u16),
    pub dst: (Ipv4Addr, u16),
}

#[derive(Debug, Default)]
pub struct TcpState {}

impl TcpState {
    pub fn on_packet(&mut self, ip: Ipv4HeaderSlice, tcp: TcpHeaderSlice, data: &[u8]) {
        let tcp_len = tcp.slice().len();
        let data_len = data.len();
        println!(
            "TCP [{}:{}] {}:{} -> {}:{}",
            tcp_len,
            data_len,
            ip.source_addr(),
            tcp.source_port(),
            ip.destination_addr(),
            tcp.destination_port(),
        );
    }
}
