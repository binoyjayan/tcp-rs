use etherparse::{IpNumber, Ipv4Header, Ipv4HeaderSlice, TcpHeader, TcpHeaderSlice};
use std::io;
use std::net::Ipv4Addr;

use super::sequence::ReceiveSequenceSpace;
use super::sequence::SendSequenceSpace;
use super::state::State;

const TTL: u8 = 64;
const ISS: u32 = 0; // Needs to change
const WINDOW_SIZE: u16 = 10; // 4096;

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct Tcp4Tuple {
    pub src: (Ipv4Addr, u16),
    pub dst: (Ipv4Addr, u16),
}

#[derive(Debug)]
pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    receive: ReceiveSequenceSpace,
    tcp4tuple: Tcp4Tuple,
}

impl Connection {
    pub fn accept(
        nic: &tun_tap::Iface,
        ip: Ipv4HeaderSlice,
        tcp: TcpHeaderSlice,
        data: &[u8],
    ) -> io::Result<Self> {
        let tcp_len = tcp.slice().len();
        let data_len = data.len();
        let src = ip.source_addr();
        let dst = ip.destination_addr();
        let srcp = tcp.source_port();
        let dstp = tcp.destination_port();
        println!(
            "TCP [{}:{}] {}:{} -> {}:{}",
            tcp_len, data_len, src, srcp, dst, dstp,
        );

        if !tcp.syn() {
            // non-syn unexpected
            return Err(io::Error::new(io::ErrorKind::Other, "Unexpected SYN"));
        }
        // establish connection with the client we received SYN from

        // Initialize receive sequence space
        let receive = ReceiveSequenceSpace {
            irs: tcp.sequence_number(),
            nxt: tcp.sequence_number() + 1,
            wnd: tcp.window_size(),
            urgent: tcp.urgent_pointer(),
        };

        // Initialize send sequence space
        let iss = ISS;
        let send = SendSequenceSpace {
            iss,
            una: iss,
            nxt: iss + 1,
            wnd: WINDOW_SIZE,
            urgent: 0,
            wl1: tcp.sequence_number(),
            wl2: iss + WINDOW_SIZE as u32,
        };

        let tcp4tuple = Tcp4Tuple {
            src: (src, srcp),
            dst: (dst, dstp),
        };

        let mut resp_tcp = TcpHeader::new(dstp, srcp, send.iss, send.wnd);
        resp_tcp.syn = true;
        resp_tcp.ack = true;
        resp_tcp.acknowledgment_number = receive.nxt;

        let resp_ip = Ipv4Header::new(
            resp_tcp.header_len() as u16,
            TTL,
            IpNumber::TCP,
            dst.octets(),
            src.octets(),
        )
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;

        // Calculate checksum
        resp_tcp.checksum = resp_tcp
            .calc_checksum_ipv4(&resp_ip, &[])
            .expect("checksum failed");

        let mut buf = [0u8; 1504];
        let mut cursor = io::Cursor::new(&mut buf[..]);
        resp_ip.write(&mut cursor)?;
        resp_tcp.write(&mut cursor)?;
        let len = cursor.position() as usize;
        nic.send(&buf[0..len])?;

        Ok(Connection {
            state: State::SynReceived,
            send,
            receive,
            tcp4tuple,
        })
    }

    pub fn on_packet(
        &self,
        _nic: &tun_tap::Iface,
        _ip: Ipv4HeaderSlice,
        tcp: TcpHeaderSlice,
        _data: &[u8],
    ) -> io::Result<()> {
        // Acceptable ACK check: SDN < SEG.ACK =< SND.NXT
        if !(self.send.una < tcp.acknowledgment_number()
            && tcp.acknowledgment_number() <= self.send.nxt)
        {
            return Ok(());
        }
        match self.state {
            State::SynReceived => {}
            State::Established => {}
        }
        Ok(())
    }
}
