use etherparse::{IpNumber, Ipv4Header, Ipv4HeaderSlice, TcpHeader, TcpHeaderSlice};
use std::io;
use std::io::Write;
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
    ip: Ipv4Header,
    tcp: TcpHeader,
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
            nxt: iss,
            wnd: WINDOW_SIZE,
            urgent: 0,
            wl1: tcp.sequence_number(),
            wl2: iss + WINDOW_SIZE as u32,
        };

        // Flip source and destination in the response
        let mut resp_tcp = TcpHeader::new(dstp, srcp, send.iss, send.wnd);
        resp_tcp.syn = true;
        resp_tcp.ack = true;

        let resp_ip = Ipv4Header::new(
            resp_tcp.header_len() as u16,
            TTL,
            IpNumber::TCP,
            dst.octets(),
            src.octets(),
        )
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;

        let mut conn = Connection {
            state: State::SynReceived,
            send,
            receive,
            ip: resp_ip,
            tcp: resp_tcp,
        };
        conn.write(nic, &[])?;
        Ok(conn)
    }

    pub fn write(&mut self, nic: &tun_tap::Iface, payload: &[u8]) -> io::Result<usize> {
        let mut buf = [0u8; 1500];
        self.tcp.sequence_number = self.send.nxt;
        self.tcp.acknowledgment_number = self.receive.nxt;

        let size = std::cmp::min(buf.len(), self.tcp.header_len() + payload.len());
        let _ = self.ip.set_payload_len(size);

        // Calculate checksum
        self.tcp.checksum = self
            .tcp
            .calc_checksum_ipv4(&self.ip, payload)
            .expect("checksum failed");
        let mut cursor = io::Cursor::new(&mut buf[..]);
        self.ip.write(&mut cursor)?;
        self.tcp.write(&mut cursor)?;
        let payload_bytes = cursor.write(payload)?;
        let len = cursor.position() as usize;

        // Adjust send sequence space
        self.send.nxt = self.send.nxt.wrapping_add(payload_bytes as u32);
        if self.tcp.syn {
            self.send.nxt = self.send.nxt.wrapping_add(1);
            self.tcp.syn = false;
        }
        if self.tcp.fin {
            self.send.nxt = self.send.nxt.wrapping_add(1);
            self.tcp.fin = false;
        }
        nic.send(&buf[0..len])?;
        Ok(payload_bytes)
    }

    pub fn on_packet(
        &mut self,
        nic: &tun_tap::Iface,
        _ip: Ipv4HeaderSlice,
        tcp: TcpHeaderSlice,
        data: &[u8],
    ) -> io::Result<()> {
        // First check if sequence numbers are valid
        let seq = tcp.sequence_number();
        let mut slen = data.len() as u32;
        if tcp.syn() {
            slen += 1;
        }
        if tcp.fin() {
            slen += 1;
        }

        // Segment check:
        // RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
        // or
        // RCV.NXT =< SEG.SEQ + SEG.LEN-1 < RCV.NXT+RCV.WND
        let wend = self.receive.nxt.wrapping_add(self.receive.wnd as u32);
        if slen == 0 {
            // zero length segment
            if self.receive.wnd == 0 {
                if seq != self.receive.nxt {
                    // Not acceptable
                    return Ok(());
                }
            } else if !Self::is_between_wrapped(self.receive.nxt.wrapping_sub(1), seq, wend) {
                return Ok(());
            }
        } else {
            if self.receive.wnd == 0 {
                // Not Acceptable
                return Ok(());
            } else if !Self::is_between_wrapped(
                self.receive.nxt.wrapping_sub(1),
                seq.wrapping_add(slen - 1),
                wend,
            ) {
                return Ok(());
            }
        }
        // Adjust receive sequence space: we have accepted the segment
        self.receive.nxt = seq.wrapping_add(slen);

        // TODO: If not acceptable, send ACK, drop segment and return
        // <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>

        if !tcp.ack() {
            eprintln!("NOT ACK");
            return Ok(());
        }
        let ack = tcp.acknowledgment_number();
        // Acceptable ACK check: SND.UNA < SEG.ACK =< SND.NXT
        if !Self::is_between_wrapped(self.send.una, ack, self.send.nxt.wrapping_add(1)) {
            if !self.state.is_sync() {
                // Reset Generation: Send RST
                self.send_rst(&nic)?;
            }
            return Ok(());
        }
        // First un-ACKed byte - same as the next byte the receiver expects
        self.send.una = ack;

        if let State::SynReceived = self.state {
            if !Self::is_between_wrapped(
                self.send.una.wrapping_sub(1),
                ack,
                self.send.nxt.wrapping_add(1),
            ) {
                self.state = State::Established;
            } else {
                //TODO: Form a RST segment: SEQ=SEG.ACK><CTL=RST>
            }
        }

        if let State::Established = self.state {
            if !Self::is_between_wrapped(self.send.una, ack, self.send.nxt.wrapping_add(1)) {
                return Ok(());
            }
            // self.send.una = ack;
            assert!(data.is_empty());
            // terminate the connection for now
            self.tcp.fin = true;
            self.write(nic, &[])?;
            self.state = State::FinWait1;
        }

        if let State::FinWait1 = self.state {
            if self.send.una == self.send.iss + 2 {
                // Sender would have ACK-ed our FIN.
                self.state = State::FinWait2;
            }
        }

        if tcp.fin() {
            if let State::FinWait2 = self.state {
                // Connection terminated
                // Sender would have ACK-ed our FIN - ACK sender's FIN
                // self.tcp.fin = false;
                self.write(nic, &[])?;
                self.state = State::TimeWait;
            }
        }

        Ok(())
    }

    /// Returns false if check failed
    fn is_between_wrapped(start: u32, x: u32, end: u32) -> bool {
        use std::cmp::Ordering;
        match start.cmp(&x) {
            Ordering::Equal => {
                return false;
            }
            Ordering::Less => {
                // check fails iff end is between start and x
                if end >= start && end <= x {
                    return false;
                }
            }
            Ordering::Greater => {
                // check fails iff x is NOT between start and x
                if !(end < start && end > x) {
                    return false;
                }
            }
        }
        true
    }

    pub fn send_rst(&mut self, nic: &tun_tap::Iface) -> io::Result<()> {
        // TODO: fix seq numbers and handle synchronized RST
        self.tcp.rst = true;
        self.tcp.sequence_number = 0;
        self.tcp.acknowledgment_number = 0;
        self.write(nic, &[])?;
        Ok(())
    }
}
