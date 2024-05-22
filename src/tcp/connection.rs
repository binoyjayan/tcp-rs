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

        let size = std::cmp::min(
            buf.len(),
            self.ip.header_len() + self.tcp.header_len() + payload.len(),
        );
        let _ = self.ip.set_payload_len(size - self.ip.header_len());

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
        let okay = if slen == 0 {
            // zero length segment
            if self.receive.wnd == 0 {
                if seq != self.receive.nxt {
                    false
                } else {
                    true
                }
            } else if !Self::is_between_wrapped(self.receive.nxt.wrapping_sub(1), seq, wend) {
                false
            } else {
                true
            }
        } else if self.receive.wnd == 0 {
            false
        } else if !Self::is_between_wrapped(self.receive.nxt.wrapping_sub(1), seq, wend)
            && !Self::is_between_wrapped(
                self.receive.nxt.wrapping_sub(1),
                seq.wrapping_add(slen - 1),
                wend,
            )
        {
            false
        } else {
            true
        };

        if !okay {
            // Not acceptable
            self.write(nic, &[])?;
            return Ok(());
        }
        // Adjust receive sequence space: we have accepted the segment
        self.receive.nxt = seq.wrapping_add(slen);

        // TODO: If not acceptable, send ACK, drop segment and return
        // <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>

        if !tcp.ack() {
            return Ok(());
        }
        let ack = tcp.acknowledgment_number();
        // Acceptable ACK check: SND.UNA < SEG.ACK =< SND.NXT
        if let State::SynReceived = self.state {
            if Self::is_between_wrapped(
                self.send.una.wrapping_sub(1),
                // self.send.una,
                ack,
                self.send.nxt.wrapping_add(1),
            ) {
                // The peer must have ACK-ed out SYN, since we detected atleast
                // one ACK-ed byte which was for the to SYN
                self.state = State::Established;
            } else {
                //TODO: Form a RST segment: SEQ=SEG.ACK><CTL=RST>
            }
        }

        if let State::Established | State::FinWait1 | State::FinWait2 = self.state {
            if !Self::is_between_wrapped(self.send.una, ack, self.send.nxt.wrapping_add(1)) {
                return Ok(());
            }
            self.send.una = ack;
            if !data.is_empty() {
                println!("Data is not empty");
            }

            if let State::Established = self.state {
                // terminate the connection for now
                self.tcp.fin = true;
                self.write(nic, &[])?;
                self.state = State::FinWait1;
            }
        }

        if let State::FinWait1 = self.state {
            if self.send.una == self.send.iss + 2 {
                // Sender would have ACK-ed our FIN.
                self.state = State::FinWait2;
            }
        }

        if tcp.fin() {
            if let State::FinWait2 = self.state {
                eprintln!("Received ACK for FIN");
                // Connection terminated
                // Sender would have ACK-ed our FIN - ACK sender's FIN
                // self.tcp.fin = false;
                self.write(nic, &[])?;
                self.state = State::TimeWait;
            }
        }

        Ok(())
    }

    /// TCP half-domain wrapping
    ///
    /// It is essential to remember that the actual sequence number space is
    /// finite, though very large.  This space ranges from 0 to 2**32 - 1.
    /// Since the space is finite, all arithmetic dealing with sequence
    /// numbers must be performed modulo 2**32.  This unsigned arithmetic
    /// preserves the relationship of sequence numbers as they cycle from
    /// 2**32 - 1 to 0 again. The symbol "=<" means "less than or equal"
    /// [modulo 2**32].
    ///
    /// RFC 1323:
    /// TCP determines if a data segment is "old" or "new" by testing
    /// whether its sequence number is within 2**31 bytes of the left edge
    /// of the window, and if it is not, discarding the data as "old".  To
    /// insure that new data is never mistakenly considered old and vice-
    /// versa, the left edge of the sender's window has to be at most
    /// 2**31 away from the right edge of the receiver's window.
    ///
    /// This function checks if a sequence number `x` is between `start` and `end`
    /// in a circular space, considering the wrapping behavior of TCP sequence numbers.
    ///
    /// # Arguments
    ///
    /// * `start` - The starting sequence number of the range.
    /// * `x` - The sequence number to check.
    /// * `end` - The ending sequence number of the range.
    ///
    /// # Returns
    ///
    /// * `true` if `x` is between `start` and `end` in the circular sequence space.
    /// * `false` otherwise.
    fn is_between_wrapped(start: u32, x: u32, end: u32) -> bool {
        Self::wrapping_lt(start, x) && Self::wrapping_lt(x, end)
    }

    /// Compares two sequence numbers using TCP's sequence number wrapping rules.
    ///
    /// This function returns `true` if `lhs` is less than `rhs` in the circular
    /// sequence space, considering the wrapping behavior.
    ///
    /// # Arguments
    ///
    /// * `lhs` - The left-hand side sequence number.
    /// * `rhs` - The right-hand side sequence number.
    ///
    /// # Returns
    ///
    /// * `true` if `lhs` is less than `rhs` in the circular sequence space.
    /// * `false` otherwise.
    fn wrapping_lt(lhs: u32, rhs: u32) -> bool {
        lhs.wrapping_sub(rhs) > u32::max_value() >> 1
    }

    pub fn _send_rst(&mut self, nic: &tun_tap::Iface) -> io::Result<()> {
        // TODO: fix seq numbers and handle synchronized RST
        self.tcp.rst = true;
        self.tcp.sequence_number = 0;
        self.tcp.acknowledgment_number = 0;
        self.write(nic, &[])?;
        Ok(())
    }
}
