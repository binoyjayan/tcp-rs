use etherparse::{IpNumber, Ipv4Header, Ipv4HeaderSlice, TcpHeader, TcpHeaderSlice};
use std::collections::{BTreeMap, VecDeque};
use std::net::Ipv4Addr;
use std::{io, io::Write, time};

use super::sequence::ReceiveSequenceSpace;
use super::sequence::SendSequenceSpace;
use super::state::{Available, State};

const MTU: usize = 1500;
const TTL: u8 = 64;
const ISS: u32 = 0; // Needs to change
const WINDOW_SIZE: u16 = 10; // 4096;

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct Tcp4Tuple {
    pub src: (Ipv4Addr, u16),
    pub dst: (Ipv4Addr, u16),
}

#[derive(Debug)]
struct Timers {
    /// when last segment was sent
    // last_send: time::Instant,
    /// segment sequence number and when it was sent
    // send_times: VecDeque<(u32, time::Instant)>,
    send_times: BTreeMap<u32, time::Instant>,
    /// round trip time
    srtt: f64,
}

impl Timers {
    fn new() -> Self {
        Self {
            // last_send: time::Instant::now(),
            // send_times: VecDeque::default(),
            send_times: BTreeMap::default(),
            srtt: time::Duration::from_secs(60).as_secs_f64(),
        }
    }
}

#[derive(Debug)]
pub struct Connection {
    pub state: State,
    send: SendSequenceSpace,
    receive: ReceiveSequenceSpace,
    timers: Timers,
    ip: Ipv4Header,
    tcp: TcpHeader,
    pub ingress: VecDeque<u8>,
    pub unacked: VecDeque<u8>,
    pub closed: bool,
    closed_at: Option<u32>,
}

impl Connection {
    /// Any state after receiving FIN
    pub fn is_recv_closed(&self) -> bool {
        if let State::TimeWait = self.state {
            // TODO: CLOSE-WAIT, LAST-ACK, CLOSED, CLOSING
            true
        } else {
            false
        }
    }

    /// Function to indicate read and write availability.
    /// Marking data availability will helps decidie waking processes up
    /// that are waiting for data to be available
    fn availability(&self) -> Available {
        let mut avail = Available::empty();
        if self.is_recv_closed() || !self.ingress.is_empty() {
            avail |= Available::READ;
        }
        // TODO: set Available::WRITE
        avail
    }

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
            timers: Timers::new(),
            ip: resp_ip,
            tcp: resp_tcp,
            ingress: VecDeque::new(),
            unacked: VecDeque::new(),
            closed: false,
            closed_at: None,
        };
        conn.write(nic, conn.send.nxt, 0)?;
        Ok(conn)
    }

    pub fn write(
        &mut self,
        nic: &tun_tap::Iface,
        seq: u32,
        // offset: usize,
        limit: usize,
    ) -> io::Result<usize> {
        let mut buf = [0u8; MTU];
        self.tcp.sequence_number = seq;
        self.tcp.acknowledgment_number = self.receive.nxt;

        let mut offset = seq.wrapping_sub(self.send.una) as usize;

        // Handle special cases of SYN and FIN
        // If asked to send bytes starting at after SYN/FIN, do not read any data
        if let Some(closed_at) = self.closed_at {
            if seq == closed_at.wrapping_add(1) {
                offset = 0;
            }
        }

        let (mut h, mut t) = self.unacked.as_slices();
        if h.len() >= offset {
            h = &h[offset..];
        } else {
            let skipped = h.len();
            h = &[];
            t = &t[(offset - skipped)..];
        }

        let max_data: usize = std::cmp::min(limit, h.len() + t.len());

        let size = std::cmp::min(
            buf.len(),
            self.ip.header_len() + self.tcp.header_len() + max_data,
        );
        let _ = self.ip.set_payload_len(size - self.ip.header_len());

        // Calculate checksum
        self.tcp.checksum = self
            .tcp
            .calc_checksum_ipv4(&self.ip, &[])
            .expect("checksum failed");
        let mut cursor = io::Cursor::new(&mut buf[..]);
        self.ip.write(&mut cursor)?;
        self.tcp.write(&mut cursor)?;

        let payload_bytes = {
            let mut written = 0;
            // write as much as possible from h
            let mut limit = max_data;
            let p1len = std::cmp::min(limit, h.len());
            written += cursor.write(&h[..p1len])?;
            limit -= written;

            // write more from t
            let p2len = std::cmp::min(limit, t.len());
            written += cursor.write(&t[..p2len])?;
            // limit -= written;
            written
        };
        let len = cursor.position() as usize;

        // Adjust send sequence space
        let mut next_seq = seq.wrapping_add(payload_bytes as u32);

        if self.tcp.syn {
            next_seq = next_seq.wrapping_add(1);
            self.tcp.syn = false;
        }
        if self.tcp.fin {
            next_seq = next_seq.wrapping_add(1);
            self.tcp.fin = false;
        }
        // self.send.nxt = self.send.nxt.wrapping_add(payload_bytes as u32);
        if Self::wrapping_lt(self.send.nxt, next_seq) {
            self.send.nxt = next_seq;
        }

        self.timers.send_times.insert(seq, time::Instant::now());

        nic.send(&buf[0..len])?;
        Ok(payload_bytes)
    }

    pub fn on_packet(
        &mut self,
        nic: &tun_tap::Iface,
        _ip: Ipv4HeaderSlice,
        tcp: TcpHeaderSlice,
        data: &[u8],
    ) -> io::Result<Available> {
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
                seq == self.receive.nxt
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
            self.write(nic, self.send.nxt, 0)?;
            return Ok(self.availability());
        }
        // Adjust receive sequence space: we have accepted the segment
        // self.receive.nxt = seq.wrapping_add(slen);

        // TODO: If not acceptable, send ACK, drop segment and return
        // <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>

        if !tcp.ack() {
            if tcp.syn() {
                // SYN as part of initial handshake
                self.receive.nxt = seq.wrapping_add(1);
            }
            return Ok(self.availability());
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
            if Self::is_between_wrapped(self.send.una, ack, self.send.nxt.wrapping_add(1)) {
                // Remove ACK-ed bytes from retransmission queue
                let nbytes = ack.wrapping_sub(self.send.una) as usize;
                if !self.unacked.is_empty() {
                    let _acked = self.unacked.drain(..nbytes).count();
                    // let mut old = std::mem::replace(&mut self.timers.send_times, BTreeMap::new());
                    // self.timers.send_times.extend(old.into_iter().filter_map(f));
                    self.timers.send_times.retain(|seq, sent| {
                        if Self::is_between_wrapped(self.send.una, *seq, ack) {
                            let rtt = sent.elapsed().as_secs_f64();
                            self.timers.srtt = 0.8 * self.timers.srtt + (1. - 0.8) * rtt;
                            false
                        } else {
                            true
                        }
                    });
                }

                self.send.una = ack;
            }

            // Since we do not have anything to send, indicate FIN from us
            // if let State::Established = self.state {
            //     self.tcp.fin = true;
            //     self.state = State::FinWait1;
            // }
        }

        if let State::FinWait1 = self.state {
            if self.send.una == self.send.iss + 2 {
                // Sender would have ACK-ed our FIN.
                self.state = State::FinWait2;
            }
        }

        // Handle reads
        if let State::Established | State::FinWait1 | State::FinWait2 = self.state {
            // offset to unread data
            let mut offset = self.receive.nxt.saturating_sub(seq) as usize;
            // nxt points to beyond the FIN but FIN is not in data
            if offset > data.len() {
                offset = offset.saturating_sub(1);
            }

            self.ingress.extend(&data[offset..]);
            // Adjust receive sequence space: we have accepted the segment

            self.receive.nxt = seq
                .wrapping_add(data.len() as u32)
                .wrapping_add(if tcp.fin() { 1 } else { 0 });

            // Send ACK. Piggyback ACK on data?
            self.write(nic, self.send.nxt, 0)?;
        }

        if tcp.fin() {
            if let State::FinWait2 = self.state {
                // Connection terminated
                // Sender would have ACK-ed our FIN - ACK sender's FIN
                self.write(nic, self.send.nxt, 0)?;
                self.state = State::TimeWait;
            }
        }

        Ok(self.availability())
    }

    /// Decide if something needs to be transmitted. Check if we have
    /// space in the window. If so, transmit it.
    pub fn on_timer(&mut self, nic: &tun_tap::Iface) -> io::Result<()> {
        // bytes sent but not ACK-ed
        let unacked = self.send.nxt.wrapping_sub(self.send.una);
        // bytes not sent yet
        let unsent = self.unacked.len() as u32 - unacked;

        // Get the elapsed time of the first unacked send time
        let waited_for = self
            .timers
            .send_times
            .range(self.send.una..)
            .next()
            .map(|t| t.1.elapsed());

        let should_restransmit = if let Some(waited_for) = waited_for {
            waited_for > time::Duration::from_secs(1)
                && waited_for.as_secs_f64() > 1.5 * self.timers.srtt
        } else {
            false // no timers
        };

        if should_restransmit {
            // retransmit
            let resend = std::cmp::min(self.unacked.len() as u32, self.send.wnd as u32);
            if resend < self.send.wnd as u32 && self.closed_at.is_some() {
                // If no data to send and connection was closed, do nothing
                self.tcp.fin = true;
                self.closed_at = Some(self.send.nxt.wrapping_add(self.unacked.len() as u32));
            }

            self.write(nic, self.send.una, resend as usize)?;
        } else {
            // send new data if available and there is space in the window
            if unsent == 0 && !self.closed {
                return Ok(());
            }
            let allowed = self.send.wnd as u32 - unacked;
            if allowed == 0 {
                return Ok(());
            }
            let send = std::cmp::min(unsent, allowed);
            if send < allowed && self.closed && self.closed_at.is_none() {
                // Send FIN
                self.tcp.fin = true;
                self.closed_at = Some(self.send.nxt.wrapping_add(self.unacked.len() as u32));
            }
            // let (mut h, mut t) = self.unacked.as_slices();
            // we want self.unacked[unacked..]
            // if h.len() >= unacked as usize {
            //     h = &h[unacked as usize..];
            // } else {
            //     let skipped = h.len();
            //     h = &[];
            //     t = &t[(unacked as usize - skipped)..];
            // }
            self.write(nic, self.send.nxt, send as usize)?;
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

    pub fn close(&mut self) -> io::Result<()> {
        self.closed = true;
        match self.state {
            State::SynReceived | State::Established => {
                self.state = State::FinWait1;
            }
            State::FinWait1 | State::FinWait2 => {}
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "already closing",
                ));
            }
        }
        Ok(())
    }
    pub fn _send_rst(&mut self, nic: &tun_tap::Iface) -> io::Result<()> {
        // TODO: fix seq numbers and handle synchronized RST
        self.tcp.rst = true;
        self.tcp.sequence_number = 0;
        self.tcp.acknowledgment_number = 0;
        self.write(nic, self.send.nxt, 0)?;
        Ok(())
    }
}
