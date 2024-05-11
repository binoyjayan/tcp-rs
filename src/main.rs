use etherparse::{IpNumber, Ipv4HeaderSlice, TcpHeaderSlice};
use std::collections::HashMap;
use std::io;

mod tcp;

use tcp::{Tcp4Tuple, TcpState};

const TUN_FRAME_LEN: usize = 4;
const MTU: usize = 1500;

fn main() -> io::Result<()> {
    let nic = tun_tap::Iface::new("tun0", tun_tap::Mode::Tun).expect("Failed to create TUN device");
    // Create a buffer. 4 bytes to hold extra tun frame format
    let mut buf = [0u8; MTU + TUN_FRAME_LEN];
    let mut connections: HashMap<Tcp4Tuple, TcpState> = HashMap::new();

    loop {
        let nbytes = nic.recv(&mut buf[..])?;
        // By default, the tun frame format includes flags,proto,raw data
        let _flags = u16::from_be_bytes([buf[0], buf[1]]);
        let proto = u16::from_be_bytes([buf[2], buf[3]]);
        if proto != 0x800 {
            continue; // ignore non-ipv4
        }
        match Ipv4HeaderSlice::from_slice(&buf[TUN_FRAME_LEN..nbytes]) {
            Ok(ip) => {
                let src = ip.source_addr();
                let dst = ip.destination_addr();
                let proto = ip.protocol();
                let ip_len = ip.slice().len();
                if proto != IpNumber::TCP {
                    continue; // ignore non-tcp
                }
                let tcp_raw = &buf[TUN_FRAME_LEN + ip_len..nbytes];
                match TcpHeaderSlice::from_slice(tcp_raw) {
                    Ok(tcp) => {
                        let srcp = tcp.source_port();
                        let dstp = tcp.destination_port();
                        let tcp_len = tcp.slice().len();
                        let data_off = TUN_FRAME_LEN + ip_len + tcp_len;
                        let data = &buf[data_off..nbytes];
                        connections
                            .entry(Tcp4Tuple {
                                src: (src, srcp),
                                dst: (dst, dstp),
                            })
                            .or_default()
                            .on_packet(ip, tcp, data);
                    }
                    Err(e) => {
                        eprintln!("Ignoring packet. len:{} Err: {}", nbytes, e);
                    }
                }
            }
            Err(e) => {
                eprintln!("Ignoring packet. len:{} Err: {}", nbytes, e);
            }
        }
    }
}
