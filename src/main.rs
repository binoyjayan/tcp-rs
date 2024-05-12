use etherparse::{IpNumber, Ipv4HeaderSlice, TcpHeaderSlice};
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::io;

mod tcp;

use tcp::connection::{Connection, Tcp4Tuple};

const MTU: usize = 1500;

fn main() -> io::Result<()> {
    let nic = tun_tap::Iface::without_packet_info("tun0", tun_tap::Mode::Tun)
        .expect("Failed to create TUN device");
    // Create a buffer
    let mut buf = [0u8; MTU];
    let mut connections: HashMap<Tcp4Tuple, Connection> = HashMap::new();

    loop {
        let nbytes = nic.recv(&mut buf[..])?;
        let version = buf[0] >> 4;
        if version != 4 {
            continue; // ignore non-ip
        }
        match Ipv4HeaderSlice::from_slice(&buf[..nbytes]) {
            Ok(ip) => {
                let src = ip.source_addr();
                let dst = ip.destination_addr();
                let proto = ip.protocol();
                let ip_len = ip.slice().len();
                if proto != IpNumber::TCP {
                    continue; // ignore non-tcp
                }
                let tcp_raw = &buf[ip_len..nbytes];
                match TcpHeaderSlice::from_slice(tcp_raw) {
                    Ok(tcp) => {
                        let srcp = tcp.source_port();
                        let dstp = tcp.destination_port();
                        let tcp_len = tcp.slice().len();
                        let data_off = ip_len + tcp_len;
                        let data = &buf[data_off..nbytes];
                        match connections.entry(Tcp4Tuple {
                            src: (src, srcp),
                            dst: (dst, dstp),
                        }) {
                            Entry::Occupied(mut entry) => {
                                let conn = entry.get_mut();
                                conn.on_packet(&nic, ip, tcp, data)
                                    .map_err(|e| eprintln!("Error processing packet: {:?}", e))
                                    .ok();
                            }
                            Entry::Vacant(e) => match Connection::accept(&nic, ip, tcp, data) {
                                Ok(c) => {
                                    e.insert(c);
                                }
                                Err(e) => eprintln!("Error creating connection: {:?}", e),
                            },
                        }
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
