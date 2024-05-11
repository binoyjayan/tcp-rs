use etherparse::{IpNumber, Ipv4HeaderSlice, TcpHeaderSlice};
use std::io;

fn main() -> io::Result<()> {
    let nic = tun_tap::Iface::new("tun0", tun_tap::Mode::Tun).expect("Failed to create TUN device");
    // Create a buffer. 4 bytes to hold extra tun frame format
    let mut buf = [0u8; 1504];
    loop {
        let nbytes = nic.recv(&mut buf[..])?;
        // By default, the tun frame format includes flags,proto,raw data
        let _flags = u16::from_be_bytes([buf[0], buf[1]]);
        let proto = u16::from_be_bytes([buf[2], buf[3]]);
        if proto != 0x800 {
            continue; // ignore non-ipv4
        }
        match Ipv4HeaderSlice::from_slice(&buf[4..nbytes]) {
            Ok(ip) => {
                let src = ip.source_addr();
                let dst = ip.destination_addr();
                let proto = ip.protocol();
                if proto != IpNumber::TCP {
                    continue;                    
                }
                let tcp_raw = &buf[4 + ip.slice().len()..];
                match TcpHeaderSlice::from_slice(tcp_raw) {
                    Ok(tcp) => {
                        let srcp = tcp.source_port();
                        let dstp = tcp.destination_port();
                        let len = tcp.slice().len();
                        println!("TCP [{}:{}] {}:{} -> {}:{}", nbytes, len, src, srcp, dst, dstp);
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
