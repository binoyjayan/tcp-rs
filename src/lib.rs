use etherparse::{IpNumber, Ipv4HeaderSlice, TcpHeaderSlice};
use std::{
    collections::{hash_map, HashMap, VecDeque},
    io,
    sync::{Arc, Condvar, Mutex},
    thread,
};

mod tcp;

use tcp::{
    connection::{Connection, Tcp4Tuple},
    state::Available,
};

const BUFFER_SIZE: usize = 1504;
const SEND_QUEUE_SIZE: usize = 1024;

/// Type for handling interface requests
type InterfaceHandle = Arc<InterfaceManager>;

#[derive(Default)]
struct InterfaceManager {
    manager: Mutex<ConnectionManager>,
    pending_var: Condvar,
    receive_var: Condvar,
}

/// struct for managing connections.
#[derive(Default)]
pub struct ConnectionManager {
    // Array to store port for which connections are accepted
    pending: HashMap<u16, VecDeque<Tcp4Tuple>>,
    // Accepted connections
    connections: HashMap<Tcp4Tuple, Connection>,
    // flag to terminate
    terminate: bool,
}

/// Struct that acts as an interface to the tcp implementation
/// Essentially, it interfaces to the thread that manages tcp connections
/// and an interface handle (to connection manager) that keeps track of
/// the connections
pub struct Interface {
    ih: Option<InterfaceHandle>,
    jh: Option<thread::JoinHandle<io::Result<()>>>,
}

fn packet_loop(nic: tun_tap::Iface, ih: InterfaceHandle) -> io::Result<()> {
    let mut buf = [0u8; BUFFER_SIZE];

    loop {
        // TODO: timeout
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

                        let mut cm_guard = ih.manager.lock().unwrap();
                        // Trick to borrow a mutable reference to the underlying connection manager
                        // instead of just a reference to the outer mutex guard
                        let cm = &mut *cm_guard;

                        let quad = Tcp4Tuple {
                            src: (src, srcp),
                            dst: (dst, dstp),
                        };

                        match cm.connections.entry(quad.clone()) {
                            hash_map::Entry::Occupied(mut entry) => {
                                let conn = entry.get_mut();
                                match conn.on_packet(&nic, ip, tcp, data) {
                                    Ok(avail) => {
                                        drop(cm_guard);
                                        if avail.contains(Available::READ) {
                                            ih.receive_var.notify_all();
                                        }
                                        if avail.contains(Available::WRITE) {
                                            // ih.send_var.notify_all();
                                        }
                                    }
                                    Err(e) => {
                                        eprintln!("Error processing packet: {:?}", e);
                                    }
                                }
                            }
                            hash_map::Entry::Vacant(e) => {
                                if let Some(pending) = cm.pending.get_mut(&dstp) {
                                    match Connection::accept(&nic, ip, tcp, data) {
                                        Ok(c) => {
                                            e.insert(c);
                                            pending.push_back(quad);
                                            // Release the lock so the woken threads can use the lock
                                            drop(cm_guard);
                                            // Notify all waiting threads
                                            ih.pending_var.notify_all();
                                        }
                                        Err(e) => eprintln!("Error accepting connection: {:?}", e),
                                    }
                                }
                            }
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

impl Interface {
    pub fn new() -> io::Result<Self> {
        let nic = tun_tap::Iface::without_packet_info("tun0", tun_tap::Mode::Tun)?;
        let ih: InterfaceHandle = Arc::default();

        // create a new thread and move the connection manager into the thread

        let jh = {
            let ih = ih.clone();
            Some(thread::spawn(move || packet_loop(nic, ih)))
        };

        Ok(Interface { ih: Some(ih), jh })
    }
    pub fn bind(&mut self, port: u16) -> io::Result<TcpListener> {
        let mut cm = self.ih.as_mut().unwrap().manager.lock().unwrap();
        match cm.pending.entry(port) {
            hash_map::Entry::Vacant(v) => {
                v.insert(VecDeque::new());
            }
            hash_map::Entry::Occupied(_o) => {
                return Err(io::Error::new(io::ErrorKind::AddrInUse, "Port in use"));
            }
        }
        // Start accepting SYN packets on 'port'
        drop(cm);
        Ok(TcpListener {
            ih: self.ih.as_mut().unwrap().clone(),
            port,
        })
    }
}

impl Drop for Interface {
    fn drop(&mut self) {
        self.ih.as_mut().unwrap().manager.lock().unwrap().terminate = true;
        drop(self.ih.take());
        self.jh
            .take()
            .expect("interface killed already")
            .join()
            .unwrap()
            .unwrap();
    }
}

pub struct TcpListener {
    ih: InterfaceHandle,
    port: u16,
}

impl TcpListener {
    pub fn accept(&mut self) -> io::Result<TcpStream> {
        let mut cm = self.ih.manager.lock().unwrap();
        loop {
            if let Some(quad) = cm
                .pending
                .get_mut(&self.port)
                .expect("Port closed while listener is active")
                .pop_front()
            {
                return Ok(TcpStream {
                    ih: self.ih.clone(),
                    quad,
                });
            }
            // Block for connections
            cm = self.ih.pending_var.wait(cm).unwrap();
        }
    }
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        let mut cm = self.ih.manager.lock().unwrap();
        let pending = cm
            .pending
            .remove(&self.port)
            .expect("Failed to remove port listener");

        for quad in pending {
            // TODO: Shutdown connection
            eprintln!("Terminating {:?}", quad);
        }
    }
}

pub struct TcpStream {
    ih: InterfaceHandle,
    quad: Tcp4Tuple,
}

impl io::Read for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut cm = self.ih.manager.lock().unwrap();
        loop {
            let conn = cm
                .connections
                .get_mut(&self.quad)
                .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "Connection closed"))?;

            if conn.is_recv_closed() && conn.ingress.is_empty() {
                // No more data to read
                return Ok(0);
            }

            if !conn.ingress.is_empty() {
                let mut nread = 0;
                let (head, tail) = conn.ingress.as_slices();
                let hread = std::cmp::min(buf.len(), head.len());
                buf.copy_from_slice(&head[..hread]);
                nread += hread;
                let tread = std::cmp::min(buf.len() - nread, tail.len());
                buf.copy_from_slice(&tail[..tread]);
                nread += tread;
                drop(conn.ingress.drain(..nread));
                return Ok(nread);
            }

            // return Err(io::Error::new(io::ErrorKind::WouldBlock, "Nothing to read"));
            cm = self.ih.receive_var.wait(cm).unwrap();
        }
    }
}

impl io::Write for TcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut cm = self.ih.manager.lock().unwrap();

        let conn = cm
            .connections
            .get_mut(&self.quad)
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "Connection closed"))?;

        if conn.unacked.len() >= SEND_QUEUE_SIZE {
            // TODO: block
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "Too much data to write",
            ));
        }

        let nwrite = std::cmp::min(buf.len(), SEND_QUEUE_SIZE - conn.unacked.len());
        conn.unacked.extend(&mut buf[..nwrite].iter());

        // TODO: Schedule wakeup
        Ok(nwrite)
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut cm = self.ih.manager.lock().unwrap();

        let conn = cm
            .connections
            .get_mut(&self.quad)
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "Connection closed"))?;

        if conn.unacked.is_empty() {
            return Ok(());
        }
        // TODO: block
        Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "Too much data to write",
        ))
    }
}

impl TcpStream {
    pub fn shutdown(&self, _how: std::net::Shutdown) -> io::Result<()> {
        // TODO: Send FIN
        Ok(())
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        let _cm = self.ih.manager.lock().unwrap();
        // if let Some(_conn) = cm.connections.remove(&self.quad) {
        //     // TODO: Send FIN
        // }
    }
}
