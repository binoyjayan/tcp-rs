use std::io;
use std::io::Read;
use std::thread;

use tcprs::Interface;

fn main() -> io::Result<()> {
    let mut iface = Interface::new()?;
    let mut list1 = iface.bind(6000)?;

    let jh1 = thread::spawn(move || {
        while let Ok(mut stream) = list1.accept() {
            eprintln!("Connected");
            loop {
                let mut buf = [0u8; 512];
                let n = stream.read(&mut buf).unwrap();
                eprintln!("Read {} bytes of data", n);
                if n == 0 {
                    break;
                }
            }
        }
    });
    let _ = jh1.join();
    Ok(())
}

