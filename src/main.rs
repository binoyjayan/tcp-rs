use std::io::Read;
use std::io::{self, Write};
use std::thread;

use tcprs::Interface;

fn main() -> io::Result<()> {
    let mut iface = Interface::new()?;
    let mut listener = iface.bind(6000)?;

    while let Ok(mut stream) = listener.accept() {
        eprintln!("Connected");
        let jh1 = thread::spawn(move || {
            if let Err(e) = stream.write(b"Hello\n") {
                eprintln!("Error {:?}", e);
            }
            // Indicate CLOSE from our side
            stream.shutdown(std::net::Shutdown::Write).unwrap();

            loop {
                let mut buf = [0u8; 512];
                let n = stream.read(&mut buf).unwrap();
                if n == 0 {
                    println!("EOF");
                    break;
                }
                println!("[{}]{}", n, std::string::String::from_utf8_lossy(&buf[..n]));
            }
        });
        let _ = jh1.join();
    }

    Ok(())
}
