use std::io;
use std::thread;

use tcprs::Interface;

fn main() -> io::Result<()> {
    let mut iface = Interface::new()?;
    let mut list1 = iface.bind(6000)?;

    let jh1 = thread::spawn(move || {
        while let Ok(_stream) = list1.accept() {
            eprintln!("Connected");
            // let n = stream.read(&mut [0]).unwrap();
            // assert_eq!(n, 0);
        }
    });
    let _ = jh1.join();
    Ok(())
}
