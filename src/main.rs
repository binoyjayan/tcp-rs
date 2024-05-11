fn main() {
    tun_tap::Iface::new("tun0", tun_tap::Mode::Tun).expect("Failed to create TUN device");
}
