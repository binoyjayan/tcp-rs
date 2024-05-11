# tcp-rs
TCP/IP implementation in rust


## Create a tun interface

```
sudo ip tuntap add mode tun user <username>
```

## Set capability

```
sudo setcap cap_net_admin=ep target/debug/tcp-rs
sudo setcap cap_net_admin=ep target/release/tcp-rs
```

## Set ip

```
sudo ip addr add 192.168.0.22/24 dev tun0 
sudo ip link set up dev tun0
```

## Establish a tcp connection

```
nc 192.168.0.2 80
```

## References

https://www.kernel.org/doc/Documentation/networking/tuntap.txt
