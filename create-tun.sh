#!/bin/bash

if [ "$UID" -ne 0 ]; then
  echo "Run as root."
  exit 1
fi

if [ -z "$1" ]; then
  echo "Usage: $0 <username>"
  exit 1
fi
username="$1"

ip tuntap add mode tun user $username
ip addr add 192.168.0.1/24 dev tun0
ip link set up dev tun0
setcap cap_net_admin=ep target/debug/tcp-rs

