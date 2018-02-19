ip addr add 10.0.3.1/24 dev tun0
ifconfig tun0 up
route add -net 10.0.4.0/24 dev tun0
route add -net 10.0.30.0/24 dev tun0
sysctl net.ipv4.ip_forward=1
