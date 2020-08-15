# How Doorbird Apps Find Devices

mdns broadcast for `_axis_video._tcp` as a QU (unicast response please)

get replies, but ignore the hostname and A/AAAA fields, and assume the source IP of the dns reply packet is the doorbird host.

this is why avahi-reflector doesn't help, because doorbird apps assume the machine running reflector is the device, and try to connect to it.

a general solution might look something like avahi-reflector but spoofing the source IP of the packet containing the dns reply


i think this is just a simple unintended bug in the doorbird code? they want the IP of the device, and grab it (wrongly) from the dns reply packet src ip, instead of parsing out the DNS A record (doorbird devices send dns "additional records" with A, AAAA, etc). If they fixed this behaviour, it would allow general solutions like avahi-reflector to work fine.

afaik you are supposed to be able to advertise mDNS services not at your own ip, so this is a bug.

# Proof of concept

only works with the spoofed source ip

(next step is make this query doorbird vlan and relay results with spoofed srcs, so it doesn't need to be told lots of config)

````python
#!/usr/bin/env python3

from scapy.all import *


def handle_multicast_query_from_app(pkt):
    d = pkt.getlayer(DNSQR)
    if not d:
        return
    if d.qname != b'_axis-video._tcp.local.':
        return
    src_ip = pkt.getlayer(IP).src
    src_port = pkt.getlayer(UDP).sport

    print(f'Got multicast query from {src_ip}:{src_port}, will reply.')
    print(pkt.summary())


    dns_part = DNS( id=pkt[DNS].id,  # replies copy question ids, for matching up (16bit)
                    aa=1,  # authoritative
                    qr=1,  # is response
                    rd=pkt[DNS].rd,  # recursion desired?
                    qdcount=pkt[DNS].qdcount,  # copy question count
                    qd=pkt[DNS].qd,  # original question
                    # populated below
#                   ancount=1, # we provide 1 answer
#                   an=answer,   # answer
#                   arcount=0,  # additional record count
#                   ar=None,   # additional records
                    )

    name = 'Doorstation - 1CCAE3726551'
    fqname = 'Doorstation - 1CCAE3726551._axis-video._tcp.local'
    hostname = 'bha-1CCAE3726551.local'

    # rr = resource record, aka DNS reply
    dns_part.an = DNSRR(rrname="_axis-video._tcp.local", type="PTR", rclass=1, ttl=10, rdata=fqname)

    ar_srv = DNSRRSRV(rrname=fqname, rclass=1, ttl=10, priority=0, weight=0, port=80, target=hostname)
    #ar_txt = DNSRR(rrname=fqname, type="TXT", rclass=0x8001, ttl=10, rdata="macaddress=1CCAE3726551")
    ar_txt = DNSRR(rrname=fqname, type="TXT", rclass=1, ttl=10, rdata="macaddress=1CCAE3726551")
    ar_a   = DNSRR(rrname=hostname, type="A", rclass=1, ttl=10, rdata='10.0.1.18')

    dns_part.ar = ar_srv / ar_txt / ar_a



    # you gotta spoof the source ip of the dns response to the device, because it seems like
    # doorbird take the IP from the dns responder, not the IP in the actual dns reply (argh!)
    # this is why avahi-reflector doesn't work, since doorbird tries to connect to the IP of the reflector machine.
    rpkt = Ether()/IP(dst=src_ip, src='10.0.1.18', ttl=1)/UDP(sport=5353, dport=src_port)/dns_part.compress()
    sendp(rpkt, verbose=1, iface='lanif')



if __name__ == "__main__":
    print("Listening for multicast queries from apps looking for doorbird devices..")
    sniff(iface='lanif',
          filter="udp and dst port 5353 and dst host 224.0.0.251 and src net 10.0.0.0/24",  # and src host 10.0.0.23",
          store=0,
          prn=handle_multicast_query_from_app)
````
