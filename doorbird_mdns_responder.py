#!/usr/bin/env python3
# formatted with Black

from scapy.all import *
import argparse
import sys

parser = argparse.ArgumentParser(
    description=(
        "Respond to mDNS queries looking for Doorbird devices, spoofing source ip of"
        " replies to appear to come from the devices directly."
    ),
    epilog="eg: %(prog)s -v -i eth0 -a 1CCAE3726FE3/10.1.2.3",
)
parser.add_argument("-v", "--verbose", action="store_true", help="Log to stdout")
parser.add_argument(
    "-i", "--iface", required=True, help="<Required> Interface to listen on (eg 'eth0')"
)
parser.add_argument(
    "-a",
    "--advertise",
    action="append",
    required=True,
    help=(
        "<Required> Advertise doorbird device(s), format is <mac>/<ipv4>, eg: -a"
        " 1CCAE3726FE3/10.1.2.3"
    ),
)

args = parser.parse_args()

doorbirds = []
for ad in args.advertise:
    [mac, addr] = ad.strip().split("/")
    mac = mac.upper().replace(":", "").strip()
    if len(mac) != 12:
        print("ERROR: invalid mac")
        sys.exit(1)
    doorbirds.append({"mac": mac, "addr": addr})


def handle_multicast_query_from_app(pkt):
    # ignore anything that isn't a DNS question
    d = pkt.getlayer(DNSQR)
    if not d:
        return
    # ignore questions unless they are for doorbird devices
    if d.qname != b"_axis-video._tcp.local.":
        return

    src_ip = pkt.getlayer(IP).src
    src_port = pkt.getlayer(UDP).sport

    if args.verbose:
        print(f"> Got mDNS query for '{d.qname}' from {src_ip}:{src_port}")
        # print(pkt.summary())

    # send an answer packet for every doorbird device we are advertising
    for doorbird in doorbirds:
        dns_part = DNS(
            id=pkt[DNS].id,  # replies copy question ids, for matching up (16bit)
            aa=1,  # authoritative
            qr=1,  # is response
            rd=pkt[DNS].rd,  # recursion desired?
            qdcount=pkt[DNS].qdcount,  # copy question count
            qd=pkt[DNS].qd,  # original question
        )
        # Emulating what doorbird devices advertise themselves as:
        fqname = f'Doorstation - {doorbird["mac"]}._axis-video._tcp.local'
        # Doesn't matter if this can't be resolved by the ios/android apps.
        # I'm sending it to emulate doorbird's usual response
        hostname = 'bha-{doorbird["mac"]}.local'

        # To emulate the exact DNS packet reply style (determined from sniffing doorbird mdns traffic)
        # we send the PTR record as the sole Answer, then in the Additional Records section we
        # send the SRV, TXT, A, AAAA records

        # add the Answer
        dns_part.an = DNSRR(
            rrname="_axis-video._tcp.local", type="PTR", rclass=1, ttl=10, rdata=fqname
        )
        # add the Additional Records
        ar_srv = DNSRRSRV(
            rrname=fqname,
            rclass=1,
            ttl=10,
            priority=0,
            weight=0,
            port=80,
            target=hostname,
        )
        ar_txt = DNSRR(
            rrname=fqname,
            type="TXT",
            rclass=1,
            ttl=10,
            rdata=f'macaddress={doorbird["mac"]}',
        )
        ar_a = DNSRR(
            rrname=hostname, type="A", rclass=1, ttl=10, rdata=doorbird["addr"]
        )
        # my doorbird devices send an AAAA record, so fine to put one in here if you need it
        # i've not bothered since i'm happy for them to use v4

        dns_part.ar = ar_srv / ar_txt / ar_a

        # We must make it look like the DNS replies are coming from the doorbird device IP
        # Ideally, doorbird apps would look at the A record to decide the
        # device IP, but they use the src IP of the packet for some reason
        #
        # this is why avahi-reflector doesn't work, since doorbird tries to connect to the IP of the reflector machine.
        reply_pkt = (
            Ether()
            / IP(dst=src_ip, src=doorbird["addr"], ttl=1)
            / UDP(sport=5353, dport=src_port)
            / dns_part.compress()
        )

        if args.verbose:
            print(f'< Sending answer to {src_ip} for "{fqname}" {doorbird["addr"]}')

        sendp(reply_pkt, verbose=0, iface=args.iface)


if __name__ == "__main__":

    if args.verbose:
        print("Doorbird devices we are answering for:")
        for db in doorbirds:
            print(f'* ip={db["addr"]} mac={db["mac"]}')

    print(f"Listening on {args.iface} for mDNS queries..")

    sniff(
        iface=args.iface,
        filter="udp and dst port 5353 and dst host 224.0.0.251",
        store=0,
        prn=handle_multicast_query_from_app,
    )
