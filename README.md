# Doorbird between subnets or VLANs mDNS advertiser

### Problem

If your Doorbird doorbell is on a different VLAN or subnet to your iOS/Android apps,
the apps won't make a direct connection, and you get very low framerate and laggy video and audio, because it's routed via Doorbird's Cloud.


[when viewing video in app: house icon in top right = direct, cloud icon = routed via doorbird's servers]

### mDNS bridging (like avahi-reflector) should work, but doesn't

Doorbird apps uses mDNS to discover devices, learn their IPs, and direct connect to them.

mDNS doesn't leave the subnet, so you would not expect to discover devices from different subnets via mDNS.

Typically you use something like avahi-reflector, to bridge mDNS between subnets.

avahi-reflector doesn't work because the doorbird apps use the source IP on the dns answer packet as the assumed IP of the doorbird device, instead of parsing out the IP from the A record in the dns response. This is presumably a bug in the apps, doesn't seem like it would be intended behaviour.

### Solution

Respond to the mDNS queries with answers, but spoof the packet source address so it seems like the answers were sent direct from the devices.

## Usage

Rather than try and act like avahi-reflector and relay mDNS queries onto the other subnet, my solution hardcodes the IP(s) to advertise for the doorbird devices. As long as the iOS and Android (or indoor station) devices can reach the doorbird IP, it works. Your doorbell probably has a static DHCP lease anyway.

Assuming eth0 is the interface where the android/ios clients live:

```bash
pip3 install scapy  # have python3 installed on linux first..
./doorbird_mdns_responder -v -i eth0 -a aa:bb:cc:dd:12:13/10.0.1.10
```

Now restart your app, select LAN-only mode, view video stream, turn off LAN-only mode, and it should remember the IP from now on, and always get a direct connection - as long as you keep the responder running.

### Note for doorbirds with wifi + ethernet

Doorbird devices describe themselves with the wifi mac in mDNS responses, even if connected via ethernet. You can get the mac from the digital passport (the paper with the QR code on it). You should use the wifi mac with the IP, even if the IP is from a network cable. I think they use the first (wifi) mac like a serial number or something.

### iptables rules needed too

Remember you need to allow udp from doorbird to apps on ports 6524 and 35344, for the push notification events like "doorbell pressed" to work in LAN-only mode.

Example, from my `iptables-save` output on my router box, which permits the doorbird at 10.0.1.10 to send packets to my wifi subnet:

```
-A FORWARD -p udp -s 10.0.1.10 -d 10.0.0.1/24 --dport 6524 -j ACCEPT -m comment --comment "Doorbird udp fwd"
-A FORWARD -p udp -s 10.0.1.10 -d 10.0.0.1/24 --dport 35344 -j ACCEPT -m comment --comment "Doorbird udp fwd"
```

Also make sure your phone is allowed to access the doorbird IP for direct connections:

```
# Allow specific IPs access to the doorbird device
-A FORWARD -s 10.0.0.23 -d 10.0.1.10 -j ACCEPT -m comment --comment "my phone to doorbird"
```

This is specific to your network topology of course.

## Dear Doorbird..

Please would you fix this, I am happy to test it for you. A fix where you take the doorbell IP from the mDNS reply A record instead of the packet src would mean general solutions like avahi-reflector would work, and I can delete this code. Thanks!

## Questions? Was this useful?

* [twitter.com/metabrew](https://twitter.com/metabrew)
* rj@metabrew.com

