import socket
import struct
import binascii
import sys
import pcapy
import ipaddress

# Watched all 8 tutorials from the new Boston https://www.youtube.com/watch?v=_HIefrog_eg and refered to bits of his code

def main(pcap_filename):
    print("Opening file: '{}'".format(pcap_filename))
    pcap_reader = pcapy.open_offline(pcap_filename)
    packet_count = 0

    while True:
        meta, raw_data = pcap_reader.next()

        # Checks to see if any more packets to process
        if len(raw_data) < 1:
            break

        packet_count += 1
        print('\n  Packet #: {}'.format(packet_count))

        # Process Frame
        dest_mac, src_mac, eth_proto, eth_data = ethernet_frame(raw_data)

        # Check for IPv4 regular internet traffic
        print (' Eth proto: {}'.format(eth_proto))

        if eth_proto == 8:
            print('Ether Type: IPv4')
            ipv4_proto, data = ipv4_packet(eth_data)

            # Check for ICMP
            if ipv4_proto == 1:
                print ('  Protocol: ICMP')
                icmp_packet(data)

            # Check for TCP
            elif ipv4_proto == 6:
                print ('  Protocol: TCP')
                tcp_segment(data)

            # Check for UDP
            elif ipv4_proto == 17:
                print ('  Protocol: UDP')
                udp_segment(data)
            print ('\n')
            print (print_raw_data(raw_data))


        # Check for IPv6
        elif eth_proto == 56710:
            print ('Ether Type: IPv6')
            next_header, ipv6 = ipv6_packet(eth_data)

            print (next_header)
            # Checks TCP
            if (next_header == 6):
                print('  Protocol: TCP')

            # Checks UDP
            elif (next_header == 17):
                print('  Protocol: UDP')

            # Checks ICMPv6
            elif (next_header == 58):
                print('  Protocol: ICMPv6')

            elif (next_header == 0):
                print('  Protocol: Exth')

            print ('\n')
            print_raw_data(raw_data)

        # Unknown
        else:
            print('Unknown protocol')



# Unpack ethernet frame
def ethernet_frame(packet):
    #allocate the first bytes
    dest_addr, source_addr, type = struct.unpack ('! 6s 6s H', packet[:14])
    return mac2str(dest_addr), mac2str(source_addr), socket.htons(type), packet[14:]



#Return formatted mac Address ie (AA:BB:CC:DD:EE..)
def mac2str(mac_bytes):
    mac_string = binascii.hexlify(mac_bytes).decode('ascii')
    mac_pairs = [i+j for i,j in zip(mac_string[0::2], mac_string[1::2])]
    return ':'.join(mac_pairs)


# Print frame data
def print_raw_data (data):
    mac_string = binascii.hexlify(data).decode('ascii')
    mac_pairs = [i + j for i, j in zip(mac_string[0::2], mac_string[1::2])]

    print ("\n".join([" ".join(mac_pairs[i:i + 16]) for i in range(0, len(mac_pairs), 16)]))


#Unpack IPv4 packet
def ipv4_packet (data):
    version_header_length = data[0]
    header_length = (version_header_length & 15) *4

    ttl, proto, src, dest = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    print ('\t  From: {}'.format(ipaddr(src)))
    print ('\t\tTo: {}'.format(ipaddr(dest)))

    return proto, data[header_length:] # Only need protocol and data


#Unpack IPv6 packet
def ipv6_packet (data):

    payload, next_header, src, dest = struct.unpack('! 4x H B 1x 16s 16s', data[:40])
    print('\t  From: {}'.format(ipaddr(src)))
    print('\t\tTo: {}'.format(ipaddr(dest)))

    return next_header, data[40:]



#Returns properly formatted IPv4 address i.e 127.0.0.1 as well as IPv6 address
def ipaddr(address):
    return ipaddress.ip_address(address)


#Unpacks ICMP packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    print ('\t Type: {}'.format(find_icmp_type(icmp_type)))
    print ('\t Code: {}'.format(code))
    print (' Checksum: {}'.format(checksum))


#Unpack TCP segment
def tcp_segment (data):
    src_port, dest_port, sequence, acknowledgement, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4  #Gets offset

    print ('  Src Port: {}'.format(src_port))
    print ('  Dst Port: {}'.format(dest_port))
    print ('   Payload: ({}) bytes'.format(len(data[offset:])))
    print (offset_reserved_flags)

    return src_port, dest_port, sequence, acknowledgement, data[offset:]


# Unpack UDP segment
def udp_segment (data):
    src_port, dest_port, length = struct.unpack('! H H 2x H', data[:8])
    print ('  Src Port: {}'.format(src_port))
    print ('  Dst Port: {}'.format(dest_port))
    print ('    Length: {}'.format(length))
    return src_port, dest_port, length, data[8:]


# Checks and returns ICMP type
def find_icmp_type (type):

    if type == 1 or 2 or 7:
        return "Unassigned"

    if 42 <= type <= 252:
        return "Unassigned"

    if 20 <= type <= 29:
        return "Reserved (for Robustness Experiment)"

        # icmp protocol type fail case
    if type > 254:
        return "Unknown"

    return dict[type]


# Dictionary of different ICMP types
dict = {

    0: "Echo Relay",
    3: "Destination Unreachable",
    4: "Source Quench (Deprecated)",
    5: "Redirect",
    6: "Alternate Host Address (Deprecated)",
    8: "Echo",
    9: "Router Advertisement",
    10: "Router Selection",
    11: "Time Exceeded",
    12: "Parameter Problem",
    13: "Timestamp",
    14: "Timestamp Reply",
    15: "Information Request(Deprecated)",
    16: "Information Reply(Deprecated)",
    17: "Address Mask Request(Deprecated)",
    18: "Address Mask Reply(Deprecated)",
    19: "Reserved(for Security)",
    30: "Traceroute (Deprecated)",
    31: "Datagram Conversion Error (Deprecated)",
    32: "Mobile Host Redirect (Deprecated)",
    33: "IPv6 Where-Are-You (Deprecated)",
    34: "IPv6 I-Am-Here (Deprecated)",
    35: "Mobile Registration Request (Deprecated)",
    36: "Mobile Registration Reply (Deprecated)",
    37: "Domain Name Request (Deprecated)",
    38: "Domain Name Reply (Deprecated)",
    39: "SKIP (Deprecated)",
    40: "Photuris",
    41: "ICMP messages utilized by experimental mobility protocols such as Seamoby",
    253: "RFC3692-style Experiment 1",
    254: "RFC3692-style Experiment 2"
}


# Main
if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Please supply pcap file argument: python3 sniffer.py packets.pcap")
        exit()

    main(sys.argv[1])