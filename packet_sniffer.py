import socket
import struct
import textwrap


def main(pcap_filename):
    print("Opening file: '{}'".format(pcap_filename))
    pcap_reader = pcapy.open_offline(pcap_filename)

    count = 0

    while True:
        meta, data = pcap_reader.next()
        dest_mac, src_mac, eth_proto, data = ethernet_frame(data)

        print ('\nEthernet Frame')
        print ('Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))


# Unpack ethernet frame
def ethernet_frame(packet):
    #allocate the first bytes
    dest_addr, source_addr, type = struct.unpack('! s6 s6 H', packet[:14])
    return mac2str(dest_addr), mac2str(source_addr), socket.htons(type), packet[14:]

#Return formatted mac Address ie (AA:BB:CC:DD:EE..)
def mac2str(mac_bytes):
    mac_string = binascii.hexlify(mac_bytes).decode('ascii')
    mac_pairs = [i+j for i,j in zip(mac_string[0::2], mac_string[1::2])]
    return ':'.join(mac_pairs)

#Unpack IPv4 packet
def ipv4_packet (data):
    v_header_length = data[0]
    version = v_header_length >> 4  #bitshift to the right
    header_length = (v_header_length & 15) *4   #gets entire header legth to find where the data starts
    ttl, proto, src, dest = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(dest), data[header_length:]

#Returns properly formatted IPv4 address i.e 127.0.0.1
def ipv4(address):
    return '.'.join(map(str, address))

#Unpacks ICMP packet
def icmp_packet(data):
    imcp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return imcp_type, code, checksum, data[4:] #Returns header and payload

#Unpack TCP segment
def tcp_segment (data):
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4  #Gets offset
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1

    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

main()



