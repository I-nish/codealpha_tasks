import struct
import socket
import textwrap

#Main function
def main():
    s = socket.socket(socket.AF_PACKET,socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data, addr = s.recvfrom(65536)
        des_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print("\nEthernet Frame")
        print("\t Destination: {}, Source: {}, Protocol: {}".format(des_mac,src_mac,eth_proto))

        #For IPv4 address
        if eth_proto == 8:
            version, header_length, ttl, proto, src, target, data = ipv4_packet(data)
            print("\t IPv4 Packet:")
            print("\t\t Version: {}, Header Length: {}, TTL: {}".format(version, header_length, ttl))
            print("\t\t Protocol: {}, Source: {}, Destination: {}".format(proto, src, target))

            #Checking for each protocol
            #For ICMP
            if proto == 1:
                icmp_type, code, checksum, data = icmp_package(data)
                print("\t ICMP Packet: ")
                print("\t\t Type: {}, Code: {}, Checksum: {},".format(icmp_type, code, checksum))
                print("\t\t Data: ")
                print(format_multi_line('\t\t\t',data))

            #For TCP
            elif proto == 6:
                src_port, dst_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn,flag_fin, data = tcp_segment(data)
                print("\t TCP Packet: ")
                print("\t\t Source Port: {}, Destination Port: {}".format(src_port, dst_port))
                print("\t\t Sequence: {}, Acknowledgement: {}".format(sequence, acknowledgement))
                print("\t\t Flags: ")
                print("\t\t\t URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}".format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn,flag_fin))
                print("\t\t Data: ")
                print(format_multi_line("\t\t\t",data))
            
            #For UDP
            elif proto == 17:
                src_port, dest_port, size, data = udp_segment(data)
                print("\t UDP Packet: ")
                print("\t\t Source Port: {}, Destination Port: {}, Length: {}".format(src_port, dest_port, size))
                print("\t\t Data: ")
                print(format_multi_line("\t\t\t",data))

            #Other IPv4
            else:
                print("\t Data: ")
                print(format_multi_line("\t\t",data))
        
        else:
            print("Data: ")
            print(format_multi_line("\t",data))


#Unwrapping ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H',data[:14])
    return get_mac(dest_mac), get_mac(src_mac), socket.htons(proto), data[14:]

#Formatting Mac address
def get_mac(bytes_adr):
    byte_str = map('{:02x}'.format,bytes_adr)
    return ':'.join(byte_str).upper()

#Unwrapping IPv4 packet
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

#Formatting IPv4 addresses
def ipv4(addr):
    return '.'.join(map(str, addr))

#Unwrapping ICMP packages
def icmp_package(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

#Unwrapping TCP segment
def tcp_segment(data):
    (src_port, dst_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H',data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dst_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn,flag_fin, data[offset:]

#Unwrapping UDP Segment
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

#Formatting multi-line data in output
def format_multi_line(prefix, string, size = 80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -=1
    return '\n'.join([prefix + line for line in textwrap.wrap(string,size)])


main()
