#!/usr/bin/env python

import scapy.all as scapy
import optparse


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="ip", help="Ur ip address range")
    (option, arguments) = parser.parse_args()
    if not option.ip:
        parser.error("[-] Please specify an ip address, use --help for more info")

    return option


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, verbose=False, timeout=1)[0]

    print("IP\t\t\tMAC address\n------------------------------------------------------")
    client_list = []

    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        client_list.append(client_dict)

    return client_list


def print_result(result_list):
    for client in result_list:
        print(client["ip"] + "\t\t" + client["mac"])


options = get_arguments()
result_scan = scan(options.ip)
print_result(result_scan)
