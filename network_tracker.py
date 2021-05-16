#!/usr/bin/env python

import scapy.all as scapy

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    #by scapy.ls you can check every list. and for ether
    # to choose dst mac always the mac will be ff:ff:ff:ff:ff:ff
    #you can set the mac in 2 way.
    #as ==> broadcast.dst="mac"
    #or broadcast = scapy.Ether(dst="mac")
    #scapy.ls(scapy.Ether())
    arp_request_broadcast = broadcast/arp_request
    #print(arp_request_broadcast.summary()) # to check all the summary
    #arp_request_broadcast.show() # to check the work
    #answer_list, unanswer_list = scapy.srp(arp_request_broadcast, timeout=1)
    #because this give us 2 list and we only need answer list so unanswer list doesnot have any value
    answer_list = scapy.srp(arp_request_broadcast, verbose=False, timeout=1,)[0] # [0] is for the anser list
    #print(unanser_list>summary())



    client_list = []

    for element in answer_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        client_list.append(client_dict)

    return(client_list)


def print_result(results_list):
    print("IP\t\t\tMac address\n---------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])



scan_result = scan("10.0.2.2/24")
print_result(scan_result)