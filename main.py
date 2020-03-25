from time import sleep

from scapy.all import *
from scapy.layers.inet import ICMP, IP, TCP, sr1
import random

def cmd_ping(ip, count, timeout, wait, verbose):
    conf.verb = False

    layer3 = IP()
    layer3.src = "192.168.1.107"
    layer3.dst = ip
    layer3.tos = 0
    layer3.id = 1
    layer3.flags = 0
    layer3.frag = 0
    layer3.ttl = 128
    layer3.proto = 1  # icmp

    layer4 = ICMP()
    layer4.type = 8  # echo-request
    layer4.code = 0
    layer4.id = 1
    layer4.seq = 31

    pkt = layer3 / layer4 / b"abcdefghijklmn opqrstuvwabcdefg hi"

    print(layer4)
    counter = 0

    while True:

        ans = sr1(pkt, timeout=timeout)
        print("1")
        if ans:
            if verbose:
                ans.show()
            else:
                print(ans.summary())
            del ans
        else:
            print('Timeout')

        counter += 1

        if counter == 1:
            layer4.id = 115
        if counter == 2:
            layer4.id = 31
        if counter == 3:
            layer4.id = 69
        layer4.seq += 1
        pkt = layer3 / layer4 / b"abcdefghijklmnopqrstuvwabcdefghi"
        print("5")

        if count != 0 and counter == count:
            break
        sleep(wait)
    return True

def cmd_tcpip(ip):
    layer3 = IP()
    layer3.src = "192.168.1.107"
    layer3.dst = ip
    layer3.ttl = 255
    layer3.ihl = 5

    layer4 = TCP()
    layer4.dport = 80
    layer4.sport = 20
    layer4.reserved = 0b0111
#    layer4.flags = "S"
    layer4.dataofs = 5
    layer4.flags = 'S'

    print("1")
    pkt = layer3 / layer4
    send(pkt)


cmd_tcpip("192.168.1.104")
#cmd_ping("192.168.1.104", 4, 128, 1, 0)