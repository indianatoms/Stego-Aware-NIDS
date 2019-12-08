from time import sleep

from scapy.all import *
from scapy.layers.inet import ICMP, IP, sr1


def cmd_ping(ip, count, timeout, wait, verbose):
    conf.verb = False

    layer3 = IP()
    layer3.src = "192.168.0.234"
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
        layer4.seq += 1
        pkt = layer3 / layer4 / b"abcdefghijklmnopqrstuvwabcdefghi"
        print("5")

        if count != 0 and counter == count:
            break
        sleep(wait)
    return True


cmd_ping("192.168.0.206", 4, 128, 1, 0)
