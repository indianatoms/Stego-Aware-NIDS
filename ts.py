import dpkt
import time
from time import sleep


filename = 'final1.pcap'
filenameToWrite = 'final2.pcap'


f = open(filename, 'rb')  # encoding='utf-16')
f2 = open(filenameToWrite,'wb')

pcap = dpkt.pcap.Reader(f)
pcap_writer = dpkt.pcap.Writer(f2)
counter = 0
epoch_time = time.time()


for ts, buf in pcap:
    counter = counter + 1
    print (counter)
    print(ts)
    epoch_time = epoch_time + 0.0017
    ts = epoch_time
    print(ts)
    pcap_writer.writepkt(buf,ts)
