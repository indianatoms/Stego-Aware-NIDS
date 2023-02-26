# ICMP-Construction

## Prerequisites

1. Zeek (https://docs.zeek.org/en/lts/install/install.html)

## How to run

Run the scripts one at a time

```bash
zeek -i <your interface> icmp.zeek
zeek -i <your interface> ip_id.zeek
zeek -i <your interface> ip_stego.zeek
zeek -i <your interface> ip_ttl.zeek
zeek -i <your interface> mqtt_stego.zeek
zeek -i <your interface> sip_stego.zeek
zeek -i <your interface> TCP.zeek
```

Run the scripts together

```bash
zeek -i <your interface> icmp.zeek ip_id.zeek ip_stego.zeek ip_ttl.zeek mqtt_stego.zeek sip_stego.zeek TCP.zeek
```

## Descriptions

The idea of the project is to detect steganography.

## Simple Alerting System

In compare.sh I have wrote a simple alerting system. Which is basically comparing the MD5 hash of a file from the last time that the script was run with the present one. If the hashes are the same nothing is done. But when the the hases are different an mail is sent to the administrator and the ole hash is replaced by the new one. To run this script periodically I have used crontab.

***
**If you use this tool in your research, please cite: Koziak, T., Wasielewska, K., & Janicki, A. (2021, November). How to Make an Intrusion Detection System Aware of Steganographic Transmission. In European Interdisciplinary Cybersecurity Conference (pp. 77-82), https://doi.org/10.1145/3487405.3487421.**
***
This work has been supported by the SIMARGL Project – Secure Intelligent Methods for Advanced RecoGnition of malware and stegomalware, with the support of the European Commission and the Horizon 2020 Program, under Grant Agreement No. 833042.
