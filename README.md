# ICMP-Construction

## Prerequisites

1. Zeek (https://docs.zeek.org/en/lts/install/install.html)

## How to run

Run Script
```bash
zeek -i <your interface> imcp.zeek ip_idBU.zeek ip_stegoBU.zeek ip_ttlBU.zeek mqtt_stego.zeek sip_stego.zeek TCP.zeek
```
## Descriptions
The idea of the project is to detect steganography.

## Simple Alerting System
In compare.sh I have wrote a simple alerting system. Which is basically comparing the MD5 hash of a file from the last time that the script was run with the present one. If the hashes are the same nothing is done. But when the the hases are different an mail is sent to the administrator and the ole hash is replaced by the new one. To run this script periodically I have used crontab.
