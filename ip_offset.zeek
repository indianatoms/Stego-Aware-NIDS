event new_packet (c: connection, p: pkt_hdr){
           if(p ?$ ip){
			print p$ip;
			}
}
