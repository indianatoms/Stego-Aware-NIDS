global Id_ip : table[addr] of count = {};
global IP_ID_counter : table[addr] of int = {};

event new_packet (c: connection, p: pkt_hdr){
	if(p ?$ ip){
		if(p$ip$src in Id_ip){
			#print  p$ip$id, p$ip$src;
			if(p$ip$id > Id_ip[p$ip$src])
			{
			#	print "UP!" , p$ip$src;
				Id_ip[p$ip$src] = p$ip$id;
				IP_ID_counter[p$ip$src] += 1;
				if(IP_ID_counter[p$ip$src] > 10){ 
					  IP_ID_counter[p$ip$src] = 0;
					  }
				}
			else if(p$ip$id < Id_ip[p$ip$src]){
				print "DOWN!" , p$ip$src, "counter",IP_ID_counter[p$ip$src];
				Id_ip[p$ip$src] = p$ip$id;
				IP_ID_counter[p$ip$src] -= 1;
				if(IP_ID_counter[p$ip$src] > 10){
                                        IP_ID_counter[p$ip$src] = 0;
					print "possible steganography",p$ip$src;
                                }
			}
		}else{
		#	print "New adders store id";
			Id_ip[p$ip$src] = p$ip$id;
			IP_ID_counter[p$ip$src] = 0;
		}
	}
}
