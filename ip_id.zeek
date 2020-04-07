global Id_ip : table[addr] of count = {};
global IP_ID_counter : table[addr] of int = {};
global IP_ID_timer : table[addr] of time = {}; 

event new_packet (c: connection, p: pkt_hdr){
	if(p ?$ ip){
		if(p$ip$src in Id_ip){
			print  p$ip$id, p$ip$src, Id_ip[p$ip$src];
			if(p$ip$id < Id_ip[p$ip$src]){
				#print "The value went down by" ,|p$ip$id - Id_ip[p$ip$src]|;
				#print "DOWN!" , p$ip$src, "counter",IP_ID_counter[p$ip$src];
				Id_ip[p$ip$src] = p$ip$id;
				if (p$ip$src in IP_ID_timer){
					if(network_time() - IP_ID_timer[p$ip$src]  < 1min){
					 IP_ID_counter[p$ip$src] += 1;
					 	if(IP_ID_counter[p$ip$src] > 10){
							print IP_ID_timer[p$ip$src] - network_time();
							print "possible IP Id stego", p$ip$src;
						 }

					}else{
					IP_ID_counter[p$ip$src] = 0;
					IP_ID_timer[p$ip$src] = network_time();
					print "entered!";
					}
				}
				else{
					IP_ID_timer[p$ip$src] = network_time();
					IP_ID_counter[p$ip$src] += 1;

				}
			}else{
				Id_ip[p$ip$src] = p$ip$id;
			}
		}else if (p$ip$src != 192.168.1.26){
		#	print "New adders store id";
			Id_ip[p$ip$src] = p$ip$id;
			IP_ID_counter[p$ip$src] = 0;
		}
	}
}
