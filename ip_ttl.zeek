global TTL : table[addr] of count = {};
global TTL_timer : table[addr] of time = {};
global TTL_counter : table[addr] of count = {};

event new_packet (c:connection, p: pkt_hdr){
	if(p ?$ ip){
		if(p$ip$src in TTL){
			   if(TTL[p$ip$src] != p$ip$ttl){
					if(|TTL[p$ip$src] - p$ip$ttl| > 10){
						if (p$ip$src in TTL_counter){
							if(network_time() - TTL_timer[p$ip$src] < 1min){
							  TTL_counter[p$ip$src] += 1;
							  if (TTL_counter[p$ip$src] > 10){
									print "possbile stego for the ip" , p$ip$src;
								}
							}
							else{
							  TTL_counter[p$ip$src] = 1;
                                                          TTL_timer[p$ip$src] = network_time();
							}
						}
						else{
							TTL_counter[p$ip$src] = 1;
							TTL_timer[p$ip$src] = network_time();
						}
					}
					TTL[p$ip$src] = p$ip$ttl;
				}
		}
		else {
	   	TTL[p$ip$src] = p$ip$ttl;
	   	print "Store first ttl number for", p$ip$src;
		}
	}
}
