 global TOS: table[addr] of count = {};
 global TOS_timer : table[addr] of time = {};
 global TOS_counter : table[addr] of count = {};
 

 event zeek_init()
            {
            	 print "Hello, World!";
            }
  
  
  event zeek_done()
            { 
         	 print "Goodbye, World!";
            }
event new_packet (c: connection, p: pkt_hdr){
	if(p ?$ ip){
		if( p$ip$src in TOS){
			if(TOS[p$ip$src] != p$ip$tos){
				print "tos has changed!";
				if (p$ip$src in TOS_counter){
					if( p$ip$src in TOS_counter)
                                            {
                                             print "check if second change of value occured in last minute";
                                             if(TOS_timer[p$ip$src] - network_time() < 1min){
                                                 TOS_counter[p$ip$src] += 1;
                                                 if(TOS_counter[p$ip$src] > 20)
                                                 {
                                                     print "possible stego or someone is using VoIP too much :-)", TOS_counter[p$ip$src];
                                                 }               
                                              }               
                                              else{
						 print "change after one minute";
                                                 TOS_timer[p$ip$src] = network_time();
                                                 TOS_counter[p$ip$src] = 1;      
                                              }
					    }
					}
				         else{   
                                    		print "First change, check if new change will occuer soon....";
                                    		TOS_timer[p$ip$src] = network_time();
                                    		TOS_counter[p$ip$src] = 1;
                                	}
			}
		}	
		else
		{
		TOS[p$ip$src] = p$ip$tos;
		print "new ip address - store tos: ",  p$ip$src;
		}
	}
}

