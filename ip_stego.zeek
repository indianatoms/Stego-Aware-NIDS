 global TOS: table[addr] of count = {};
 global TOS_counter : table[addr] of time = {};

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
		if( p$ip$src in TOS ){
			if(TOS[p$ip$src] == p$ip$tos)
				{
				print "same tos for same address";
				}
			else{
				print "tos has changed!";
				if( p$ip$src in TOS_counter)
				{
					print "check if second change of value occured in the last ten minuts";
					if(TOS_counter[p$ip$src] - network_time() < 10min){
						print "Possible IP - TOS stego occured";
					}
				}
				else{
					print "First change, check if new change occured in 10 minutes.";
					TOS_counter[p$ip$src] = network_time();
				}
			}	
		}
		else{
			print "New address - Store TOS"; 
			TOS[p$ip$src] = p$ip$tos;
		}
	}
}
