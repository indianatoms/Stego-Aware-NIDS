@load record.zeek
@load policy/tuning/json-logs.zeek

global id_changes_counter = 0;
global TCP_Urgent = F;
global old_seq_TCP = 0;

global TCP_seq : table[addr] of VTC = {};
global TCP_port: table[addr] of VTC = {};

event tcp_packet (c: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count, payload: string)
	{
	for (i in flags)
		{
	#check URG flag If it exist set it to TRUE
			if (i == "U")
				{
				print "Urgent pointer is on";
				TCP_Urgent = T;
				}
	#check for RST flag and payload
			if (i == "R" && payload != "")
				{
				print "Possible Stego, the RST flag is up and the payload is not empty.";
				NOTICE([$note=Possible_Steganography,
					$msg = "Possible RST/payload TCP steganography",
					$ts=network_time(),
					$sub = "The RST flag is set and payload is not empty.",
					$conn = c]);
				}
		}
	old_seq_TCP = seq;
	}


event new_packet (c: connection, p: pkt_hdr){
	#REserved bits check
	if(p ?$ tcp && p$tcp$reserved != 0 ){
			print "Reserved bits number is : ",p$tcp$reserved;
			print "Possible Reserved Bits Stego";
			NOTICE([$note=Possible_Steganography,
                                  $msg = "Possible reserved bits TCP steganography",
				  $ts=network_time(),
                                  $sub = "TCP reserved bits are not equal to zero",
                                  $conn = c]);
                        Weird::weird([
                        $ts=network_time(),
                        $name="Possible_Staeganography",
                        $conn=c,
                        $notice=T]); #check whats going on over here
	}
	#check Urgent pointer
	if(p ?$ tcp){
		if(p$tcp$urp != 0 && !TCP_Urgent){
			print "Possibile stego URG flag is 0 and urgent pointer exists";
		}
	}

	TCP_seq[p$ip$src]$a += 1;
	if(p ?$ ip && p ?$ tcp){
		if(p$ip$src in TCP_seq && p$ip$src != local_address)
		{
			#print "same address";
			if(p$tcp$seq > TCP_seq[p$ip$src]$v)
				{
					TCP_seq[p$ip$src]$c += 1;
					if(TCP_seq[p$ip$src]$c >= 20){
						TCP_seq[p$ip$src]$c = 0;
						TCP_seq[p$ip$src]$a = 0;
					}
				}
			else
				{
					TCP_seq[p$ip$src]$c -= 1;
					#print "DOWN!";
					if( |TCP_seq[p$ip$src]$c / TCP_seq[p$ip$src]$a| > 0.1){
						print("possible stego seq");
						NOTICE([$note=Possible_Steganography,
                		                   $msg = "Possible seq numbe TCP steganography",
        	                	           $sub = "SEQ number not increasing",
						   $ts=network_time(),
	                                	   $conn = c]);
						TCP_seq[p$ip$src]$c = 0;
						TCP_seq[p$ip$src]$a = 0;
					}
				}
			TCP_seq[p$ip$src]$v = p$tcp$seq;
		}
		else if(p$ip$src != local_address)
		{
			TCP_seq[p$ip$src] = VTC($v = p$tcp$seq, $t = network_time(), $c = 0, $a=0);
		}
	}

#		if(p$ip$src in TCP_port && p$ip$src != local_address){
#		#	print "same address";
#				if(TCP_port[p$ip$src]$v != port_to_count(p$tcp$sport))
#				{
#					print "new source port for same address";
#						if(network_time() - TCP_port[p$ip$src]$t < 1min){
#							TCP_port[p$ip$src]$c += 1;
#							print TCP_port[p$ip$src]$c;
#							if(TCP_port[p$ip$src]$c >= 10){
#									print "possible port stego";
#									print p$ip$src;
#		      					NOTICE([$note=Possible_Steganography,
#                                                    		$msg = "Possible source port TCP steganography",
#                                                   		$sub = "Source port number changing too requently",
#								$ts=network_time(),
#                                                    		$conn = c]);
#							}
#						}
#						else{
#							TCP_port[p$ip$src]$t = network_time();
#							TCP_port[p$ip$src]$c = 0;
#						}
#					TCP_port[p$ip$src]$v = port_to_count(p$tcp$sport);
#				}
#		}	
#		else if(p$ip$src != local_address){
#		#	print "new address";
#			TCP_port[p$ip$src] = VTC($v = port_to_count(p$tcp$sport), $t = network_time(), $c = 0);
#		}
	#Unset urgent pointer
	TCP_Urgent = F;
}
