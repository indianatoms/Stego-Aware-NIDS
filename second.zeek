global old_seq = 0;
global old_id : count = 0;
global id_changes_counter = 0;
global TCP_Urgent = F;
global old_seq_TCP = 0;
global t: table[addr] of count = {};
global TCP_seq : table[addr] of count = {};
global port_count: table[addr] of count = {};
global addres_port: table[addr] of port = {};


#Add new notice type
redef enum Notice::Type += { Possible_Steganography };
redef Weird::actions: table[string] of Weird::Action += {
	["Possible_Steganography"] = Weird::ACTION_NOTICE,
event tcp_packet (c: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count, payload: string)
	{
	for (i in flags)
		{
			if (i == "U")
				{
				print "Urgent pointer is on";
				TCP_Urgent = T;
				}
			if (i == "R" && payload != "")
				{
				print "Possible Stego, the RST flag is up and the payload is not empty.";
				}
		}
	old_seq_TCP = seq;
	}


event new_packet (c: connection, p: pkt_hdr){
	if(p ?$ tcp && p$tcp$reserved != 0 ){
			print "Reserved bits number is : ",p$tcp$reserved;
			print "Possible Reserved Bits Stego";
			NOTICE([$note=Possible_Steganography,
                                  $msg = "Possible reserved bits TCP steganography",
                                  $sub = "TCP reserved bits are not equal to zero",
                                  $conn = c]);
                        Weird::weird([
                        $ts=network_time(),
                        $name="Possible_Staeganography",
                        $conn=c,
                        $notice=T]); #check whats going on over here
	}
	if(p ?$ tcp){
		if(p$tcp$urp != 0 && !TCP_Urgent){
			print "Possibile stego URG flag is 0 and urgent pointer exists";
		}
	}

	if(p ?$ tcp){
		print p$tcp;
		print p$ip$src;
		if(p$ip$src in t && p$tcp$seq != 0 && p$ip$src != 192.168.1.104)
		{
			print "same address";
			if(p$tcp$seq > TCP_seq[p$ip$src])
				{
					t[p$ip$src] += 1;
					print "UP!";
				}
			else
				{
					t[p$ip$src] -= 1;
					print "DOWN!";
					if(t[p$ip$src] == -5 || t[p$ip$src] == -10){
						print("possible stego");
						NOTICE([$note=Possible_Steganography,
                		                   $msg = "Possible reserved bits TCP steganography",
        	                	           $sub = "SEQ number not increasing",
	                                	   $conn = c]);

					}
				}
			TCP_seq[p$ip$src] = p$tcp$seq;
		}
		else if(p$ip$src != 192.168.1.104)
		{
			print "new address";
			t[p$ip$src] = 1;
			TCP_seq[p$ip$src] = p$tcp$seq;
		}

		if(p$ip$src in addres_port){
			print "same address";
				if(addres_port[p$ip$src] != p$tcp$sport)
				{
					print "new source port for same address";
					port_count[p$ip$src] += 1;
					if(port_count[p$ip$src] >= 10){
						print "possible port stego";
					}
				}
		}	
		else{
			print "new address";
			addres_port[p$ip$src] = p$tcp$sport;
			port_count[p$ip$src] = 1;
		}
			



	}

	TCP_Urgent = F;
}
