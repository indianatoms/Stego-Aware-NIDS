global old_seq = 0;
global old_id : count = 0;
global id_changes_counter = 0;
global TCP_Urgent = F;
global old_seq_TCP = 0;
global t: table[addr] of count = {};
global TCP_seq : table[addr] of count = {};

#Add new notice type
redef enum Notice::Type += { Possible_Steganography };
redef Weird::actions: table[string] of Weird::Action += {
	["Possible_Steganography"] = Weird::ACTION_NOTICE,
};

#github test
event zeek_init()

        {

        print "Hello, World!";

        }


event zeek_done()

        {

        print "Goodbye, World!";
#	print TCP_seq_counter;
        }


event icmp_echo_request(c: connection, icmp: icmp_conn, id: count, seq: count, payload: string)

        {
	
        print "Current seq number is : ",seq;
	print "Current id nuber is : ",id;

	if (old_id != id)
	{
		++id_changes_counter;
		if (id_changes_counter == 2){
#temporary solution for the sake of example -- remeber to improve.
			print "Possible id number stego";
			NOTICE([$note=Possible_Steganography,
    	 			$msg = "Possible ID number Steganography",
        			$sub = "Id number of ICMP is not appearing in order",
				$conn = c]);
			Weird::weird([
			$ts=network_time(),
			$name="Possible_Staeganography",
			$conn=c,
			$notice=T]); #check whats going on over here
		}
	}
	else
	{
		id_changes_counter = 0;
	}

        if (old_seq != seq-1 && old_seq != 0){
                	print "possible sequence number stego";
			NOTICE([$note=Possible_Steganography,
    	 			$msg = "Possible Sequence Steganography",
        			$sub = "Sequence number of ICMP is not appearing in order",
				$conn = c]);
			Weird::weird([
			$ts=network_time(),
			$name="Possible_Staeganography",
			$conn=c,
			$notice=T]); #check whats going on over here
    		}
        
        old_seq = seq;
	old_id = id;
	}

event tcp_packet (c: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count, payload: string)
	{
#	print "----------------------------";
#	print seq;
#	if(old_seq_TCP < seq){
#		TCP_seq_counter += 1;
#		if(TCP_seq_counter == 30)
#		{
#			TCP_seq_counter = 0;
#		}
#		print "UP!";
#	}
#	else{
#		TCP_seq_counter -= 1;
#		print "DOWN!";
#		if(TCP_seq_counter <= -10)
#		{
#			print ("Possbile Steganography");
#		}
#	}
	
#	print payload;
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
		print p$tcp$seq;
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
	}

	TCP_Urgent = F;
}
