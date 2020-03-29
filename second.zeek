global old_seq = 0;
global old_id : count = 0;
global id_changes_counter = 0;
global TCP_Urgent = F;

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
	print flags;
	for (i in flags)
		{
			if (i == "U")
				{
				print "Urgent pointer is on";
				TCP_Urgent = T;
				break;
				}
		}
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
	#	print p$tcp;
		if(p$tcp$urp != 0 && !TCP_Urgent){
			print "Possibile stego URG flag is 0 and urgent pointer exists";
		}
	}
	TCP_Urgent = F;
}
