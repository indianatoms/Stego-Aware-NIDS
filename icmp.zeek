global old_seq = 0;
global old_id : count = 0;
global ICMP_ID : table[addr] of count = {};
global id_seq : table[count] of count = {};

#Add new notice type
redef enum Notice::Type += { Possible_Steganography };
redef Weird::actions: table[string] of Weird::Action += {
	["Possible_Steganography"] = Weird::ACTION_NOTICE,
};


event icmp_echo_request(c: connection, icmp: icmp_conn, id: count, seq: count, payload: string)

        {
	
        print "Current seq number is : ",seq;
	print "Current id nuber is : ",id;
	print c$id$orig_h;
	if (c$id$orig_h in ICMP_ID)
	{
		if(ICMP_ID[c$id$orig_h] != id){
			if(ICMP_ID[c$id$orig_h]+1 < id){
				print "possible stego!";
      			 	NOTICE([$note=Possible_Steganography,
                                  	$msg = "Possible ICMP ID Steganography",
                                  	$sub = "ID number is changing of ICMP is not appearing in order",
                                  	$conn = c]);
                         	Weird::weird([
                         	$ts=network_time(),
                         	$name="Possible_Staeganography",
                         	$conn=c,
                         	$notice=T]); #check whats going on over here
			}
			else{
				ICMP_ID[c$id$orig_h] = id;
			}
		}
	}
	else{
		ICMP_ID[c$id$orig_h] = id;
	}
	
	if (id in id_seq){
		if (id_seq[id]+1 == seq){
			id_seq[id] = seq;
		}
		else{
			print "Possible seq stego";
			NOTICE([$note=Possible_Steganography,
                                    $msg = "Possible ICMP ID Steganography",
                                    $sub = "Sequence number of ICMP is not appearing in order",
                                    $conn = c]);
                        Weird::weird([
                        $ts=network_time(),
                        $name="Possible_Staeganography",
                        $conn=c,
                        $notice=T]); #check whats going on over here

		}
	}
	else{	
		id_seq[id] = seq;
	}
        
}
