global old_seq = 0;
global old_id : count = 0;
global id_changes_counter = 0;

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

        if (old_seq != seq-1 && old_seq != 0 && old_id == id){
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
