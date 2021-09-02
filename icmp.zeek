@load policy/tuning/json-logs.zeek
@load iat.zeek

type ID: record {
        src: addr;
        dst: addr;
};


global IAT_tab : table[addr] of IAT = {};
global ICMP_ID : table[ID] of count = {};
global id_seq : table[count] of count = {};
global t : time;
global id1 : ID;
global counter : int;


redef Weird::actions: table[string] of Weird::Action += {
	["Possible_Steganography"] = Weird::ACTION_NOTICE,
};
redef enum Notice::Type += { Possible_Steganography1 };

event zeek_init() {
	t = current_time();
	counter = 0;
}

event icmp_echo_request(c: connection , info: icmp_info , id: count , seq: count , payload: string )
{
	counter = counter + 1;
	print "===============";
	print counter;
	# print IAT_tab;
	cheek_intervals(IAT_tab,c$id$orig_h,c,t);
	id1 = ID($src = c$id$orig_h, $dst = c$id$resp_h);
	# print id1 ;
	if (id1 in ICMP_ID)
	{
		if(ICMP_ID[id1] != id){
			# print ICMP_ID[id1], id;
			if(ICMP_ID[id1]+1 < id){
				print "possible stego!";
      			 	 NOTICE([$note=Possible_Steganography1,
                                   	$msg = "Possible ICMP ID Steganography",
                                   	$sub = "ID number is changing of ICMP is not appearing in order",
                                   	$conn = c]);
                         	Weird::weird([
                         	$ts=network_time(),
                         	$name="Possible_Staeganography ID",
                         	$conn=c,
                         	$notice=T]);
				ICMP_ID[id1] = id;
			}
			else{
				ICMP_ID[id1] = id;
			}
		}
	}
	else{
		ICMP_ID[id1] = id;
	}
	
	if (id in id_seq){
		print id_seq[id] , seq;
		if ( seq == 0 || id_seq[id]+1 == seq || id_seq[id] == seq){
			id_seq[id] = seq;
		}
		else{
			print "Possible seq stego";
			NOTICE([$note=Possible_Steganography,
			 	    $conn = c,
			 	    $id = c$id,
                                     $msg = "Possible ICMP SEQ  Steganography",
                                     $sub = "Sequence number of ICMP is not appearing in order",
			 	    $ts = network_time()]);
                        Weird::weird([
                        $ts=network_time(),
                        $name="Possible_Staeganography SEQ",
                        $conn=c,
                        $notice=T]);
			id_seq[id] = seq;
		}
	}
	else{	
		id_seq[id] = seq;
	}
        
}
