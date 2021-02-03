@load policy/tuning/json-logs.zeek
@load iat.zeek

global IAT_tab : table[addr] of IAT = {};
global ICMP_ID : table[addr] of count = {};
global id_seq : table[count] of count = {};
global t : time;

#Add new notice type
redef Weird::actions: table[string] of Weird::Action += {
	["Possible_Steganography"] = Weird::ACTION_NOTICE,
};

event zeek_init() {
	t = current_time()
}

event icmp_echo_request(c: connection, icmp: icmp_conn, id: count, seq: count, payload: string)
{
	cheek_intervals(IAT_tab,c$id$orig_h,c,t);
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
                         	$name="Possible_Staeganography ID",
                         	$conn=c,
                         	$notice=T]);
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
		if ( seq == 0 || id_seq[id]+1 == seq){
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
