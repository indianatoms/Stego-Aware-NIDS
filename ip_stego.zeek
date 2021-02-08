@load record.zeek
global t_TOS: table[addr] of VTC = {};
global packet_counter = 0;

event new_packet (c: connection, p: pkt_hdr){
	t_TOS[p$ip$src]$a +=1;
	if(p ?$ ip){
		if(p$ip$src in t_TOS){
			if (t_TOS[p$ip$src]$v != p$ip$tos){
				if(network_time() - t_TOS[p$ip$src]$t < 1min){
					t_TOS[p$ip$src]$c +=1;
					if(|t_TOS[p$ip$src]$c / t_TOS[p$ip$src]$a | > 0.1)
                                                 {
                                                     print "possible stego or someone is using VoIP too much :-)", t_TOS[p$ip$src]$c;
                                                     NOTICE([$note=Possible_Steganography,
							    $conn = c,
		                                            $id = c$id,
                                                            $msg = "Possible  Steganography",
                                                            $sub = "IP DSCP/ESN numbers are changing too often",
                                                            $ts = network_time()]);
						 }
				}
				else
				{
					t_TOS[p$ip$src]$t = network_time();
					t_TOS[p$ip$src]$c = 0;
					t_TOS[p$ip$src]$a = 0;
					packet_counter = 0;
				}
			}
		}
		else{
			t_TOS[p$ip$src] = VTC($v = p$ip$tos, $t = network_time(), $c = 0);
		}
	}
}

