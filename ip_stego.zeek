@load vtcs.zeek
global t_TOS: table[ID] of VTC = {};
#global id : ID;

event new_packet (c: connection, p: pkt_hdr){

	if(p ?$ ip){
		id = ID($src = p$ip$src, $dst = p$ip$dst);
		if(id in t_TOS){
			t_TOS[id]$a +=1;
			print "a", t_TOS[id]$a;
			print "c", t_TOS[id]$c;
			if (t_TOS[id]$v != p$ip$tos){
				if(network_time() - t_TOS[id]$t < 1min){
					t_TOS[id]$c +=1;
					print "dup";
					print t_TOS[id]$a / t_TOS[id]$c;
					if(|t_TOS[id]$a / t_TOS[id]$c | < 20 && t_TOS[id]$a > 20)
                        {
                                                     print "possible stego or someone is using VoIP too much :-)", t_TOS[id]$c;
                                                     NOTICE([$note=Possible_Steganography,
							    $conn = c,
		                                            		$id = c$id,
                                                            $msg = "Possible  Steganography",
                                                            $sub = "IP DSCP/ESN numbers are changing too often",
                                                            $ts = network_time()]);
															t_TOS[id]$t = network_time();
															t_TOS[id]$c = 0;
															t_TOS[id]$a = 100;
						 }
				}
				else
				{
					t_TOS[id]$t = network_time();
					t_TOS[id]$c = 0;
					t_TOS[id]$a = 100;
				}
			}
		}
		else{
			t_TOS[id] = VTC($v = p$ip$tos, $t = network_time(), $c = 0, $a=100);
		}
	}
}

