@load record.zeek

global t_TTL : table[addr] of VTC = {};

event new_packet (c:connection, p: pkt_hdr){
        if(p ?$ ip){
                if(p$ip$src in t_TTL){
                           if(t_TTL[p$ip$src]$v != p$ip$ttl){
                                        if(|t_TTL[p$ip$src]$v - p$ip$ttl| > 10){
                                                        if(network_time() - t_TTL[p$ip$src]$t < 1min){
                                                          t_TTL[p$ip$src]$c += 1;
							  print "One up for", p$ip$src;
                                                          if (t_TTL[p$ip$src]$c > 5){
                                                                        print "possbile stego for the ip" , t_TTL[p$ip$src]$c;
									NOTICE([$note=Possible_Steganography,
                                                                                $conn = c,
                                                                        	$id = c$id,
                                                                        	$msg = "Possible Steganography",
                                                                        	$sub = "The IP TTL field value is changing too often",
                                     						$ts = network_time()]);

                                                                }
                                                        }
                                                        else{
                                                          t_TTL[p$ip$src]$c = 1;
                                                          t_TTL[p$ip$src]$t = network_time();
                                                        }
                                                
                                        }
                                        t_TTL[p$ip$src]$v = p$ip$ttl;
                                }
                }
                else if (p$ip$src != local_address){
               		t_TTL[p$ip$src] = VTC($v = p$ip$ttl, $t = network_time(), $c = 0);
                	print "Store first ttl number for", p$ip$src;
                }
        }
}


