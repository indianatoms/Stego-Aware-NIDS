@load record.zeek

global t_TTL : table[addr] of VTC = {};
global packet_counter = 0;

event new_packet (c:connection, p: pkt_hdr){
        t_TTL[p$ip$src]$a += 1;
        if(p ?$ ip){
                if(p$ip$src in t_TTL){
                           if(t_TTL[p$ip$src]$v != p$ip$ttl){
                                        if(|t_TTL[p$ip$src]$v - p$ip$ttl| > 10){
                                                        if(network_time() - t_TTL[p$ip$src]$t < 1min){
                                                          t_TTL[p$ip$src]$c += 1;
							  print "One up for", p$ip$src;
                                                          #check if the spoofed packets are exceding 10% of the network flow.
                                                          if (|t_TTL[p$ip$src]$c / t_TTL[p$ip$src]$a| > 0.1){
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
                                                        #Reset the counters
                                                          t_TTL[p$ip$src]$c = 0;
                                                          t_TTL[p$ip$src]$a = 0;
                                                          t_TTL[p$ip$src]$t = network_time();
                                                        }
                                                
                                        }
                                        t_TTL[p$ip$src]$v = p$ip$ttl;
                                }
                }
                else if (p$ip$src != local_address){
               		t_TTL[p$ip$src] = VTC($v = p$ip$ttl, $t = network_time(), $c = 0, $a = 0);
                	print "Store first ttl number for", p$ip$src;
                }
        }
}


