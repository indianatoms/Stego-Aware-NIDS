@load vtcs.zeek

#global id : ID;
global t_TTL : table[ID] of VTC = {};

event new_packet (c:connection, p: pkt_hdr){

        if(p ?$ ip){
                id = ID($src = p$ip$src, $dst = p$ip$dst);
                if(id in t_TTL){
                           t_TTL[id]$a += 1;
                           if(t_TTL[id]$v != p$ip$ttl){
                                        if(|t_TTL[id]$v - p$ip$ttl| > 100){
                                                        if(network_time() - t_TTL[id]$t < 1min){
                                                          t_TTL[id]$c += 1;
							  print "One up for", p$ip$src;
                                                          print t_TTL[id]$c, t_TTL[id]$a; 
                                                          print |t_TTL[id]$a  /t_TTL[id]$c |;
                                                          #check if the spoofed packets are exceding 10% of the network flow.
                                                          if (|t_TTL[id]$a / t_TTL[id]$c| < 10){
                                                                        print "possbile stego for the ip" , t_TTL[id]$c;
									NOTICE([$note=Possible_Steganography,
                                                                                $conn = c,
                                                                        	$id = c$id,
                                                                        	$msg = "Possible Steganography",
                                                                        	$sub = "The IP TTL field value is changing too often",
                                     						$ts = network_time()]);
                                                                        t_TTL[id]$c = 0;
                                                                        t_TTL[id]$a = 100;
                                                                        t_TTL[id]$t = network_time();

                                                                }
                                                        }
                                                        else{
                                                        #Reset the counters
                                                          t_TTL[id]$c = 0;
                                                          t_TTL[id]$a = 100;
                                                          t_TTL[id]$t = network_time();
                                                        }
                                                
                                        }
                                        t_TTL[id]$v = p$ip$ttl;
                                }
                }
                else if (p$ip$src != local_address){
               		t_TTL[id] = VTC($v = p$ip$ttl, $t = network_time(), $c = 0, $a = 100);
                	print "Store first ttl number for", p$ip$src;
                }
        }
}


