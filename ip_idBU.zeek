@load record.zeek

global t_IP : table[addr] of VTC = {};

event new_packet (c: connection, p: pkt_hdr){
        if(p ?$ ip){
                if(p$ip$src in t_IP){
                        print  p$ip$id, p$ip$src, t_IP[p$ip$src]$v;
                        if(p$ip$id < t_IP[p$ip$src]$v){
                                #print "The value went down by" ,|p$ip$id - t_IP[p$ip$src]$v|;
                                #print "DOWN!" , p$ip$src, "counter", t_IP[p$ip$src]$c;
                                t_IP[p$ip$src]$v = p$ip$id;
                                if(network_time() - t_IP[p$ip$src]$t  < 1min){
                                  t_IP[p$ip$src]$c += 1;
                                  if(t_IP[p$ip$src]$c > 5){
                                      print "possible IP Id stego", p$ip$src;
                                  }
                                }
				else{
                                  t_IP[p$ip$src]$c = 0;
                                  t_IP[p$ip$src]$t = network_time();
                                  print "entered!";
                                }
                        }
                        else{
                                t_IP[p$ip$src]$v = p$ip$id;
                        }
                }else if (p$ip$src != 192.168.1.26){
                #       print "New adders store id";
			t_IP[p$ip$src] = VTC($v = p$ip$id, $t = network_time(), $c = 0);
                }
        }
}



