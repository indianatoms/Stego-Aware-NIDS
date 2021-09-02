@load vtcs.zeek

#global id : ID;
global t_IP : table[ID] of VTC = {};
#local local_address : addr = 192.168.0.235;
# global counter : int;


# event zeek_init() {
# 	counter = 0;
# }


event new_packet (c: connection, p: pkt_hdr){
        if(p ?$ ip){	
                # counter = counter + 1;
	        # print "===============";
	        # print counter;

                id = ID($src = p$ip$src, $dst = p$ip$dst);
                if(id in t_IP){
                        t_IP[id]$a += 1;
                        #print  id, t_IP[id]$v;
                        if(p$ip$id < t_IP[id]$v){
                                print t_IP[id]$a / t_IP[id]$c;
                                t_IP[id]$v = p$ip$id;
                                if(network_time() - t_IP[id]$t  < 1min){
                                  t_IP[id]$c += 1;
                                  if(|t_IP[id]$a / t_IP[id]$c| < 20){
                                      print  t_IP[id]$c,  t_IP[id]$a;       
                                      print "possible IP Id stego", p$ip$src;
                                      NOTICE([$note=Possible_Steganography,
				      $ts = network_time(),
                                      $msg = "Possible IP ID Steganography",
                                      $sub = "ID number of IP decreased unexpected number of times",
                                      $conn = c]);
                                        t_IP[id]$c = 1;
                                        t_IP[id]$t = network_time();
                                        t_IP[id]$a = 100;
                                        print "Reset Data";
                                  }
                                }
				else{
                                  t_IP[id]$c = 1;
                                  t_IP[id]$t = network_time();
                                  t_IP[id]$a = 100;
                                  print "Reset Data";
                                }
                        }
                        else{
                                t_IP[id]$v = p$ip$id;
                        }
                }else if (p$ip$src != local_address){
                #       print "New adders store id";
			t_IP[id] = VTC($v = p$ip$id, $t = network_time(), $c = 1, $a = 100);
                }
        }
}



