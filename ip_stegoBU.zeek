type TOS: record {
    v: int;
    t: time;
    c: count;
};

 global t_TOS: table[addr] of TOS = {};
# global TOS_timer : table[addr] of time = {};
# global TOS_counter : table[addr] of count = {};

event new_packet (c: connection, p: pkt_hdr){
	if(p ?$ ip){
		if(p$ip$src in t_TOS){
			if (t_TOS[p$ip$src]$v != p$ip$tos){
				if(network_time() - t_TOS[p$ip$src]$t < 1min){
					t_TOS[p$ip$src]$c +=1;
					if(t_TOS[p$ip$src]$c > 5)
                                                 {
                                                     print "possible stego or someone is using VoIP too much :-)", t_TOS[p$ip$src]$c;
                                                 }
				}
				else
				{
					t_TOS[p$ip$src]$t = network_time();
					t_TOS[p$ip$src]$c = 0;
				}
			}
		}
		else{
			t_TOS[p$ip$src] = TOS($v = p$ip$tos, $t = network_time(), $c = 0);
		}
	}
}

