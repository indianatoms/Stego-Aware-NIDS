@load iat.zeek

event zeek_init() {
	local x: vector of interval = {20sec,21sec,26sec,30sec,31sec};
	variance(x);

}
