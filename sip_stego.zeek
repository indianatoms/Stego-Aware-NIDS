@load vtcs.zeek

global packet_counter = 0;
global SIP_callid : table[addr] of STC = {};
global SIP_cseq : table[addr] of STC = {};
global SIP_MF : table[addr] of STC = {};
global SIP_contact: table[addr] of STC = {};

# global counter : int;

# event zeek_init() {
#  	counter = 0;
# }


event sip_header(c: connection, is_orig: bool, name: string, value: string){
			# counter = counter + 1;
		# print "===============";
		# print counter;
		
	if (name == "CALL-ID"){
		check_freqency(SIP_callid,c$id$orig_h,value,"SIP CALL ID CHANGING TOO FREQUENTLY");
		print "CALL-ID: "+ value;
	}
	if (name == "s"){
		check_freqency(SIP_cseq,c$id$orig_h,value,"SIP CSEQ CHANGING TOO FREQUENTLY");
		print "CSEQ: " +value;
	}
	if (name == "MAX-FORWARDS"){
		check_freqency(SIP_MF,c$id$orig_h,value,"MAX-FORWARS CHANGING TOO FREQUENTLY");
		print "MAX_FORWARS: " +value;
	}
	if (name == "CONTACT"){
		check_freqency(SIP_contact,c$id$orig_h,split_string(value,/:|@/)[1],"SIP CONTACT CHANGING TOO FREQUENTLY");
		print "CONTACT: " +split_string(value,/:|@/)[1];
	}
}
