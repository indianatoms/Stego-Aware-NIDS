@load record.zeek

global packet_counter = 0;
global SIP_callid : table[addr] of STC = {};
global SIP_cseq : table[addr] of STC = {};
global SIP_MF : table[addr] of STC = {};
global SIP_contact: table[addr] of STC = {};

event sip_header(c: connection, is_orig: bool, name: string, value: string){
	if (name == "CALL-ID"){
		check_freqency(SIP_callid,c$id$orig_h,value,"SIP CALL ID CHANGING TOO FREQUENTLY",1min,10);
#		print "CALL-ID: "+ value;
	}
	if (name == "CSEQ"){
#		print "CSEQ: " +value;
	}
	if (name == "MAX-FORWARDS"){
		check_freqency(SIP_MF,c$id$orig_h,value,"MAX-FORWARS CHANGING TOO FREQUENTLY",1min,2);
#		print "MAX_FORWARS: " +value;
	}
	if (name == "CONTACT"){
		check_freqency(SIP_contact,c$id$orig_h,split_string(value,/:|@/)[1],"SIP CONTACT CHANGING TOO FREQUENTLY",1min,10);
#		print "CONTACT: " +split_string(value,/:|@/)[1];
	}
}
