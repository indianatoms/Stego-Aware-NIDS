@load policy/protocols/mqtt
@load record.zeek

global MQTT_id : table[addr] of STC = {};
global MQTT_user : table[addr] of STC = {};
global MQTT_pass : table[addr] of STC = {};
global MQTT_alive : table[addr] of ITC = {};
global MQTT_clean : table[addr] of BTC = {};



event mqtt_publish (c: connection, is_orig: bool, msg_id: count, msg: MQTT::PublishMsg){
#	print "pub";
#	print c$id$orig_h;
#	print msg$payload;
#	print find_entropy(msg$payload)$entropy;
	check_freqency_b(MQTT_clean,c$id$orig_h,msg$retain,"MQTT RETAIN MESSAGE");
	print msg_id;
}

event mqtt_subscribe(c: connection, msg_id: count, topics: string_vec, requested_qos: index_vec){
#	for (i in topics)
#	{
#		print topics[i];
#	}
	print "sub";
	print msg_id;
}

event mqtt_connect(c: connection, msg: MQTT::ConnectMsg){
         check_freqency(MQTT_id,c$id$orig_h,msg$client_id,"MQTT ID CHANGING TOO FREQUENTLY");
         check_freqency(MQTT_user,c$id$orig_h,msg$username,"MQTT USER CHANGING TOO FREQUENTLY");
         check_freqency(MQTT_pass,c$id$orig_h,msg$password,"MQTT PASSWORD CHANGING TOO FREQUENTLY");
         check_freqency_t(MQTT_alive,c$id$orig_h,msg$keep_alive,"MQTT KEEP ALIVE CHANGING TOO FREQUENTLY");
	 check_freqency_b(MQTT_clean,c$id$orig_h,msg$clean_session,"MQTT CLEAN SESSION");
}

