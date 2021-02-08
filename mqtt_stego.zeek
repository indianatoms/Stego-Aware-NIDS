@load policy/protocols/mqtt
@load vtcs.zeek

global MQTT_id : table[addr] of STC = {};
global MQTT_user : table[addr] of STC = {};
global MQTT_pass : table[addr] of STC = {};
global MQTT_alive : table[addr] of ITC = {};
global MQTT_clean : table[addr] of BTC = {};

event mqtt_publish (c: connection, is_orig: bool, msg_id: count, msg: MQTT::PublishMsg){
	print msg$payload;
#	print find_entropy(msg$payload)$entropy;
	if (find_entropy(msg$payload)$entropy > 3.5){
		NOTICE([$note=Possible_Steganography,
			$conn=c,
			$ts = network_time(),
			$sub = "The entrophy of MQTT payload is too high",
                        $msg = "Possible steganography"]);
        }
	check_freqency_b(MQTT_clean,c$id$orig_h,msg$retain,"MQTT RETAIN MESSAGE",packet_counter);
	print msg_id;
}

event mqtt_subscribe(c: connection, msg_id: count, topics: string_vec, requested_qos: index_vec){
	print "subscribe";
	for (i in topics)
	{
		print topics[i];
		print find_entropy(topics[i])$entropy;
		if (find_entropy(topics[i])$entropy> 3.5){
			NOTICE([$note=Possible_Steganography,
				$conn=c,
				$msg = "Possible steganography",
				$sub = "The entrophy of topic is too high",
				$ts = network_time()]);
		}
	}
	print msg_id;
}

event mqtt_connect(c: connection, msg: MQTT::ConnectMsg){
        check_freqency(MQTT_id,c$id$orig_h,msg$client_id,"MQTT ID CHANGING TOO FREQUENTLY",packet_counter);
        check_freqency(MQTT_user,c$id$orig_h,msg$username,"MQTT USER CHANGING TOO FREQUENTLY",packet_counter);
        check_freqency(MQTT_pass,c$id$orig_h,msg$password,"MQTT PASSWORD CHANGING TOO FREQUENTLY",packet_counter);
        check_freqency_t(MQTT_alive,c$id$orig_h,msg$keep_alive,"MQTT KEEP ALIVE CHANGING TOO FREQUENTLY",packet_counter);
	 	check_freqency_b(MQTT_clean,c$id$orig_h,msg$clean_session,"MQTT CLEAN SESSION",packet_counter);
}

