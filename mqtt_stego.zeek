@load policy/protocols/mqtt

#event mqtt_connect  (c: connection, msg: MQTT::ConnectMsg){
#	print c;
#}

#event mqtt_puback(c: connection, is_orig: bool, msg_id: count)
#{
#	print c;
#}

event mqtt_publish (c: connection, is_orig: bool, msg_id: count, msg: MQTT::PublishMsg){
	print msg;
}

#event mqtt_subscribe(c: connection, msg_id: count, topics: string_vec, requested_qos: index_vec){
#print topics;
#}

#event mqtt_pubrel (c: connection, is_orig: bool, msg_id: count){
#	print c;
#}

#event mqtt_puback (c: connection, is_orig: bool, msg_id: count){
#	print c;
#}

#event MQTT::log_mqtt(rec: MQTT::ConnectInfo){
#	print rec;
#}
