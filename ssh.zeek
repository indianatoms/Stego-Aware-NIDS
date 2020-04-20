#@load policy/protocols/ssh
#local SSH_Fail_Count : table[addr] of int = {};
event ssh_auth_attempted(c: connection, authenticated: bool){
         print c;
}

