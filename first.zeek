global x = 0;


event zeek_init()

        {

        print "Hello, World!";

        }


event zeek_done()

        {

        print "Goodbye, World!";

        }


event icmp_echo_request(c: connection, icmp: icmp_conn, id: count, seq: count, payload: string)

        {

        print x;

        if (x != seq-1 && x != 0){

                  print "possible stego";

                }

        print seq;

        x = seq;

        }