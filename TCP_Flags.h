#pragma once

namespace analyzer { namespace tcp {

class TCP_Flags {
public:
	TCP_Flags(const struct tcphdr* tp)	
	{ 
		flags = tp->th_flags;
		reserved = tp->th_x2;
	}
	TCP_Flags()	
	{ 
		flags = 0; 
		reserved = 0;
	}

	bool SYN() const	{ return flags & TH_SYN; }
	bool FIN() const	{ return flags & TH_FIN; }
	bool RST() const	{ return flags & TH_RST; }
	bool ACK() const	{ return flags & TH_ACK; }
	bool URG() const	{ return flags & TH_URG; }
	bool PUSH() const	{ return flags & TH_PUSH; }
	char RESERVED() const	{ return static_cast<char>(reserved);}

	string AsString() const;
	string ResString() const;

protected:
	u_char flags;
	int reserved;
};

inline string TCP_Flags::AsString() const
	{
	char tcp_flags[20];
	char* p = tcp_flags;

	if ( SYN() )
		*p++ = 'S';

	if ( FIN() )
		*p++ = 'F';

	if ( RST() )
		*p++ = 'R';

	if ( ACK() )
		*p++ = 'A';

	if ( PUSH() )
		*p++ = 'P';

	if ( URG() )
		*p++ = 'U';
	*p++ = RESERVED();
	*p++ = '\0';
	return tcp_flags;
	}
}


}
