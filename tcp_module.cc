// You will build this in project part B - this is merely a
// stub that does nothing but integrate into the stack

// For project parts A and B, an appropriate binary will be 
// copied over as part of the build process



#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>


#include <iostream>

#include "Minet.h"

using namespace std;

struct TCPState {
    // need to write this
    std::ostream & Print(std::ostream &os) const { 
	os << "TCPState()" ; 
	return os;
    }
};


int main(int argc, char * argv[]) {
    MinetHandle mux;
    MinetHandle sock;
    
    ConnectionList<TCPState> clist;
	
    MinetInit(MINET_TCP_MODULE);

    mux = MinetIsModuleInConfig(MINET_IP_MUX) ?  
	MinetConnect(MINET_IP_MUX) : 
	MINET_NOHANDLE;
    
    sock = MinetIsModuleInConfig(MINET_SOCK_MODULE) ? 
	MinetAccept(MINET_SOCK_MODULE) : 
	MINET_NOHANDLE;

    if ( (mux == MINET_NOHANDLE) && 
	 (MinetIsModuleInConfig(MINET_IP_MUX)) ) {

	MinetSendToMonitor(MinetMonitoringEvent("Can't connect to ip_mux"));

	return -1;
    }

    if ( (sock == MINET_NOHANDLE) && 
	 (MinetIsModuleInConfig(MINET_SOCK_MODULE)) ) {

	MinetSendToMonitor(MinetMonitoringEvent("Can't accept from sock_module"));

	return -1;
    }
    
    cerr << "tcp_module STUB VERSION handling tcp traffic.......\n";

    MinetSendToMonitor(MinetMonitoringEvent("tcp_module STUB VERSION handling tcp traffic........"));
	MinetSendToMonitor(MinetMonitoringEvent("Handling mux"));
	
    MinetEvent event;
    double timeout = 1;

    while (MinetGetNextEvent(event,timeout) == 0) {
		if ((event.eventtype == MinetEvent::Dataflow) && 
			(event.direction == MinetEvent::IN)) {
			if (event.handle == mux) {
				// ip packet has arrived!
				Packet p;
				unsigned short len;
				bool checksumok;
				cerr << "Handling Mux\n";
				MinetReceive(mux,p);
				cerr << p << endl;
				p.ExtractHeaderFromPayload<TCPHeader>(TCPHeader::EstimateTCPHeaderLength(p));
				TCPHeader tcph;
				tcph=p.FindHeader(Headers::TCPHeader);
				checksumok=tcph.IsCorrectChecksum(p);
				IPHeader iph;
				iph=p.FindHeader(Headers::IPHeader);
				cerr << "Found Headers\n";
				Connection c;
				// note that this is flipped around because
				// "source" is interepreted as "this machine"
				iph.GetDestIP(c.src);
				iph.GetSourceIP(c.dest);
				iph.GetProtocol(c.protocol);
				tcph.GetDestPort(c.srcport);
				tcph.GetSourcePort(c.destport);
				ConnectionList<TCPState>::iterator cs = clist.FindMatching(c);
				if (cs!=clist.end()) {
					
					Buffer &data = p.GetPayload().ExtractFront(len);
					SockRequestResponse write(WRITE,
							(*cs).connection,
							data,
							len,
							EOK);
					if (!checksumok) {
						MinetSendToMonitor(MinetMonitoringEvent("forwarding packet to sock even though checksum failed"));
					}
					MinetSend(sock,write);
				} else {
					MinetSendToMonitor(MinetMonitoringEvent("Unknown port, sending ICMP error message"));
					IPAddress source; iph.GetSourceIP(source);
					ICMPPacket error(source,DESTINATION_UNREACHABLE,PORT_UNREACHABLE,p);
					MinetSendToMonitor(MinetMonitoringEvent("ICMP error message has been sent to host"));
					MinetSend(mux, error);
				}
			}
			if (event.handle == sock) {
				// socket request or response has arrived
				cerr << "HELLO\n";
				SockRequestResponse req;
				MinetReceive(sock,req);
				cerr << req << endl;
				switch (req.type) {
				case CONNECT:
					{
						
						Packet p;
						// Make the IP header first since we need it to do the udp checksum
						IPHeader ih;
						ih.SetProtocol(IP_PROTO_TCP);
						ih.SetSourceIP(req.connection.src);
						ih.SetDestIP(req.connection.dest);
						ih.SetTotalLength(TCP_HEADER_BASE_LENGTH+IP_HEADER_BASE_LENGTH);
						// push it onto the packet
						p.PushFrontHeader(ih);
						// Now build the TCP header
						// notice that we pass along the packet so that the udpheader can find
						// the ip header because it will include some of its fields in the checksum
						TCPHeader uh;
						unsigned char flag;
						SET_SYN(flag);
						uh.SetSourcePort(req.connection.srcport,p);
						uh.SetDestPort(req.connection.destport,p);
						uh.SetHeaderLen(TCP_HEADER_BASE_LENGTH,p);
						uh.SetFlags(flag,p);
						// Now we want to have the tcp header BEHIND the IP header
						p.PushBackHeader(uh);
						MinetSend(mux,p);
						SockRequestResponse repl;
						// repl.type=SockRequestResponse::STATUS;
						repl.type=STATUS;
						repl.connection=req.connection;
						repl.bytes=bytes;
						repl.error=EOK;
						MinetSend(sock,repl);
					}
					break;
				case ACCEPT:
				  { // ignored, send OK response
					SockRequestResponse repl;
					repl.type=STATUS;
					repl.connection=req.connection;
					// buffer is zero bytes
					repl.bytes=0;
					repl.error=EOK;
					MinetSend(sock,repl);
				  }
				  break;
				case STATUS:
				  // ignored, no response needed
				  break;
				  // case SockRequestResponse::WRITE:
				case WRITE:
				  {
					unsigned bytes = MIN_MACRO(UDP_MAX_DATA, req.data.GetSize());
					// create the payload of the packet
					Packet p(req.data.ExtractFront(bytes));
					// Make the IP header first since we need it to do the udp checksum
					IPHeader ih;
					ih.SetProtocol(IP_PROTO_TCP);
					ih.SetSourceIP(req.connection.src);
					ih.SetDestIP(req.connection.dest);
					ih.SetTotalLength(bytes+UDP_HEADER_LENGTH+IP_HEADER_BASE_LENGTH);
					// push it onto the packet
					p.PushFrontHeader(ih);
					// Now build the UDP header
					// notice that we pass along the packet so that the udpheader can find
					// the ip header because it will include some of its fields in the checksum
					TCPHeader uh;
					uh.SetSourcePort(req.connection.srcport,p);
					uh.SetDestPort(req.connection.destport,p);
					uh.SetHeaderLen(UDP_HEADER_LENGTH,p);
					// Now we want to have the udp header BEHIND the IP header
					p.PushBackHeader(uh);
					MinetSend(mux,p);
					SockRequestResponse repl;
					// repl.type=SockRequestResponse::STATUS;
					repl.type=STATUS;
					repl.connection=req.connection;
					repl.bytes=bytes;
					repl.error=EOK;
					MinetSend(sock,repl);
				  }
				  break;
				  // case SockRequestResponse::FORWARD:
				case FORWARD:
				  {
					ConnectionToStateMapping<TCPState> m;
					m.connection=req.connection;
					// remove any old forward that might be there.
					ConnectionList<TCPState>::iterator cs = clist.FindMatching(req.connection);
					if (cs!=clist.end()) {
					  clist.erase(cs);
					}
					clist.push_back(m);
					SockRequestResponse repl;
					// repl.type=SockRequestResponse::STATUS;
					repl.type=STATUS;
					repl.connection=req.connection;
					repl.error=EOK;
					repl.bytes=0;
					MinetSend(sock,repl);
				  }
				  break;
				  // case SockRequestResponse::CLOSE:
				case CLOSE:
				  {
					ConnectionList<TCPState>::iterator cs = clist.FindMatching(req.connection);
					SockRequestResponse repl;
					repl.connection=req.connection;
					// repl.type=SockRequestResponse::STATUS;
					repl.type=STATUS;
					if (cs==clist.end()) {
					  repl.error=ENOMATCH;
					} else {
					  repl.error=EOK;
					  clist.erase(cs);
					}
					MinetSend(sock,repl);
				  }
				  break;
				default:
				  {
					SockRequestResponse repl;
					// repl.type=SockRequestResponse::STATUS;
					repl.type=STATUS;
					repl.error=EWHAT;
					MinetSend(sock,repl);
				  }
				}
			}			
		}
		if (event.eventtype == MinetEvent::Timeout) {
			//cerr << "Timeout\n";
			// timeout ! probably need to resend some packets
		}

	}

    MinetDeinit();

    return 0;
}
