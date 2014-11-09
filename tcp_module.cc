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
#include <stdlib.h>

using namespace std;

struct TCPState {
    // need to write this
    unsigned int seq_num;
    unsigned int ack_num;
    bool is_server;
    bool first_ack_recvd;
    Connection connection;
    std::ostream & Print(std::ostream &os) const { 
    os << "TCPState()" ; 
    return os;
    }

    friend std::ostream &operator<<(std::ostream &os, const TCPState& L) {
        return L.Print(os);
    }
};

/*
    Simple timer class from cplusplus.com
*/
class timer {
    private:
        unsigned long begTime;
    public:
        void start() {
            begTime = clock();
        }

        unsigned long elapsedTime() {
            return ((unsigned long) clock() - begTime) / CLOCKS_PER_SEC;
        }

        bool isTimeout(unsigned long seconds) {
            printf("Elapsed %lu\n", elapsedTime());
            return seconds <= elapsedTime();
        }

        void stop(){
            begTime = 0;
        }

        unsigned long getBeg(){
            return begTime;
        }
};


/*
    Builds the TCPHeader for you, takes the ipheader, connection, clients ack #, clients seq # (-1 if none), 
    the window size, the flags, and lastly the payload. Then builds the packet and returns it
*/
Packet build_packet(Packet p2, Connection c, IPHeader ip, TCPHeader th, unsigned short w, 
                    unsigned int ack, unsigned int seq, unsigned char flags,
                    Buffer payload ){
    Packet p;
    p.PushFrontHeader(ip);

    printf("build packet\n");
    printf("do connection stuff!\n");
    th.SetSourcePort(c.srcport, p);
    //set dest port
    th.SetDestPort(c.destport, p);
    //set header len
    printf("fflags\n");
    th.SetFlags(flags, p);

    th.SetHeaderLen(20,p);
    //set flags

    //k so we're setting the ack to client_isn+1
    printf("acks and window size!\n");

    th.SetAckNum(ack+1, p);
    th.SetWinSize(w, p);
    printf("or maybe it's this!\n");
    if( seq == NULL ){ //First packet we're sending
        //seed and set seqNum here
        srand (time(NULL));
        th.SetSeqNum(rand() % 100, p);
    }
    else{   //Else, just add one to seq
        th.SetSeqNum(seq+1, p);
    }
    //Check to see if we need to add a payload
    printf("is this making me sad? \n");
    if(payload.GetSize() == 0 ){
        unsigned int payload_size;
        payload_size = (unsigned int) payload.GetSize();
        //TODO: add payload
        //and update the ipheader size
        ip.SetTotalLength(TCP_HEADER_BASE_LENGTH+IP_HEADER_BASE_LENGTH + payload_size);
        p.PushFrontHeader(ip);

    }
    p.PushBackHeader(th);
    printf("Returning packet\n");
    return p;
}

    /*
    Sets protocol and ports for ip header
    The total size will be updated as neccessary in build_packet 
    */
IPHeader build_IPHeader(Connection c){
    IPHeader ih;
    ih.SetProtocol(IP_PROTO_TCP);
    //If I'm not mistaken, c.dest is the clients IP, so
    //I think we should be using c.src
    ih.SetSourceIP(c.src);
    ih.SetDestIP(c.dest);
    ih.SetTotalLength(TCP_HEADER_BASE_LENGTH+IP_HEADER_BASE_LENGTH);
    return ih;
}

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
    MinetEvent event;
    unsigned long timeout = 1;
    timer t;
    timer ack_timer;
    ack_timer.stop();
    t.stop();

    //This is going to have to be replaced eventually, but we're just going to create 
    //our state here
    struct TCPState myState;
    myState.seq_num = 0;
    myState.ack_num = 0;
    while (MinetGetNextEvent(event, timeout) == 0) {

        //Check if our timer has elapsed
        if(t.getBeg() != 0 && t.isTimeout(timeout)){
            printf("We've timed out\n");
            t.stop();
        }
        if(ack_timer.getBeg() != 0 && ack_timer.isTimeout(timeout)){
            printf("Ack timed out\n");
            ack_timer.stop();
        }

        if ((event.eventtype == MinetEvent::Dataflow) && 
           (event.direction == MinetEvent::IN)) {
    
            if (event.handle == mux) {
              // ip packet has arrived!
                MinetSendToMonitor(MinetMonitoringEvent("packet received!\n"));

                //printf("%s\n", "Packet received");

                Packet p;
                Connection c;
                //Grab that packet that packet and store it in p
                MinetReceive(mux, p);
                //Grab the header and store it in tcph
                unsigned int tcp_len = TCPHeader::EstimateTCPHeaderLength(p);
                p.ExtractHeaderFromPayload<TCPHeader>(tcp_len);

                TCPHeader tcph;
                tcph=p.FindHeader(Headers::TCPHeader);
                //Do the same with the IP header
                IPHeader iph;
                iph=p.FindHeader(Headers::IPHeader);
                //So here we're snagging the connection's src, putting it as
                //our destination; same with their dest/our source
                iph.GetDestIP(c.src);
                iph.GetSourceIP(c.dest);
                iph.GetProtocol(c.protocol);
                //Getting port information for the tcp header, so we know where to send
                //this packet
                tcph.GetDestPort(c.srcport);
                tcph.GetSourcePort(c.destport);   
                myState.connection=c;
                //Alright, lets make sure this a SYN packet, otherwise
                //the client's dun goof'd         
                unsigned char ch;
                tcph.GetFlags(ch);
                if(IS_SYN(ch) && IS_ACK(ch) && (t.getBeg() == 0))
                {
					Packet p2;
                    IPHeader ih;
                    TCPHeader th;
                    //build ipheader
                    ih = build_IPHeader(c);
                    p2.PushFrontHeader(ih);

                    //set flags to SYN and ACK
                    unsigned char flags = 0;
                    SET_ACK(flags);
                    //grab the packet to ack
                    tcph.GetSeqNum(myState.ack_num);
                    //grab the window size
                    unsigned short w;
                    tcph.GetWinSize(w);
                    //Build the packet, with the connection, iphead, window size,
                    //# to ack, NULL (generate new seq #), the flags, and no payload
                    th.SetSourcePort(c.srcport, p2);
                    //set dest port
                    th.SetDestPort(c.destport, p2);
                    //set flags
                    th.SetFlags(flags, p2);
                    //set header len
                    th.SetHeaderLen(20,p2);
                    //set ack and win size
                    myState.ack_num += 1;
                    th.SetAckNum(myState.ack_num, p2);
                    th.SetWinSize(w, p2);
                    
                    th.SetSeqNum(1, p2);

                    p2.PushBackHeader(th);
                    
                    MinetSend(mux, p2);
                    printf("%s\n", "ACK sent");
                    
                    unsigned short dataLength;
                    unsigned char ipHead, tcpHead;
                        //compute the length of their data
                        iph.GetTotalLength(dataLength);
                        iph.GetHeaderLength(ipHead);
                        tcph.GetHeaderLen(tcpHead);
                        ipHead = ipHead << 2; 
                        tcpHead = tcpHead << 2;
                        dataLength = dataLength - (short)ipHead - (short)tcpHead;
                        
                         Buffer &data = p.GetPayload();
						
                    SockRequestResponse con;
                    con.connection=myState.connection;
                    con.type=WRITE;
                    con.data=data;
                    con.error=EOK;
                    con.bytes=0;
					MinetSend(sock,con);
					sleep(1);
					MinetSend(sock,con);
					
					
                    
				} 
                else if (IS_SYN(ch) && (t.getBeg() == 0) )
                {
                    
                    Packet p2;
                    IPHeader ih;
                    TCPHeader th;
                    //build ipheader
                    ih = build_IPHeader(c);
                    p2.PushFrontHeader(ih);

                    //set flags to SYN and ACK
                    unsigned char flags = 0;
                    SET_SYN(flags);
                    SET_ACK(flags);
                    //grab the packet to ack
                    tcph.GetSeqNum(myState.ack_num);
                    //grab the window size
                    unsigned short w;
                    tcph.GetWinSize(w);
                    //Build the packet, with the connection, iphead, window size,
                    //# to ack, NULL (generate new seq #), the flags, and no payload
                    th.SetSourcePort(c.srcport, p2);
                    //set dest port
                    th.SetDestPort(c.destport, p2);
                    //set flags
                    th.SetFlags(flags, p2);
                    //set header len
                    th.SetHeaderLen(20,p2);
                    //set ack and win size
                    myState.ack_num += 1;
                    th.SetAckNum(myState.ack_num, p2);
                    th.SetWinSize(w, p2);
                    srand (time(NULL));
                    myState.seq_num = rand() % 100;
                    myState.is_server=true;
                    myState.first_ack_recvd=false;
                    th.SetSeqNum(myState.seq_num, p2);

                    p2.PushBackHeader(th);
                    
                    MinetSend(mux, p2);
                    printf("%s\n", "SYNACK sent, start timer");
                    t.start();

                }
                else
                {
                    t.stop();
                    tcph.GetFlags(ch);
                    if(IS_ACK(ch)){
                        printf("Okay we got Ack.\n");
                        //So we need to check to see if the packet contains data
                        unsigned short dataLength;
                        unsigned char ipHead, tcpHead;
                        //compute the length of their data
                        iph.GetTotalLength(dataLength);
                        iph.GetHeaderLength(ipHead);
                        tcph.GetHeaderLen(tcpHead);
                        tcph.GetSeqNum(myState.ack_num);

                        ipHead = ipHead << 2; 
                        tcpHead = tcpHead << 2;
                        dataLength = dataLength - (short)ipHead - (short)tcpHead;
                        //Update what we're acking to acknowledge the data we got
                        myState.ack_num += dataLength;
                        
                        //send data to socket

						Buffer &data = p.GetPayload();
						SockRequestResponse con;
						con.connection=myState.connection;
						con.type=WRITE;
						con.data=data;
						con.error=EOK;
						con.bytes=dataLength;
						MinetSend(sock,con);
						

						myState.first_ack_recvd=true;

                        printf("data: %d ip: %d header: %d\n", dataLength,ipHead,tcpHead);
                        //If they sent us data, let's just read it into a char and print
                        //for now
                        if(dataLength > 0 && (ack_timer.getBeg() == 0) ){
                            printf("We have some data, let's read it\n");
                            //Grab the payload, allocate a buffer and read extract the data
                            Buffer &data = p.GetPayload();
                            char * buf = (char *)malloc(sizeof(char) * dataLength);
                            data.GetData(buf, dataLength, 0);
							/*SockRequestResponse dat;
							dat.connection=myState.connection;
							dat.type=WRITE;
							dat.data=datas;
							dat.error=EOK;
							dat.bytes=dataLength;
							MinetSend(sock,dat);
							*/
                            printf("Data: %s\n", buf);
                            free(buf);

                            //Okay, so we got the data, now lets ack that to make them happy
                            Packet p2("Hey\n", sizeof("Hey\n"));
                            IPHeader ih;
                            TCPHeader th;
                            //build ipheader
                            ih = build_IPHeader(c);
                            ih.SetTotalLength(TCP_HEADER_BASE_LENGTH+IP_HEADER_BASE_LENGTH
                                             + sizeof("Hey\n"));
                            p2.PushFrontHeader(ih);

                            //set flags to SYN and ACK
                            unsigned char flags = 0;
                            SET_ACK(flags);
                            //grab the packet to ack
                            //grab the window size
                            unsigned short w;
                            tcph.GetWinSize(w);
                            //Build the packet, with the connection, iphead, window size,
                            //# to ack, NULL (generate new seq #), the flags, and no payload
                            th.SetSourcePort(c.srcport, p2);
                            //set dest port
                            th.SetDestPort(c.destport, p2);
                            //set flags
                            th.SetFlags(flags, p2);
                            //set header len
                            th.SetHeaderLen(20,p2);
                            //set ackand sin size
                            th.SetAckNum(myState.ack_num, p2);
                            th.SetWinSize(w, p2);
                            tcph.GetAckNum(myState.seq_num);
                            th.SetSeqNum(myState.seq_num,p2);
                            p2.PushBackHeader(th);
                            
                            MinetSend(mux, p2);
                            printf("%s\n", "ACK sent, start timer");
                            //Change seq number
                            myState.seq_num += sizeof("Hey\n");
                            ack_timer.start();

                        }
                        else{   //If there's no data... whatever
                            printf("No data in this ack\n");
                            ack_timer.stop();
                            t.stop();
                        }

                    }

                    if(IS_FIN(ch)){
                        printf("They're trying to close the connection\n");
                        //We need to ack, then fin, then we're done
                        Packet p2;
                        IPHeader ih;
                        TCPHeader th;
                        //build ipheader
                        ih = build_IPHeader(c);
                        p2.PushFrontHeader(ih);

                        //set flags to ACK
                        unsigned char flags = 0;
                        SET_ACK(flags);
                        //grab the window size
                        unsigned short w;
                        tcph.GetWinSize(w);
                        //Build the packet, with the connection, iphead, window size,
                        //# to ack, NULL (generate new seq #), the flags, and no payload
                        th.SetSourcePort(c.srcport, p2);
                        //set dest port
                        th.SetDestPort(c.destport, p2);
                        //set flags
                        th.SetFlags(flags, p2);
                        //set header len
                        th.SetHeaderLen(20,p2);
                        //set ack and win size
                        th.SetAckNum(myState.ack_num+1, p2);
                        th.SetWinSize(w, p2);
                        th.SetSeqNum(myState.seq_num, p2);
                        p2.PushBackHeader(th);
                        MinetSend(mux, p2);

                        //Now just change the ack to a fin, and send a new one
                        CLR_ACK(flags);
                        SET_FIN(flags);
                        th.SetFlags(flags,p2);
                        th.SetAckNum(0,p2);    //Wireshark says this should be 0
                        //Eject the back header and put on our new one.
                        p2.PopBackHeader();
                        p2.PushBackHeader(th);
                        MinetSend(mux, p2);
                    }
                }
            }
            if (event.handle == sock) {
            // socket request or response has arrived
                SockRequestResponse req;
                MinetReceive(sock,req);
                switch (req.type) {
                    case CONNECT:
                    {
                        printf("wanna connect\n");
                        ConnectionToStateMapping<TCPState> m;
						m.connection=req.connection;
						myState.connection=req.connection;
						// remove any old forward that might be there.
						//ConnectionList<TCPState>::iterator cs = clist.FindMatching(req.connection);
					//	if (cs!=clist.end()) {
					//	  clist.erase(cs);
					//	}
					//	* */
						
						
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
						unsigned char flag=0;
						unsigned int seq=0;
						CLR_SYN(flag);
						SET_SYN(flag);
						uh.SetSourcePort(req.connection.srcport,p);
						uh.SetDestPort(req.connection.destport,p);
						uh.SetHeaderLen(TCP_HEADER_BASE_LENGTH,p);
						uh.SetFlags(flag,p);
						uh.SetSeqNum(seq,p);
						uh.SetUrgentPtr(0,p);
						uh.SetWinSize(5,p);
						// Now we want to have the tcp header BEHIND the IP header
						p.PushBackHeader(uh);
						//cerr << p << endl;
						MinetSend(mux,p);
						sleep(1);
						MinetSend(mux,p);
						
						//add this new connection to TCP state list
						clist.push_back(m);
						//cerr << "Added connection to TCP state list" << endl;
						SockRequestResponse repl;
						// repl.type=SockRequestResponse::STATUS;
						repl.type=STATUS;
						repl.connection=req.connection;
						
						repl.error=EOK;
						MinetSend(sock,repl);

                    }
                    break;
                    case ACCEPT:
                    {  //send OK response, check for data
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
                    {
                       printf(" wanna status\n");
                    }
                    break;
                    case WRITE:
                    {
                        printf(" wanna write\n");
                        unsigned bytes =  req.data.GetSize();
						// create the payload of the packet
						Packet p(req.data.ExtractFront(bytes));
						// Make the IP header first since we need it to do the udp checksum
						IPHeader ih;
						ih.SetProtocol(IP_PROTO_TCP);
						ih.SetSourceIP(req.connection.src);
						ih.SetDestIP(req.connection.dest);
						ih.SetTotalLength(bytes+20+IP_HEADER_BASE_LENGTH);
						// push it onto the packet
						p.PushFrontHeader(ih);
						// Now build the UDP header
						// notice that we pass along the packet so that the udpheader can find
						// the ip header because it will include some of its fields in the checksum
						TCPHeader uh;
						uh.SetSourcePort(req.connection.srcport,p);
						uh.SetDestPort(req.connection.destport,p);
						uh.SetHeaderLen(20,p);
                        uh.SetSeqNum(myState.seq_num+1,p);
                        myState.seq_num+=bytes;
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
                    case FORWARD:
                    {
                        printf("wanna forward\n");
                    }
                    break;
                      // case SockRequestResponse::CLOSE:
                    case CLOSE:
                    {
                        printf("wanna close\n");
                    }
                    break;
                    default:
                    {
                        printf("want something else\n");
                    }
                }
            }

            if (event.eventtype == MinetEvent::Timeout) {
               // timeout ! probably need to resend some packets
            }
        }
        else{
            //This just means we're waiting...patiently
        }
    }
    printf("Now we're exiting\n");
    MinetDeinit();
    return 0;
}










