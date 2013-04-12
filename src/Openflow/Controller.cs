using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Threading;
using NDesk.Options;

using uint8_t = System.Byte;
using uint16_t = System.UInt16;
using uint32_t = System.UInt32;
using uint64_t = System.UInt64;

namespace Openflow {
	public class Controller : Protocol {

		SocketConnection socket_connection;

		//Switch information
      uint64_t datapath_id;
     	uint32_t n_buffers;
      uint8_t n_tables;
      ofp_capabilities capabilities;
      ofp_action_type action_type;
		protected List<ofp_phy_port> phy_port_list;
		string log_file;
		Logger logger;

		MacLearning mac_learning;

		public Controller(string[] args) {

			List<string> connections = new List<string>();
			bool is_active=false, is_tcp=false;

			phy_port_list = new List<ofp_phy_port>();
			var optionSet = new OptionSet() { };

			try {
				connections = optionSet.Parse(args);
			} catch {
				Console.WriteLine("Error: Option error");
			}

			if (connections.Count != 1 ) {
            Console.WriteLine("Error:Inapropriate address argument");
            Usage();
            Environment.Exit(0);
			}

         if ( !(connections[0].StartsWith("ptcp:") || connections[0].StartsWith("tcp") || connections[0].StartsWith("punix:") || connections[0].StartsWith("unix:"))) {
            Console.WriteLine("Error:Not a valid connection address");
            Usage();
            Environment.Exit(0);
         }
         if ( !connections[0].StartsWith("p")) {
            is_active = true;
         }
         if ( connections[0].Split(':')[0].Contains("tcp")) {
            is_tcp = true;
         }

			try { 
				socket_connection = new SocketConnection(is_active, is_tcp, connections[0].Split(':')[1]);
			} catch {
            Console.WriteLine("Error:Fail to establish socket connection");
				Environment.Exit(0);
			}

			string[] log_files = connections[0].Split('/');  
			log_file = log_files[log_files.Length-1];
			log_file += ".log";
			logger = new Logger(log_file);
			mac_learning = new MacLearning(logger);


         StreamWriter file = new StreamWriter("controller.log", false);
         file.Close();
			Write(ofp_hello(0));	
			Write(ofp_features_request(0));
		} //Controller


		void Write(byte[] msg) {
			logger.WriteLine("-------------WRITE-----------");	
			for(int i=0;i<msg.Length;i++) {
           	logger.Write("{0:X2} ", msg[i]);
           	if(i % 8 == 7) {
              logger.WriteLine("");
            }
			}
			logger.WriteLine("-----------------------------");	
			socket_connection.Write(msg);
		}

		void Receiving() {
			while(true) {
				byte[] header = new byte[OFP_HEADER_SIZE];
				int header_received = socket_connection.Read(header);
				logger.WriteLine("----------header----------------");
				logger.WriteLine("header_received:{0} header.Length:{1}" , header_received, header.Length);
				logger.WriteLine("version:{0} type:{1} length:{2} xid:{3}", header[0], (ofp_type) header[1], byte_reorder16(header, 2), byte_reorder32(header, 4));
            for(int i=0; i<header.Length; i++) {
               logger.Write("{0:X2} ",header[i]);
               if(i % 8 == 7) {
                  logger.WriteLine("");
               }
            }
				byte[] msg = new byte[byte_reorder16(header, 2)-OFP_HEADER_SIZE];
				if (byte_reorder16(header, 2) > OFP_HEADER_SIZE) {
					int msg_received = socket_connection.Read(msg);
					logger.WriteLine("----------msg-------------------");
					logger.WriteLine("msg_received:{0} header.Length:{1}", msg_received, msg.Length);
            	for(int i=0; i<msg.Length; i++) {
               	logger.Write("{0:X2} ",msg[i]);
               	if(i % 8 == 7) {
                  	logger.WriteLine("");
               	}
            	}
               logger.WriteLine("");
				}
				process_packet(ref header, ref msg);
				PacketInsert();
			}
		}

      void process_packet(ref byte[] header, ref byte[] msg) {
         switch ((ofp_type) header[1]) {
            case ofp_type.OFPT_HELLO:
         		if (ofp_version > header[0]) {
            		ofp_version = header[0];
            		logger.WriteLine("Minimum mutually support openflow protocol version is {0}. We change to version {0}", ofp_version);
         		}
               break;
            case ofp_type.OFPT_ERROR:
            	logger.WriteLine("OFPT_ERROR");
         		Environment.Exit(1);
               break;
            case ofp_type.OFPT_ECHO_REQUEST:
					uint32_t xid = byte_reorder32(header, 4);
					//socket_connection.Write(ofp_echo_reply(xid, ref msg));
					Write(ofp_echo_reply(xid, ref msg));
               break;
            case ofp_type.OFPT_FEATURES_REPLY:
               datapath_id = byte_reorder64(msg, 0);
               n_buffers = byte_reorder32(msg, 8);
               n_tables = msg[12];
               capabilities = (ofp_capabilities) byte_reorder32(msg, 16);
               action_type = (ofp_action_type) byte_reorder32(msg, 20);

               logger.WriteLine("-----------------SWITCH_FEATURES----------------------------");
               logger.WriteLine("datapath_id:{0:X}", datapath_id);
               logger.WriteLine("n_buffers:{0}", n_buffers);
               logger.WriteLine("n_tables:{0}", n_tables);
               logger.WriteLine("capabilities:{0}", capabilities);
               logger.WriteLine("actions:{0}", action_type);

               int number_of_phy_ports = ((int) byte_reorder16(header, 2) + OFP_HEADER_SIZE - OFP_SWITCH_FEATURES_SIZE)/OFP_PHY_PORT_SIZE;
               logger.WriteLine("number_of_phy_ports:{0}", number_of_phy_ports);

               for (int i=0;i<number_of_phy_ports;i++) {
                  phy_port_list.Add(new ofp_phy_port(ref msg, 24+i*OFP_PHY_PORT_SIZE));

                  logger.WriteLine("-----------------PORT INFO----------------------------------");
                  logger.WriteLine("port_no:{0}", phy_port_list[i].port_no);
                  logger.Write("hw_addr");
                  for(int j=0;j<OFP_ETH_ALEN;j++) {
                     logger.Write(":{0:X2}",phy_port_list[i].hw_addr[j]);
                  }
                  logger.Write("\n");
                  logger.Write("name:{0}", phy_port_list[i].name);
                  logger.Write("\n");
                  logger.WriteLine("config:{0}", phy_port_list[i].config);
                  logger.WriteLine("state:{0}", phy_port_list[i].state);
                  logger.WriteLine("curr:{0}", phy_port_list[i].curr);
                  logger.WriteLine("advertised:{0}", phy_port_list[i].advertised);
                  logger.WriteLine("supported:{0}", phy_port_list[i].supported);
                  logger.WriteLine("peer:{0}", phy_port_list[i].peer);
                  logger.WriteLine("------------------------------------------------------------");
               }
               logger.WriteLine("-----------------------------------------------------------------------------------------------------------");
					features_reply();
               break;
            case ofp_type.OFPT_PACKET_IN:
					Flow flow = new Flow(ref header, ref msg, logger);
            	mac_learning.learning(flow.dl_src, flow.in_port);


					if (flow.reason == ofp_packet_in_reason.OFPR_ACTION) {
						Console.WriteLine("packet captured whatever i want to do");
						PacketCapture(ref msg);
            	}


					ofp_port port;
					byte[] action;
					byte[] match;
            	switch (flow.eth_type) {
               	case Eth_type.ETH_TYPE_IP:
                  	port = mac_learning.search_by_mac(flow.dl_dst);
                  	action = ofp_action_output(port);
                  	match = flow.ofp_match();
                  	Write(ofp_flow_mod(flow.xid, match, 9, ofp_flow_mod_command.OFPFC_ADD, 60, 0, 9, flow.buffer_id, port, 0, action));
                  	//socket_connection.Write(ofp_flow_mod(match, 9, ofp_flow_mod_command.OFPFC_ADD, 60, 0, 9, flow.buffer_id, port, 0, action));
                  	break;
               	case Eth_type.ETH_TYPE_ARP:
                  	if (flow.nw_proto == 1) { //ARP REQUEST PACKET
                     	action = ofp_action_output(ofp_port.OFPP_FLOOD);
                     	//socket_connection.Write(ofp_packet_out(flow.xid, flow.buffer_id, flow.in_port, action));
                     	Write(ofp_packet_out(flow.xid, flow.buffer_id, flow.in_port, action));
                  	} else if (flow.nw_proto == 2) { //ARP REPLY
                     	port = mac_learning.search_by_mac(flow.dl_dst);
                     	action = ofp_action_output(port);
                     	match = flow.ofp_match();
                     	//socket_connection.Write(ofp_flow_mod(flow.xid, match, 9, ofp_flow_mod_command.OFPFC_ADD, 60, 0, 9, flow.buffer_id, port, 0, action));
                     	Write(ofp_flow_mod(flow.xid, match, 9, ofp_flow_mod_command.OFPFC_ADD, 60, 0, 9, flow.buffer_id, port, 0, action));
                  	}
                  	break;
               	case Eth_type.ETH_TYPE_RARP:
                  	action = ofp_action_output(ofp_port.OFPP_FLOOD);
                  	//socket_connection.Write(ofp_packet_out(flow.buffer_id, flow.in_port, action));
                  	Write(ofp_packet_out(flow.xid, flow.buffer_id, flow.in_port, action));
                  	break;
						case (Eth_type) 44:
							//don't know this protocol, broadcast anyway
                    	action = ofp_action_output(ofp_port.OFPP_FLOOD);
                    	//socket_connection.Write(ofp_packet_out(flow.buffer_id, flow.in_port, action));
                    	Write(ofp_packet_out(flow.xid, flow.buffer_id, flow.in_port, action));
							break;
               	case Eth_type.ETH_TYPE_IPV6:
                  	if (flow.dl_dst[0] == 0x33 && flow.dl_dst[1] == 0x33 ) { ;
                     	action = ofp_action_output(ofp_port.OFPP_FLOOD);
                     	//socket_connection.Write(flow.xid, ofp_packet_out(flow.buffer_id, flow.in_port, action));
                     	Write(ofp_packet_out(flow.xid, flow.buffer_id, flow.in_port, action));
                  	} else {
                     	logger.WriteLine("unknown ipv6 case");
                     	Environment.Exit(1);
                  	}
                  	break;
               	default:
                  	logger.WriteLine("unknown packet type");
                  	break;
            	}

               break;
            default:
               logger.WriteLine("Unknown packet from switch");
               Environment.Exit(1);
               break;
         }
      }

		public virtual void PacketCapture(ref byte[] msg) {
		}

		public virtual void features_reply() {
		}

		public virtual void PacketInsert() {
		}


		public void Run() {
			Thread receiving = new Thread(this.Receiving);
			receiving.Start();
			//int sent = socket_connection.Write(ofp_hello());
			//Console.WriteLine("sent {0}:", sent);
		}

		void Usage() {
         Console.WriteLine("usage description");
         Console.WriteLine("sudo ./Controller.exe [OPTION] [CONNECTION METHOD]" );
         Console.WriteLine("Active OpenFlow connection methods:");
         Console.WriteLine("  tcp:IP[:PORT]           PORT (default: 6633) at remote IP");
         Console.WriteLine("  ssl:IP[:PORT]           SSL PORT (default: 6633) at remote IP");
         Console.WriteLine("  unix:FILE               Unix domain socket named FILE");
         Console.WriteLine("Passive OpenFlow connection methods:");
         Console.WriteLine("  ptcp:[PORT][:IP]        listen to TCP PORT (default: 6633) on IP");
         Console.WriteLine("  pssl:[PORT][:IP]        listen for SSL on PORT (default: 6633) on IP");
         Console.WriteLine("  punix:FILE              listen on Unix domain socket FILE");
         Console.WriteLine("PKI configuration (required to use SSL):");
         Console.WriteLine("  -p, --private-key=FILE  file with private key");
         Console.WriteLine("  -c, --certificate=FILE  file with certificate for private key");
         Console.WriteLine("  -C, --ca-cert=FILE      file with peer CA certificate");
         Console.WriteLine("");
         Console.WriteLine("Daemon options:");
         Console.WriteLine("  --detach                run in background as daemon");
         Console.WriteLine("  --no-chdir              do not chdir to '/'");
         Console.WriteLine("  --pidfile[=FILE]        create pidfile (default: /usr/local/var/run/openvswitch/ovs-controller.pid)");
         Console.WriteLine("  --overwrite-pidfile     with --pidfile, start even if already running");
         Console.WriteLine("");
         Console.WriteLine("Logging options:");
         Console.WriteLine("  -v, --verbose=[SPEC]    set logging levels");
         Console.WriteLine("  -v, --verbose           set maximum verbosity level");
         Console.WriteLine("  --log-file[=FILE]       enable logging to specified FILE");
         Console.WriteLine("                          (default: /usr/local/var/log/openvswitch/ovs-controller.log)");
         Console.WriteLine("");
         Console.WriteLine("Other options:");
         Console.WriteLine("  -H, --hub               act as hub instead of learning switch");
         Console.WriteLine("  -n, --noflow            pass traffic, but don't add flows");
         Console.WriteLine("  --max-idle=SECS         max idle time for new flows");
         Console.WriteLine("  -N, --normal            use OFPP_NORMAL action");
         Console.WriteLine("  -w, --wildcards[=MASK]  wildcard (specified) bits in flows");
         Console.WriteLine("  -q, --queue=QUEUE-ID    OpenFlow queue ID to use for output");
         Console.WriteLine("  -Q PORT-NAME:QUEUE-ID   use QUEUE-ID for frames from PORT-NAME");
         Console.WriteLine("  --with-flows FILE       use the flows from FILE");
         Console.WriteLine("  --unixctl=SOCKET        override default control socket name");
         Console.WriteLine("  -h, --help              display this help message");
         Console.WriteLine("  -V, --version           display version information");
		}


		public static void Main(string[] args) {
			Controller controller = new Controller(args);
			controller.Run();
			Console.WriteLine("so far so good");
		}
	}
}
