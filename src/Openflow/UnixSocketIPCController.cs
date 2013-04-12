using System;
using System.Collections.Generic;

using uint8_t = System.Byte;
using uint16_t = System.UInt16;
using uint32_t = System.UInt32;
using uint64_t = System.UInt64;

namespace Openflow {

	public class UnixSocketIPCServerController : Controller { 

		SocketConnection socket_connection; 

		public UnixSocketIPCServerController(string[] args, string addr) : base(args) { 
			socket_connection = new SocketConnection(true, addr); 
		}

		public override void PacketCapture(ref byte[] msg) {
			socket_connection.Write(msg);
		}
	}
	
	public class UnixSocketIPCClientController : Controller {

		ofp_port tap_port = ofp_port.OFPP_NONE;
		SocketConnection socket_connection; 

		public UnixSocketIPCClientController(string[] args, string addr) : base(args) { 
			socket_connection = new SocketConnection(false, addr); 
		}

		public override void PacketInsert() {
			if (tap_port != ofp_port.OFPP_NONE) {
				byte[] buffer = new byte[1500];
				int received = socket_connection.Read(buffer);
				byte[] action = ofp_action_output(tap_port);
				byte[] data_action = new byte[action.Length + received];
				Array.Copy(buffer, 0, data_action, action.Length, received);
				Array.Copy(action, 0, data_action, 0, action.Length);
				byte[] send = ofp_packet_out(0, (uint32_t) 0xffffffff, tap_port, data_action);
				socket_connection.Write(send);
			}
		}

		public override void features_reply() {
			for(int i=0; i<phy_port_list.Count; i++) {
				if (phy_port_list[i].name =="tapdevice") {
					tap_port = phy_port_list[i].port_no;  
				}
			}
		}

	}

	public class UnixSocketIPCController {
		public static void Main(string[] args) {
			string[] br0_controller = new string[1];
			string[] br1_controller = new string[1];
			br0_controller[0] = "punix:/var/run/openvswitch/br0.controller";
			br1_controller[0] = "punix:/var/run/openvswitch/br1.controller";
			UnixSocketIPCServerController controller0 = new UnixSocketIPCServerController(br0_controller,"./local_socket"); 
			UnixSocketIPCClientController controller1 = new UnixSocketIPCClientController(br1_controller,"./local_socket"); 
			controller0.Run();
			controller1.Run();
			Console.WriteLine("so far so good");
		}
	}
}
