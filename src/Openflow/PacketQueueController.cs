using System;
using System.Collections.Generic;

namespace Openflow {
	public class PacketQueueController : Controller {

		ofp_port tap_port;
		Queue<byte[]> send_queue;
		Queue<byte[]> rcv_queue;

		public PacketQueueController(string[] args, Queue<byte[]> send_queue, Queue<byte[]> rcv_queue) : base(args) { 
			this.send_queue = send_queue;
			this.rcv_queue = rcv_queue;
		}

		public override void PacketCapture(ref byte[] msg) {
			if (send_queue == null) {
				base.PacketCapture(ref msg);
				return;
			}
			send_queue.Queue(msg);
		}

		public override void PacketInsert() {
			if (rcv_queue == null) {
				return base.PacketInsert();
			}

			if (rcv_queue != null && tap_port != null) {
				byte[] data = rcv_queue.DeQueue();
				byte[] action = ofp_action_out(tap_port);
				byte[] data_action = new byte[data.Length + action.Length];
				data_action = Array.Copy(data, 0, data_action, action.Length, data.Length);
				data_action = Array.Copy(action, 0, data_action, 0, action.Length);
				byte[] send = ofp_packet_out(0, -1, tap_port, action);
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

		public static void Main(string[] arg) {
			Queue<byte[]> queue = new Queue<byte[]>();
			PacketQueueController controller0 = new PacketQueueController("punix:/var/run/openvswitch/br0.controller",queue,null); 
			PacketQueueController controller1 = new PacketQueueController("punix:/var/run/openvswitch/br1.controller",null,queue); 
			controller0.Run();
			controller1.Run();
			Console.WriteLine("so far so good");
		}
	}
}
