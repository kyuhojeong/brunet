using System;
using System.Linq;
using System.Net;
using System.Text;

using uint8_t = System.Byte;
using uint16_t = System.UInt16;
using uint32_t = System.UInt32;
using uint64_t = System.UInt64;

namespace Openflow {
	class Flow : Protocol {

		//ofp_header
		public ofp_type type;
		public uint16_t length; //length of packet including header
		public uint32_t xid;

		//ofp_error_msg
		public ofp_error_type ofp_error_t;
		public uint16_t ofp_error_code;

		//ofp_packet_in
		public uint32_t buffer_id;
		public uint16_t total_len; //length of frame (only frame except ofp header / ofp packet in header)
		public ofp_port in_port;
		public ofp_packet_in_reason reason;

		//l2 
		public byte[] dl_dst = new byte[OFP_ETH_ALEN];
		public byte[] dl_src = new byte[OFP_ETH_ALEN];
		//public uint32_t nw_src;
		//public uint32_t nw_dst;
		public IPAddress nw_src;
		public IPAddress nw_dst;
		public Eth_type eth_type;
		public byte[] arp_sha = new byte[OFP_ETH_ALEN];
		public byte[] arp_tha = new byte[OFP_ETH_ALEN];

		public ofp_flow_wildcards wildcards;
		public uint8_t nw_tos; //DSCP(Different Service Code Point, Type of Service)
		public uint16_t tp_src;
		public uint16_t tp_dst;
		public uint16_t nw_proto; // network layer protocol OR ARP operation protocol 1 request 2 reply

		//802.1Q
		public uint16_t dl_vlan; 
		public uint8_t dl_vlan_pcp;

		//IPv4 Field
		uint8_t ipv4_version;
		uint8_t ihl; 
		uint16_t total_length;

		//int offset;
		int l2_offset;
		int l3_offset;
		int l4_offset;


		public Flow(ref byte[] header, ref byte[] msg, Logger logger) {
		   ofp_version = header[0];
		   type = (ofp_type) header[1];
		   length = byte_reorder16(header, 2);
		   xid = byte_reorder32(header, 4);

		   wildcards = 0;
		   logger.WriteLine("-----------------------------------------------FLOW--------------------------------------------------------");
		   logger.WriteLine("FLOW ofp_header version:{0} type:{1} length:{2} xid:{3}", ofp_version, type, length, xid);

		   switch(type) {
		      case ofp_type.OFPT_HELLO:
		         logger.WriteLine("-----------------------------------------------------------------------------------------------------------");
		         return;
		      case ofp_type.OFPT_ERROR:
		         ofp_error_t = (ofp_error_type) byte_reorder16(msg, 0);
		         ofp_error_code = byte_reorder16(msg, 2);
		         logger.WriteLine("FLOW OFPT_ERROR | type:{0} code:{1} ", ofp_error_t, ofp_error_code);
		         logger.WriteLine("-----------------------------------------------------------------------------------------------------------");
		         return;
		      case ofp_type.OFPT_ECHO_REQUEST:
		         logger.WriteLine("-----------------------------------------------------------------------------------------------------------");
		         return;
				case ofp_type.OFPT_PACKET_IN:
		         buffer_id = byte_reorder32(msg, 0);
		         total_len = byte_reorder16(msg, 4);
		         in_port = (ofp_port) byte_reorder16(msg, 6);
		         reason = (ofp_packet_in_reason) msg[8];
		         logger.WriteLine("buffer_id:{0:x} total_len:{1} in_port:{2} reason:{3}", buffer_id, total_len, in_port, reason);
		         logger.WriteLine("");

		         // Link Layer
		         l2_offset = 10;
		         Array.Copy(msg, l2_offset, dl_dst, 0, OFP_ETH_ALEN);
		         Array.Copy(msg, l2_offset+OFP_ETH_ALEN, dl_src, 0, OFP_ETH_ALEN);

		         //802.11Q and VLAN tag is not yet implemented 
		         if (byte_reorder16(msg, l2_offset+2*OFP_ETH_ALEN) == (uint16_t) Eth_type.ETH_TYPE_VLAN ) {
		            dl_vlan = (uint16_t) (BitConverter.ToUInt16(msg, l2_offset+2*OFP_ETH_ALEN+2) & 0x0fff);
		            dl_vlan_pcp = (uint8_t) (BitConverter.ToUInt16(msg, l2_offset+2*OFP_ETH_ALEN+2) >> 13);
		            eth_type = (Eth_type) byte_reorder16(msg, l2_offset+2*OFP_ETH_ALEN+4);
		            l3_offset = l2_offset+2*OFP_ETH_ALEN+6;
		         } else {
		            eth_type = (Eth_type) byte_reorder16(msg, l2_offset+2*OFP_ETH_ALEN);
		            l3_offset = l2_offset+2*OFP_ETH_ALEN+2;
		         }
		         logger.WriteLine("dl_src:{0:X} dl_dst:{1:X}", BitConverter.ToString(dl_src), BitConverter.ToString(dl_dst));
		         logger.WriteLine("eth_type:{0}", eth_type);
		         switch (eth_type) {
		            case Eth_type.ETH_TYPE_RARP:
		               break;
		            case Eth_type.ETH_TYPE_ARP:
		               this.wildcards = ofp_flow_wildcards.OFPFW_TP_SRC | ofp_flow_wildcards.OFPFW_TP_DST | ofp_flow_wildcards.OFPFW_DL_VLAN | ofp_flow_wildcards.OFPFW_DL_VLAN_PCP;
		               if ( byte_reorder16(msg, l3_offset) == 1 && 
									byte_reorder16(msg, l3_offset+2)  == (uint16_t) Eth_type.ETH_TYPE_IP && 
									msg[l3_offset+4] == OFP_ETH_ALEN && 
									msg[l3_offset+5] == 4 && 
									byte_reorder16(msg, l3_offset+6) <= 0xff) { //referred to flow.c flow_extract
		                  nw_proto = byte_reorder16(msg, l3_offset+6);
		                  //nw_src = new IPAddress(byte_reorder32(msg, l3_offset+14));
		                  //nw_dst = new IPAddress(byte_reorder32(msg, l3_offset+24));
		                  //nw_src = new IPAddress(msg.Skip(l3_offset+14).Take(4).ToArray());
		                  //nw_dst = new IPAddress(msg.Skip(l3_offset+24).Take(4).ToArray());
								nw_src = new IPAddress(BitConverter.ToUInt32(msg, l3_offset+14));
								nw_dst = new IPAddress(BitConverter.ToUInt32(msg, l3_offset+24));

		                  Array.Copy(msg, l3_offset+8, arp_sha, 0, OFP_ETH_ALEN);
		                  Array.Copy(msg, l3_offset+18, arp_tha, 0, OFP_ETH_ALEN);
		               }
		               logger.WriteLine("nw_proto:{0:X} nw_src:{1:X} nw_dst:{2:X} arp_sha:{3:X} arp_tha", nw_proto, nw_src, nw_dst, arp_sha, arp_tha);
		               break;
						case Eth_type.ETH_TYPE_IP:
		               this.wildcards = ofp_flow_wildcards.OFPFW_DL_VLAN | ofp_flow_wildcards.OFPFW_DL_VLAN_PCP;

		               //Extract_IP_ETH_HEADER(ref msg);
		               ipv4_version = (byte) (msg[l3_offset] >> 4);
		               ihl = (byte) (msg[l3_offset] & 0x0f);
							nw_tos = (byte) (msg[l3_offset+1] >> 2); 
		               total_length = byte_reorder16(msg, l3_offset+2);
		               nw_proto = msg[l3_offset+9];

		               //TCP/UDP
		               //nw_src = new IPAddress(byte_reorder32(msg, l3_offset+12));
		               //nw_dst = new IPAddress(byte_reorder32(msg, l3_offset+16));
		               //nw_src = new IPAddress(msg.Skip(l3_offset+12).Take(4));
		               //nw_dst = new IPAddress(msg.Skip(l3_offset+16).Take(4));
		               nw_src = new IPAddress(BitConverter.ToUInt32(msg, l3_offset+12));
		               nw_dst = new IPAddress(BitConverter.ToUInt32(msg, l3_offset+16));
					
		               logger.WriteLine("version:{0} ihl:{1}", ipv4_version, ihl);
		               logger.WriteLine("nw_tos(Type of Service):{0} total_length:{1} protocol:{2}", nw_tos, total_length, nw_proto);
		               if (ihl > 5) {
		                  l4_offset = l3_offset + 24;
		               } else {
		                  l4_offset = l3_offset + 20;
		               }
		               logger.WriteLine("l3_offset:{0}, l4_offset:{1}", l3_offset, l4_offset);
		               tp_src = byte_reorder16(msg, l4_offset);
		               tp_dst = byte_reorder16(msg, l4_offset+2);

		               logger.WriteLine("protocol:{0:X} ", nw_proto);
		               logger.WriteLine("nw_src:{0} nw_dst:{1} tp_src:{2} tp_dst:{3}", nw_src.ToString(), nw_dst.ToString(), tp_src, tp_dst);
		               break;
		            case Eth_type.ETH_TYPE_IPV6:
		               logger.WriteLine("Eth_type.ETH_TYPE_IPV6:");
		               break;
						case (Eth_type) 44:
		               logger.WriteLine("ethernet type 44 0x2c ipv6 framenet ");
							break;
						
		            default:
		               logger.WriteLine("FATAL: UNKNOWN ETHERNET HEADER TYPE");
		               Environment.Exit(1);
		               break;
		         }
		         break;
		      default:
		         logger.WriteLine("Unknown packet from switch");
		         Environment.Exit(1);
		         break;

		   }
		   logger.WriteLine("-----------------------------------------------------------------------------------------------------------");
		}

      public byte[] ofp_match() {


//ofp_match(uint32_t wildcards, uint16_t in_port, byte[] dl_src, byte[] dl_dst, uint16_t dl_vlan, uint8_t dl_vlan_pcp, Eth_type dl_type, uint8_t nw_tos, uint8_t nw_proto, uint32_t nw_src, uint32_t nw_dst, uint16_t tp_src, uint16_t tp_dst)

			return ofp_match((uint32_t) this.wildcards, this.in_port, this.dl_src, this.dl_dst, this.dl_vlan, this.dl_vlan_pcp, this.eth_type, this.nw_tos, (uint8_t) this.nw_proto, this.nw_src, this.nw_dst, this.tp_src, this.tp_dst);
		}

	}
}
