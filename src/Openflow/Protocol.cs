using System;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;

using uint8_t = System.Byte;
using uint16_t = System.UInt16;
using uint32_t = System.UInt32;
using uint64_t = System.UInt64;

namespace Openflow {
	public class Protocol {

		protected uint8_t ofp_version = 0x01;

		protected const int OFP_HEADER_SIZE = 8;
		protected const int OFP_PHY_PORT_SIZE = 48;
		protected const int OFP_ETH_ALEN = 6;
		protected const int OFP_SWITCH_FEATURES_SIZE = 32;
		protected const int OFP_MAX_PORT_NAME_LEN = 16; 

      public enum Eth_type {
         ETH_TYPE_IP         = 0x0800,
         ETH_TYPE_ARP        = 0x0806,
         ETH_TYPE_VLAN       = 0x8100,
         ETH_TYPE_IPV6       = 0x86dd,
         ETH_TYPE_LACP       = 0x8809,
         ETH_TYPE_RARP       = 0x8035,
         ETH_TYPE_MPLS       = 0x8847,
         ETH_TYPE_MPLS_MCAST = 0x8848
      }

		public enum ofp_type {
			/* Immutable messages. */
			OFPT_HELLO,               /* Symmetric message */
			OFPT_ERROR,               /* Symmetric message */
			OFPT_ECHO_REQUEST,        /* Symmetric message */
			OFPT_ECHO_REPLY,          /* Symmetric message */
			OFPT_VENDOR,              /* Symmetric message */

			/* Switch configuration messages. */
			OFPT_FEATURES_REQUEST,    /* Controller/switch message */
			OFPT_FEATURES_REPLY,      /* Controller/switch message */
			OFPT_GET_CONFIG_REQUEST,  /* Controller/switch message */
			OFPT_GET_CONFIG_REPLY,    /* Controller/switch message */
			OFPT_SET_CONFIG,          /* Controller/switch message */

			/* Asynchronous messages. */
			OFPT_PACKET_IN,           /* Async message */
			OFPT_FLOW_REMOVED,        /* Async message */
			OFPT_PORT_STATUS,         /* Async message */

			/* Controller command messages. */
			OFPT_PACKET_OUT,          /* Controller/switch message */
			OFPT_FLOW_MOD,            /* Controller/switch message */
			OFPT_PORT_MOD,            /* Controller/switch message */

			/* Statistics messages. */
			OFPT_STATS_REQUEST,       /* Controller/switch message */
			OFPT_STATS_REPLY,         /* Controller/switch message */

			/* Barrier messages. */
			OFPT_BARRIER_REQUEST,     /* Controller/switch message */
			OFPT_BARRIER_REPLY,       /* Controller/switch message */

			/* Queue Configuration messages. */
			OFPT_QUEUE_GET_CONFIG_REQUEST,  /* Controller/switch message */
			OFPT_QUEUE_GET_CONFIG_REPLY     /* Controller/switch message */
		};

		/* Values for 'type' in ofp_error_message.  These values are immutable: they
		 * will not change in future versions of the protocol (although new values may
		 * be added). */
		public enum ofp_error_type {
			OFPET_HELLO_FAILED,         /* Hello protocol failed. */
			OFPET_BAD_REQUEST,          /* Request was not understood. */
			OFPET_BAD_ACTION,           /* Error in action description. */
			OFPET_FLOW_MOD_FAILED,      /* Problem modifying flow entry. */
			OFPET_PORT_MOD_FAILED,      /* Port mod request failed. */
			OFPET_QUEUE_OP_FAILED       /* Queue operation failed. */
		};

		/* Why is this packet being sent to the controller? */
		public enum ofp_packet_in_reason {
    		OFPR_NO_MATCH,          /* No matching flow. */
		    OFPR_ACTION             /* Action explicitly output to controller. */
		};

		/* Flow wildcards. */
		[Flags]
		public enum ofp_flow_wildcards {
			OFPFW_IN_PORT  = 1 << 0,  /* Switch input port. */
			OFPFW_DL_VLAN  = 1 << 1,  /* VLAN id. */
			OFPFW_DL_SRC   = 1 << 2,  /* Ethernet source address. */
			OFPFW_DL_DST   = 1 << 3,  /* Ethernet destination address. */
			OFPFW_DL_TYPE  = 1 << 4,  /* Ethernet frame type. */
			OFPFW_NW_PROTO = 1 << 5,  /* IP protocol. */
			OFPFW_TP_SRC   = 1 << 6,  /* TCP/UDP source port. */
			OFPFW_TP_DST   = 1 << 7,  /* TCP/UDP destination port. */

			/* IP source address wildcard bit count.  0 is exact match, 1 ignores the
			 * LSB, 2 ignores the 2 least-significant bits, ..., 32 and higher wildcard
			 * the entire field.  This is the *opposite* of the usual convention where
			 * e.g. /24 indicates that 8 bits (not 24 bits) are wildcarded. */
			OFPFW_NW_SRC_SHIFT = 8,
			OFPFW_NW_SRC_BITS = 6,
			OFPFW_NW_SRC_MASK = ((1 << OFPFW_NW_SRC_BITS) - 1) << OFPFW_NW_SRC_SHIFT,
			OFPFW_NW_SRC_ALL = 32 << OFPFW_NW_SRC_SHIFT,

			/* IP destination address wildcard bit count.  Same format as source. */
			OFPFW_NW_DST_SHIFT = 14,
			OFPFW_NW_DST_BITS = 6,
			OFPFW_NW_DST_MASK = ((1 << OFPFW_NW_DST_BITS) - 1) << OFPFW_NW_DST_SHIFT,
			OFPFW_NW_DST_ALL = 32 << OFPFW_NW_DST_SHIFT,

			OFPFW_DL_VLAN_PCP = 1 << 20,  /* VLAN priority. */
			OFPFW_NW_TOS = 1 << 21,  /* IP ToS (DSCP field, 6 bits). */

			/* Wildcard all fields. */
			OFPFW_ALL = ((1 << 22) - 1)
		};


		/* Capabilities supported by the datapath. */
		[Flags]
		public enum ofp_capabilities {
    		OFPC_FLOW_STATS     = 1 << 0,  /* Flow statistics. */
    		OFPC_TABLE_STATS    = 1 << 1,  /* Table statistics. */
    		OFPC_PORT_STATS     = 1 << 2,  /* Port statistics. */
    		OFPC_STP            = 1 << 3,  /* 802.1d spanning tree. */
    		OFPC_RESERVED       = 1 << 4,  /* Reserved, must be zero. */
    		OFPC_IP_REASM       = 1 << 5,  /* Can reassemble IP fragments. */
    		OFPC_QUEUE_STATS    = 1 << 6,  /* Queue statistics. */
    		OFPC_ARP_MATCH_IP   = 1 << 7   /* Match IP addresses in ARP pkts. */
		};


      [Flags]
      public enum ofp_action_type {
         OFPAT_OUTPUT,           /* Output to switch port. */
         OFPAT_SET_VLAN_VID,     /* Set the 802.1q VLAN id. */
         OFPAT_SET_VLAN_PCP,     /* Set the 802.1q priority. */
         OFPAT_STRIP_VLAN,       /* Strip the 802.1q header. */
         OFPAT_SET_DL_SRC,       /* Ethernet source address. */
         OFPAT_SET_DL_DST,       /* Ethernet destination address. */
         OFPAT_SET_NW_SRC,       /* IP source address. */
         OFPAT_SET_NW_DST,       /* IP destination address. */
         OFPAT_SET_NW_TOS,       /* IP ToS (DSCP field, 6 bits). */
         OFPAT_SET_TP_SRC,       /* TCP/UDP source port. */
         OFPAT_SET_TP_DST,       /* TCP/UDP destination port. */
         OFPAT_ENQUEUE,          /* Output to queue.  */
         OFPAT_VENDOR = 0xffff
      };

      /* Flags to indicate behavior of the physical port.  These flags are
       * used in ofp_phy_port to describe the current configuration.  They are
       * used in the ofp_port_mod message to configure the port's behavior.
       */
      [Flags]
      public enum ofp_port_config {
          OFPPC_PORT_DOWN    = 1 << 0,  /* Port is administratively down. */

          OFPPC_NO_STP       = 1 << 1,  /* Disable 802.1D spanning tree on port. */
          OFPPC_NO_RECV      = 1 << 2,  /* Drop all packets except 802.1D spanning
                                           tree packets. */
          OFPPC_NO_RECV_STP  = 1 << 3,  /* Drop received 802.1D STP packets. */
          OFPPC_NO_FLOOD     = 1 << 4,  /* Do not include this port when flooding. */
          OFPPC_NO_FWD       = 1 << 5,  /* Drop packets forwarded to port. */
          OFPPC_NO_PACKET_IN = 1 << 6   /* Do not send packet-in msgs for port. */
      };

      /* Current state of the physical port.  These are not configurable from
       * the controller.
       */
      [Flags]
      public enum ofp_port_state {
          OFPPS_LINK_DOWN   = 1 << 0, /* No physical link present. */

          /* The OFPPS_STP_* bits have no effect on switch operation.  The
           * controller must adjust OFPPC_NO_RECV, OFPPC_NO_FWD, and
           * OFPPC_NO_PACKET_IN appropriately to fully implement an 802.1D spanning
           * tree. */
          OFPPS_STP_LISTEN  = 0 << 8, /* Not learning or relaying frames. */
          OFPPS_STP_LEARN   = 1 << 8, /* Learning but not relaying frames. */
          OFPPS_STP_FORWARD = 2 << 8, /* Learning and relaying frames. */
          OFPPS_STP_BLOCK   = 3 << 8, /* Not part of spanning tree. */
          OFPPS_STP_MASK    = 3 << 8  /* Bit mask for OFPPS_STP_* values. */
      };

      /* Features of physical ports available in a datapath. */
      [Flags]
      public enum ofp_port_features {
         OFPPF_10MB_HD    = 1 << 0,  /* 10 Mb half-duplex rate support. */
         OFPPF_10MB_FD    = 1 << 1,  /* 10 Mb full-duplex rate support. */
         OFPPF_100MB_HD   = 1 << 2,  /* 100 Mb half-duplex rate support. */
         OFPPF_100MB_FD   = 1 << 3,  /* 100 Mb full-duplex rate support. */
         OFPPF_1GB_HD     = 1 << 4,  /* 1 Gb half-duplex rate support. */
         OFPPF_1GB_FD     = 1 << 5,  /* 1 Gb full-duplex rate support. */
         OFPPF_10GB_FD    = 1 << 6,  /* 10 Gb full-duplex rate support. */
         OFPPF_COPPER     = 1 << 7,  /* Copper medium. */
         OFPPF_FIBER      = 1 << 8,  /* Fiber medium. */
         OFPPF_AUTONEG    = 1 << 9,  /* Auto-negotiation. */
         OFPPF_PAUSE      = 1 << 10, /* Pause. */
         OFPPF_PAUSE_ASYM = 1 << 11  /* Asymmetric pause. */
      };

      /* Port numbering.  Physical ports are numbered starting from 1. */
      public enum ofp_port {
         /* Maximum number of physical switch ports. */
         OFPP_MAX = 0xff00,

         /* Fake output "ports". */
         OFPP_IN_PORT    = 0xfff8,  /* Send the packet out the input port.  This
                                       virtual port must be explicitly used
                                       in order to send back out of the input
                                       port. */
         OFPP_TABLE      = 0xfff9,  /* Perform actions in flow table.
                                       NB: This can only be the destination
                                       port for packet-out messages. */
         OFPP_NORMAL     = 0xfffa,  /* Process with normal L2/L3 switching. */
         OFPP_FLOOD      = 0xfffb,  /* All physical ports except input port and
                                       those disabled by STP. */
         OFPP_ALL        = 0xfffc,  /* All physical ports except input port. */
         OFPP_CONTROLLER = 0xfffd,  /* Send to controller. */
         OFPP_LOCAL      = 0xfffe,  /* Local openflow "port". */
         OFPP_NONE       = 0xffff   /* Not associated with a physical port. */
      };

      public enum ofp_flow_mod_command {
         OFPFC_ADD,              /* New flow. */
         OFPFC_MODIFY,           /* Modify all matching flows. */
         OFPFC_MODIFY_STRICT,    /* Modify entry strictly matching wildcards */
         OFPFC_DELETE,           /* Delete all matching flows. */
         OFPFC_DELETE_STRICT    /* Strictly match wildcards and priority. */
      };

      public enum ofp_flow_mod_flags {
         OFPFF_SEND_FLOW_REM = 1 << 0,  /* Send flow removed message when flow
                                         * expires or is deleted. */
         OFPFF_CHECK_OVERLAP = 1 << 1,  /* Check for overlapping entries first. */
         OFPFF_EMERG         = 1 << 2   /* Remark this is for emergency. */
      };


		/* Description of a physical port */
		public class ofp_phy_port {
			public ofp_port port_no;
			public uint8_t[] hw_addr;
			public string name;/* Null-terminated */
	
			public ofp_port_config config;        /* Bitmap of OFPPC_* flags. */
			public ofp_port_state state;         /* Bitmap of OFPPS_* flags. */

			/* Bitmaps of OFPPF_* that describe features.  All bits zeroed if
			 * unsupported or unavailable. */
			public ofp_port_features curr;          /* Current features. */
			public ofp_port_features advertised;    /* Features being advertised by the port. */
			public ofp_port_features supported;     /* Features supported by the port. */
			public ofp_port_features peer;          /* Features advertised by peer. */
			public ofp_phy_port(ref byte[] msg, int offset) {
         	port_no = (ofp_port) byte_reorder16(msg, offset);
				hw_addr = new uint8_t[OFP_ETH_ALEN];
            Array.Copy(msg, offset+2, hw_addr, 0, OFP_ETH_ALEN);
            string s = Encoding.Default.GetString(msg, offset+8, OFP_MAX_PORT_NAME_LEN);
            name = s.Substring(0, s.IndexOf((char) 0));
            config = (ofp_port_config)  byte_reorder32(msg, offset+24);
            state = (ofp_port_state) byte_reorder32(msg, offset+28);
            curr = (ofp_port_features) byte_reorder32(msg, offset+32);
            advertised = (ofp_port_features) byte_reorder32(msg, offset+36);
            supported = (ofp_port_features) byte_reorder32(msg, offset+40);
            peer = (ofp_port_features) byte_reorder32(msg, offset+44);
			}
		};

		void uint16_to_bytes(uint16_t from, ref byte[] to, int offset) {
			to[offset] = (uint8_t) ((from >> 8) & 0xff);
			to[offset+1] = (uint8_t) (from & 0xff);
		}

		void uint32_to_bytes(uint32_t from, ref byte[] to, int offset) {
			to[offset] = (uint8_t) ((from >> 24) & 0xff);
			to[offset+1] = (uint8_t) ((from >> 16) & 0xff);
			to[offset+2] = (uint8_t) ((from >> 8) & 0xff);
			to[offset+3] = (uint8_t) (from & 0xff);
		}

		void uint64_to_bytes(uint64_t from, ref byte[] to, int offset) {
			to[offset] = (uint8_t) ((from >> 56) & 0xff);
			to[offset+1] = (uint8_t) ((from >> 48) & 0xff);
			to[offset+2] = (uint8_t) ((from >> 40) & 0xff);
			to[offset+3] = (uint8_t) ((from >> 32)& 0xff);
			to[offset+4] = (uint8_t) ((from >> 24) & 0xff);
			to[offset+5] = (uint8_t) ((from >> 16) & 0xff);
			to[offset+6] = (uint8_t) ((from >> 8) & 0xff);
			to[offset+7] = (uint8_t) (from & 0xff);
		}


      //C# provides library for network to host byte ordering, 
      //but not for the unsigned types. 
      protected static uint16_t byte_reorder(uint16_t n) {
         byte[] bytes = BitConverter.GetBytes(n);
         Array.Reverse(bytes);
         return BitConverter.ToUInt16(bytes, 0);
      }

      protected static uint32_t byte_reorder(uint32_t n) {
         byte[] bytes = BitConverter.GetBytes(n);
         Array.Reverse(bytes);
         return BitConverter.ToUInt32(bytes, 0);
      }

      protected static uint64_t byte_reorder(uint64_t n) {
         byte[] bytes = BitConverter.GetBytes(n);
         Array.Reverse(bytes);
         return BitConverter.ToUInt64(bytes, 0);
      }


      protected static uint16_t byte_reorder16(byte[] bytes, int offset) {
         byte[] b = new byte[2];
         Array.Copy(bytes, offset, b, 0, 2);
         Array.Reverse(b);
         return BitConverter.ToUInt16(b, 0);
      }

      protected static uint32_t byte_reorder32(byte[] bytes, int offset) {
         byte[] b = new byte[4];
         Array.Copy(bytes, offset, b, 0, 4);
         Array.Reverse(b);
         return BitConverter.ToUInt32(b, 0);
      }

      protected static uint64_t byte_reorder64(byte[] bytes, int offset) {
         byte[] b = new byte[8];
         Array.Copy(bytes, offset, b, 0, 8);
         Array.Reverse(b);
         return BitConverter.ToUInt64(b, 0);
      }

      protected string wtoi(uint32_t addr) {
         IPAddress ip = new IPAddress(addr);
         return ip.ToString();
      }

      public static bool mac_compare(byte[] addr1, byte[] addr2) {
         if (addr1.Length != OFP_ETH_ALEN || addr2.Length != OFP_ETH_ALEN) {
            Environment.Exit(1);
            return false;
         } else {
            for(int i=0; i<OFP_ETH_ALEN; i++) {
               if (addr1[i] != addr2[i]) {
                  return false;
               }
            }
            return true;
         }
      }
		
      protected byte[] ofp_hello(uint32_t xid) {
         byte[] header = new byte[OFP_HEADER_SIZE];
         header[0] = ofp_version;
         header[1] = (uint8_t) ofp_type.OFPT_HELLO;
			uint16_to_bytes(OFP_HEADER_SIZE, ref header, 2);
			uint32_to_bytes(xid, ref header, 4);
         return header;
      }


		protected byte[] ofp_features_request(uint32_t xid) {
			byte[] ret = new byte[OFP_HEADER_SIZE];
         ret[0] = ofp_version;
         ret[1] = (uint8_t) ofp_type.OFPT_FEATURES_REQUEST;
			uint16_to_bytes(OFP_HEADER_SIZE, ref ret, 2);
			uint32_to_bytes(xid, ref ret, 4);
			return ret;
		}

      protected byte[] ofp_echo_reply(uint32_t xid, ref byte[] msg) {
         byte[] ret = new byte[OFP_HEADER_SIZE + msg.Length];
         ret[0] = ofp_version;
         ret[1] = (uint8_t) ofp_type.OFPT_ECHO_REPLY;
			uint16_to_bytes(OFP_HEADER_SIZE, ref ret, 2);
			uint32_to_bytes(xid, ref ret, 4);
			Array.Copy(msg, 0, ret, OFP_HEADER_SIZE, msg.Length); 
			return ret;
      }

		protected byte[] ofp_action_output(ofp_port port) {
			byte[] ret = new byte[8];
			uint16_to_bytes((uint16_t) ofp_action_type.OFPAT_OUTPUT, ref ret, 0);
			uint16_to_bytes((uint16_t) 8, ref ret, 2);
			uint16_to_bytes((uint16_t) port, ref ret, 4);
			uint16_to_bytes((uint16_t) 0, ref ret, 6);
			return ret;
		}

		public byte[] ofp_packet_out(uint32_t xid, uint32_t buffer_id, ofp_port in_port, byte[] actions) {
			byte[] ret = new byte[16+actions.Length];
			ret[0] = ofp_version;
			ret[1] = (uint8_t) ofp_type.OFPT_PACKET_OUT;
			uint16_to_bytes((uint16_t) (16 + actions.Length), ref ret, 2);
			uint32_to_bytes(xid, ref ret, 4);
			uint32_to_bytes(buffer_id, ref ret, 8);
			uint16_to_bytes((uint16_t) in_port, ref ret, 12);
			uint16_to_bytes((uint16_t) actions.Length, ref ret, 14);
			Array.Copy(actions, 0, ret, 16, actions.Length); 
			return ret;
		}

		public byte[] ofp_match(uint32_t wildcards, ofp_port in_port, byte[] dl_src, byte[] dl_dst, uint16_t dl_vlan, uint8_t dl_vlan_pcp, Eth_type dl_type, uint8_t nw_tos, uint8_t nw_proto, IPAddress nw_src, IPAddress nw_dst, uint16_t tp_src, uint16_t tp_dst) {
			byte[] ret = new byte[40];
			uint32_to_bytes(wildcards, ref ret, 0);
			uint16_to_bytes((uint16_t) in_port, ref ret, 4);
			Array.Copy(dl_src, 0, ret, 6, OFP_ETH_ALEN);
			Array.Copy(dl_dst, 0, ret, 12, OFP_ETH_ALEN);
			uint16_to_bytes(dl_vlan, ref ret, 18);
			ret[20]=dl_vlan_pcp;
			uint16_to_bytes((uint16_t) dl_type, ref ret, 22);
			ret[24] = nw_tos;
			ret[25] = nw_proto;
			//uint32_to_bytes(nw_src, ref ret, 28);
			//uint32_to_bytes(nw_dst, ref ret, 32);
			Array.Copy(nw_src.GetAddressBytes(), 0, ret, 28, nw_src.GetAddressBytes().Length); 
			Array.Copy(nw_dst.GetAddressBytes(), 0, ret, 32, nw_dst.GetAddressBytes().Length); 
			uint16_to_bytes(tp_src, ref ret, 36);
			uint16_to_bytes(tp_dst, ref ret, 38);
			return ret;
		}

		public byte[] ofp_flow_mod(uint32_t xid, byte[] match, uint64_t cookie, ofp_flow_mod_command command, uint16_t idle_timeout, uint16_t hard_timeout, uint16_t priority, uint32_t buffer_id, ofp_port out_port, ofp_flow_mod_flags flags, byte[] actions) {
			if (match.Length != 40) {
				return null;
			}
			byte[] ret = new byte[72+actions.Length];
			ret[0] = ofp_version;
			ret[1] = (uint8_t) ofp_type.OFPT_FLOW_MOD;
			uint16_to_bytes((uint16_t) (72 + actions.Length), ref ret, 2);
			uint32_to_bytes(xid, ref ret, 4);
			Array.Copy(match, 0, ret, 8, 40);
			uint64_to_bytes(cookie, ref ret, 48);
			uint16_to_bytes((uint16_t) command, ref ret, 56);
			uint16_to_bytes(idle_timeout, ref ret, 58);
			uint16_to_bytes(hard_timeout, ref ret, 60);
			uint16_to_bytes(priority, ref ret, 62);
			uint32_to_bytes(buffer_id, ref ret, 64);
			uint16_to_bytes((uint16_t) out_port, ref ret, 68);
			uint16_to_bytes((uint16_t) flags, ref ret, 70);
			Array.Copy(actions, 0, ret, 72, actions.Length);
			return ret;
		}

      public class Logger {

         string log_file_name;

         public Logger(string log_file_name) {
            this.log_file_name = log_file_name;
            Console.WriteLine("Log file name is : {0}", this.log_file_name);
         }

         public void WriteLine(string line, params object[] lines) {
            StreamWriter file = new StreamWriter(log_file_name, true);
            file.WriteLine(line, lines);
            file.Close();
         }

         public void Write(string line, params object[] lines) {
            StreamWriter file = new StreamWriter(log_file_name, true);
            file.Write(line, lines);
            file.Close();
         }
      }

	}
}
