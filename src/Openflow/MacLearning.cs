using System;
using System.Collections.Generic;
using uint8_t = System.Byte;
using uint16_t = System.UInt16;
using uint32_t = System.UInt32;
using uint64_t = System.UInt64;

namespace Openflow {
   class MacLearning : Protocol {

		Logger logger;

		public MacLearning(Logger logger) {
			this.logger = logger;
		}

		//class Entry {
		public struct Entry {
		   public byte[] mac_addr;// = new byte[OFP_ETH_ALEN];
		   //public uint16_t port;
		   public ofp_port port;
		}


		List<Entry> list = new List<Entry>();

		public void show() {
		   logger.WriteLine("----------mac learning-------------");
		   foreach (Entry e in list) {
		      logger.WriteLine("{0} \t{1}", BitConverter.ToString(e.mac_addr), e.port);
		   }
		   logger.WriteLine("----------mac learning-------------");
		}


		public void learning(byte[] addr, ofp_port port) {
		   if (list.Exists(e => mac_compare(addr, e.mac_addr))) {
		   	Entry entry = list.Find(e => mac_compare(addr, e.mac_addr));

	      	//mac address with different port number -> update to new port number
	       	if ( entry.port != port ) {
	          	//list.Remove(e => e.mac_addr.Equals(addr));
	          	list.Remove(entry);
	          	//Entry entry = new Entry();
	          	entry.port = port;
	          	list.Add(entry);
	       	}
	    	} else {
	       	Entry entry = new Entry();
	       	entry.mac_addr = addr;
	       	entry.port = port;
	       	list.Add(entry);
	    	}
	    	show();
	 	}

		public void insert(byte[] addr, ofp_port port) {
			Entry entry = new Entry();
		   entry.mac_addr = addr;
		   entry.port = port;
		   list.Add(entry);
		}

		public ofp_port search_by_mac(byte[] addr) {
		   Entry entry = list.Find(e => mac_compare(e.mac_addr, addr));
			if (entry.port == 0) {
				entry.port = ofp_port.OFPP_FLOOD;
			}
			if ( entry.mac_addr != null) {
		   	logger.WriteLine("search_by_mac addr:{0} entry.port:{1}", BitConverter.ToString(entry.mac_addr), entry.port);
			}
		   return entry.port;
		}
	}
}
