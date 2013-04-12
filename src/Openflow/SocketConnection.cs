using System;
using System.Net;
using System.Net.Sockets;
using Mono.Unix;
using Mono.Unix.Native;

namespace Openflow {
	public class SocketConnection {

		EndPoint endPoint;  
		Socket listener, handler;
		public SocketConnection(bool is_tcp, bool is_active, string addr) {
      	if (is_tcp) {
            //TCP socket
         } else {
            //Unix socket domain 
            if (is_active) {
               //active, client 
            } else {
               //pasive, server
               try {
						Console.WriteLine("addr:{0}", addr);
                 	Syscall.unlink(addr);
                  endPoint = new UnixEndPoint(addr);
                  listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.IP);
                  listener.Bind(endPoint);
                  listener.Listen(10);
                  handler = listener.Accept();
               } catch (Exception e) {
                  Console.WriteLine("Connection failed to {0}: exception {1}", addr, e);
               }
            }
         }
		}

		//Socket interface for Datagram Type Unix Socket Domain
		public SocketConnection(bool is_active, string addr) {
			if (is_active) {
         	try {
					Console.WriteLine("[Server] Datagram UnixSocketDomain addr:{0}", addr);
            	Syscall.unlink(addr);
            	endPoint = new UnixEndPoint(addr);
            	//listener = new Socket(AddressFamily.Unix, SocketType.Dgram, ProtocolType.IP);
            	//listener.Bind(endPoint);
            	handler = new Socket(AddressFamily.Unix, SocketType.Dgram, ProtocolType.IP);
            	handler.Bind(endPoint);
            	//listener.Listen(10);
            	//handler = listener.Accept();
         	} catch (Exception e) {
            	Console.WriteLine("Connection failed to {0}: exception {1}", addr, e);
         	}
			} else {
					Console.WriteLine("[Client] Datagram UnixSocketDomain addr:{0}", addr);
            	endPoint = new UnixEndPoint(addr);
            	handler = new Socket(AddressFamily.Unix, SocketType.Dgram, ProtocolType.IP);
					//handler.Connect(endPoint);
			}	
		}

		public int Write(byte[] msg) {
			return handler.Send(msg, msg.Length, 0);
		}

		public int Read(byte[] msg) {
         return handler.Receive(msg, msg.Length, SocketFlags.None);
		}
	}
}
