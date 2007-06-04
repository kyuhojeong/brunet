using System;
using System.Collections;
using System.Runtime.Remoting;
using System.Runtime.Remoting.Channels;
using System.Runtime.Remoting.Channels.Tcp;
using System.Runtime.Remoting.Channels.Http;
using System.Runtime.Remoting.Lifetime;
using CookComputing.XmlRpc;
using System.Threading;
using Brunet;
using Brunet.Dht;

namespace Ipop {
  /// <summary>
  /// A Dht Server thread listens to Soap and XmlRpc requests
  /// Soap URL: http://loalhost:64221/sd.rem
  /// XmlRpc URL: http://loalhost:64221/xd.rem
  /// </summary>
  public class DhtServer {
    public static Thread StartDhtServerAsThread(FDht dht) {
      Thread DhtThread = new Thread(DhtServer.StartDhtServer);
      DhtThread.Start(dht);
      return DhtThread;
    }

    public static void StartDhtServer(object odht) {
      FDht dht = (FDht)odht;
      XmlRpcServerFormatterSinkProvider chain = new XmlRpcServerFormatterSinkProvider();
      chain.Next = new SoapServerFormatterSinkProvider();

      IDictionary props = new Hashtable();
      props.Add("port", 64221);
      HttpChannel channel = new HttpChannel(props, null, chain);
      ChannelServices.RegisterChannel(channel);

      SoapDht sd = new SoapDht(dht);
      RemotingServices.Marshal(sd, "sd.rem");

      XmlRpcDht xd = new XmlRpcDht(dht);
      RemotingServices.Marshal(xd, "xd.rem");

      ISponsor sponsor = new DhtLifeTimeSponsor();
      // get lifetime manager for the remote object
      ILease lifetime = (ILease)sd.GetLifetimeService();
      // registering our sponsor
      lifetime.Register(sponsor);

      while (true) System.Threading.Thread.Sleep(99999999);
    }
  }

  public class DhtLifeTimeSponsor : ISponsor
  {
    public TimeSpan Renewal(ILease lease)
    {
      TimeSpan ts = new TimeSpan();
      ts = TimeSpan.FromDays(365);
      return ts;
    }
  }
}