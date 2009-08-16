/*
Copyright (C) 2009  David Wolinsky <davidiw@ufl.edu>, University of Florida

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
*/


using System;
using System.Threading;
using System.Collections;
using System.Collections.Generic;

namespace Brunet.Tunnel {
  /// <summary>Holds the state information for a Tunnels.</summary>
  public class TunnelEdge : Edge {
    protected static readonly Random _rand = new Random();
    public readonly int LocalID;
    protected int _remote_id;

    public int RemoteID {
      get {
        return _remote_id;
      }
      set {
        //When an outgoing edge first hears back, he doesn't know the
        //remote id, we set it ONCE and fail if it is attempted again!
        if(Interlocked.CompareExchange(ref _remote_id, value, -1) != -1) {
          throw new Exception("RemoteID already set!");
        }

        byte[] bid = new byte[8];
        NumberSerializer.WriteInt(LocalID, bid, 0);
        NumberSerializer.WriteInt(_remote_id, bid, 4);
        MemBlock mid = MemBlock.Reference(bid);
        Interlocked.Exchange(ref _mid, mid);
      }
    }


    protected MemBlock _mid;
    public MemBlock MId { get { return _mid; } }

    protected readonly TransportAddress _local_ta;
    protected readonly TransportAddress _remote_ta;

    /// <summary>A functional list of tunnels.  Replace to update.</summary>
    protected List<Address> _tunnels;
    protected IAddressSelector _ias;

    public IList<Address> Overlap { get { return _tunnels.AsReadOnly(); } }

    public Address NextAddress {
      get {
        return _ias.NextAddress;
      }
    }

    public override Brunet.TransportAddress LocalTA {
      get {
        return _local_ta;
      }
    }

    public override Brunet.TransportAddress RemoteTA {
      get {
        return _remote_ta;
      }
    }

    public override Brunet.TransportAddress.TAType TAType {
      get {
        return TransportAddress.TAType.Tunnel;
      }
    }

    public readonly MemBlock Header;

    /// <summary>Outgoing edge, since we don't know the RemoteID yet!</summary>
    public TunnelEdge(IEdgeSendHandler send_handler, TunnelTransportAddress local_ta,
        TunnelTransportAddress remote_ta, IAddressSelector ias, List<Address> overlap) :
      this(send_handler, local_ta, remote_ta, ias, overlap, -1)
    {
    }

    /// <summary>Constructor for a TunnelEdge, RemoteID == -1 for out bound.</summary>
    public TunnelEdge(IEdgeSendHandler send_handler, TunnelTransportAddress local_ta,
        TunnelTransportAddress remote_ta, IAddressSelector ias, List<Address> overlap,
        int remote_id) : base(send_handler, remote_id != -1)
    {
      _remote_id = remote_id;
      lock(_rand) {
        LocalID = _rand.Next();
      }
      byte[] bid = new byte[8];
      NumberSerializer.WriteInt(LocalID, bid, 0);
      NumberSerializer.WriteInt(_remote_id, bid, 4);
      _mid = MemBlock.Reference(bid);
      _local_ta = local_ta;
      _remote_ta = remote_ta;
      _tunnels = new List<Address>(overlap);
      _ias = ias;
      _ias.Update(_tunnels);

      AHHeader ahh = new AHHeader(1, 20, local_ta.Target, remote_ta.Target,
          AHHeader.Options.Exact);
      ICopyable header = new CopyList(PType.Protocol.AH, ahh,
          PType.Protocol.Tunneling);
      Header = MemBlock.Copy(header);
    }

    /// <summary>When our tunnel peer has some state change, he notifies us and
    /// use that information to update our overlap, here we set the overlap.</summary>
    public void UpdateNeighborIntersection(List<Address> neighbors)
    {
      bool close = false;
      lock(_sync) {
        _tunnels = new List<Address>(neighbors);
        close = _tunnels.Count == 0;
      }

      if(close) {
        Close();
      }
      _ias.Update(_tunnels);
    }

    /// <summary>We don't want to send on disconnected edges.  So we remove said
    /// connections and edges!</summary>
    public void DisconnectionHandler(Address addr)
    {
      bool close = false;
      lock(_sync) {
        List<Address> tunnels = new List<Address>(_tunnels);
        tunnels.Remove(addr);
        if(_tunnels.Count == tunnels.Count) {
          return;
        }
        _tunnels = tunnels;
        close = _tunnels.Count == 0;
      }

      if(close) {
        Close();
      }
      _ias.Update(_tunnels);
    }
  }
}