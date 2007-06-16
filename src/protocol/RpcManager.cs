/*
This program is part of BruNet, a library for the creation of efficient overlay
networks.
Copyright (C) 2006,2007 P. Oscar Boykin <boykin@pobox.com>, University of Florida

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

//#define RPC_DEBUG
//#define USE_ASYNC_INVOKE
#define DAVID_ASYNC_INVOKE
using System;
using System.IO;
using System.Collections;
using System.Reflection;
using System.Threading;

namespace Brunet {


/**
 * This class holds Rpc results and the packet that carried them.
 */
public class RpcResult {

  public RpcResult(ISender ret_path, object res) {
    _ret_path = ret_path;
    _result = res;
  }

  public RpcResult(ISender ret_path, object res, ReqrepManager.Statistics stats) {
    _ret_path = ret_path;
    _result = res;
    _statistics = stats;
  }

  //statistical information from the ReqreplyManager
  protected ReqrepManager.Statistics _statistics;
  public ReqrepManager.Statistics Statistics {
    get {
      return _statistics;
    }
  }
  protected ISender _ret_path;
  /**
   * This is a ISender that can send to the Node that
   * sent this result.
   */
  public ISender ResultSender { get { return _ret_path; } }

  protected object _result;
  /**
   * Here is the object which is the result of the RPC call.
   * If it is an exception, accessing this property will throw
   * an exception.
   */
  public object Result {
    get {
      //If result is an exception, we throw here:
      if( _result is Exception ) { throw (Exception)_result; }
      return _result;
    }
  }
  
}
	
/**
 * This makes RPC over Brunet easier
 */
public class RpcManager : IReplyHandler, IDataHandler {
 
  protected class RpcRequestState {
    public BlockingQueue result_queue;
  }
 
  //Here are the methods that don't want the return_path
  protected Hashtable _method_handlers;
  //Here are the methods that *DO* want the return_path
  protected Hashtable _method_handlers_sender;
  
  protected object _sync;
  protected ReqrepManager _rrman;
  public readonly Node Node;
  ///Holds a cache of method string names to MethodInfo
  protected readonly Cache _method_cache;
  protected const int CACHE_SIZE = 128;

#if DAVID_ASYNC_INVOKE
  protected BlockingQueue _rpc_command;
  protected Thread _rpc_thread;
#endif

  protected RpcManager(ReqrepManager rrm) {

    _method_handlers = new Hashtable();
    _method_handlers_sender = new Hashtable();
    _sync = new Object();
    Node = rrm.Node;
    _rrman = rrm;
    _method_cache = new Cache(CACHE_SIZE);

#if DAVID_ASYNC_INVOKE
    _rpc_command = new BlockingQueue();
    Node.DepartureEvent += this.RpcCommandStop;
    _rpc_thread = new Thread(RpcCommandRun);
    _rpc_thread.Start();
#endif
  }
  /** static hashtable to keep track of RpcManager objects. */
  protected static Hashtable _rpc_table = new Hashtable();
  /** 
   * Static method to create RpcManager objects
   * @param node The node we work for
   */
  public static RpcManager GetInstance(Node node) {
    lock(_rpc_table) {
      //check if there is already an instance object for this node
      if (_rpc_table.ContainsKey(node)) {
	return (RpcManager) _rpc_table[node];
      }
      //in case no instance exists, create one
      RpcManager rpc  = new RpcManager(ReqrepManager.GetInstance(node)); 
      _rpc_table[node] = rpc;
      node.GetTypeSource( PType.Protocol.Rpc ).Subscribe(rpc, node);
      return rpc;
    }
  }
   
  /**
   * When a method is called with "name.meth"
   * we look up the object with name "name"
   * and invoke the method "meth".
   * @param handler the object to handle the RPC calls
   * @param name the name exposed for this object.  RPC calls to "name."
   * come to this object.
   */
  public void AddHandler(string name, object handler)
  {
    lock( _sync ) {
      _method_handlers.Add(name, handler);
      _method_cache.Clear();
    }
  }
  /**
   * Allows to unregister existing handlers.
   */
  public void RemoveHandler(string name)
  {
    lock( _sync ) {
      _method_handlers.Remove(name);
      _method_cache.Clear();
    }
  }
  /**
   * When a method is called with "name.meth"
   * we look up the object with name "name"
   * and invoke the method "meth".
   * The method's last parameter MUST be an ISender object
   *
   * @param handler the object to handle the RPC calls
   * @param name the name exposed for this object.  RPC calls to "name."
   * come to this object.
   */
  public void AddHandlerWithSender(string name, object handler)
  {
    lock( _sync ) {
      _method_handlers_sender.Add(name, handler);
      _method_cache.Clear();
    }
  }
  /**
   * Allows to unregister existing handlers.
   */
  public void RemoveHandlerWithSender(string name)
  {
    lock( _sync ) {
      _method_handlers_sender.Remove(name);
      _method_cache.Clear();
    }
  }

  /**
   * Implements the IReplyHandler (also provides some light-weight statistics)
   */
  public bool HandleReply(ReqrepManager man, ReqrepManager.ReqrepType rt,
			  int mid, PType prot, MemBlock payload, ISender ret_path,
			  ReqrepManager.Statistics statistics, object state)
  {
    object data = AdrConverter.Deserialize(payload);
    RpcRequestState rs = (RpcRequestState) state;
    BlockingQueue bq = rs.result_queue;
    if( bq != null ) {
      if (!bq.Closed) {
        RpcResult res = new RpcResult(ret_path, data, statistics);
        bq.Enqueue(res);
      }
      //Keep listening unless the queue is closed
      return (!bq.Closed);
    }
    else {
      //If they didn't even pass us a queue, I guess they didn't want to
      //listen too long
      return false;
    }
  }

  /**
   * When requests come in this handles it
   */
  public void HandleData(MemBlock payload, ISender ret_path, object state)
  {
    Exception exception = null; 
#if RPC_DEBUG
    Console.Error.WriteLine("[RpcServer: {0}] Getting method invocation request at: {1}.",
                     _rrman.Node.Address, DateTime.Now);
#endif
    try {
      object data = AdrConverter.Deserialize(payload);
      IList l = data as IList;

      if( l == null ) {
        //We could not cast the request into a list... so sad:
	throw new AdrException(-32600,"method call not a list");
      }
      
      string methname = (string)l[0];
#if RPC_DEBUG
      Console.Error.WriteLine("[RpcServer: {0}] Getting invocation request,  method: {1}",
                     _rrman.Node.Address, methname);
#endif
      
      object handler = null;
      MethodInfo mi = null;
      bool add_sender = false;
      /*
       * Lookup this method name in our table.
       * This uses a cache, so it should be fast
       * after the first time
       */
      lock( _sync ) {
        object[] info = (object[]) _method_cache[methname];
        if( info == null ) {
          string[] parts = methname.Split('.');
          string hname = parts[0];
          string mname = parts[1];
          
          handler = _method_handlers[ hname ];
          if( handler == null ) {
            handler = _method_handlers_sender[ hname ];
            if( handler != null ) {
              add_sender = true;
            }
            else {
              //No handler for this.
              throw new AdrException(-32601, "No Handler for method: " + methname);
            }
          }
          mi = handler.GetType().GetMethod(mname);
          info = new object[]{ mi, handler, add_sender };
          _method_cache[ methname ] = info;
        } else {
          //We already have looked these up:
          mi = (MethodInfo)info[0];
          handler = info[1];
          add_sender = (bool)info[2];
        }
      }
      
      ArrayList pa = (ArrayList)l[1];
      if( add_sender ) {
        pa.Add( ret_path );
      }
      //Console.Error.WriteLine("About to call: {0}.{1} with args",handler, mname);
      //foreach(object arg in pa) { Console.Error.WriteLine("arg: {0}",arg); }
      //make the following happen asynchronously in a separate thread
      //build an invocation record for the call
#if USE_ASYNC_INVOKE
      RpcMethodInvokeDelegate inv_dlgt = this.RpcMethodInvoke;
      inv_dlgt.BeginInvoke(ret_path, mi, handler, pa.ToArray(), 
			   new AsyncCallback(RpcMethodFinish),
			   inv_dlgt);
      //we have setup an asynchronous invoke here
#elif DAVID_ASYNC_INVOKE
      object[] odata = new object[4];
      odata[0] = ret_path;
      odata[1] = mi;
      odata[2] = handler;
      odata[3] = pa.ToArray();
      _rpc_command.Enqueue(odata);
#else
      /*
       * Invoke the method synchronously, it is not clear which is 
       * better.  Async uses the threadpool, which can lead to performance
       * issues.
       */
      RpcMethodInvoke(ret_path, mi, handler, pa.ToArray()); 
#endif
    }
    catch(ArgumentException argx) {
      exception = new AdrException(-32602, argx);
    }
    catch(TargetParameterCountException argx) {
      exception = new AdrException(-32602, argx);
    }
    catch(Exception x) {
      exception = x;
    }
    if (exception != null) {
      //something failed even before invocation began
#if RPC_DEBUG
      Console.Error.WriteLine("[RpcServer: {0}] Something failed even before invocation began: {1}",
                     _rrman.Node.Address, exception);
#endif
      MemoryStream ms = new MemoryStream();
      AdrConverter.Serialize(exception, ms);
      ret_path.Send( new CopyList( PType.Protocol.Rpc, MemBlock.Reference( ms.ToArray() ) ) );
    }
  }
  
  /**
   * When an error comes in, this handles it
   */
  public void HandleError(ReqrepManager man, int message_number,
                   ReqrepManager.ReqrepError err, ISender ret_path, object state)
  {
    Exception x = null;
    RpcRequestState rs = (RpcRequestState) state;
    BlockingQueue bq = rs.result_queue;
    switch(err) {
        case ReqrepManager.ReqrepError.NoHandler:
          x = new AdrException(-32601, "No RPC Handler on remote host");
          break;
        case ReqrepManager.ReqrepError.HandlerFailure:
          x = new AdrException(-32603, "The remote RPC System had a problem");
          break;
        case ReqrepManager.ReqrepError.Timeout:
          //In this case we close the BlockingQueue:
          if( bq != null ) { bq.Close(); }
          break;
        case ReqrepManager.ReqrepError.Send:
          //We had some problem sending, but ignore it for now
          break;
    }
    if( x != null && (bq != null) ) {
      RpcResult res = new RpcResult(ret_path, x);
      bq.Enqueue(res);
    }
  }

  /**
   * This is how you invoke a method on a remote host.
   * Results are put into the BlockingQueue.
   * 
   * If you want to have an Event based approach, listen to the EnqueueEvent
   * on the BlockingQueue you pass for the results.  That will be fired
   * immediately from the thread that gets the result.
   *
   * When a result comes back, we put and RpcResult into the Queue.
   * When you have enough responses, Close the queue (please).  The code
   * will stop sending requests after the queue is closed.  If you never close
   * the queue, this will be wasteful of resources.
   *
   * @param target the sender to use when making the RPC call
   * @param q the BlockingQueue into which the RpcResult objects will be placed.
   *            q may be null if you don't care about the response.
   * @param method the Rpc method to call
   * 
   */
  public void Invoke(ISender target, BlockingQueue q, string method,
                              params object[] args)
  {
    //build state for the RPC call
    RpcRequestState rs = new RpcRequestState();
    rs.result_queue = q;

    ArrayList arglist = new ArrayList();
    if( args != null ) {
      arglist.AddRange(args);
    }
    //foreach(object o in arglist) { Console.Error.WriteLine("arg: {0}",o); } 
    ArrayList rpc_call = new ArrayList();
    rpc_call.Add(method);
    rpc_call.Add(arglist);
    
    MemoryStream ms = new MemoryStream();
    AdrConverter.Serialize(rpc_call, ms);

#if RPC_DEBUG
    Console.Error.WriteLine("[RpcClient: {0}] Invoking method: {1} on target: {2}",
                     _rrman.Node.Address, method, target);
#endif
    ICopyable rrpayload = new CopyList( PType.Protocol.Rpc, MemBlock.Reference(ms.ToArray()) ); 
    _rrman.SendRequest(target, ReqrepManager.ReqrepType.Request, rrpayload, this, rs);
  }
  
  protected void RpcMethodInvoke(ISender ret_path, MethodInfo mi, Object handler, 
				 Object[] param_list) {
    Object result = null;
    try {
#if RPC_DEBUG
      Console.Error.WriteLine("[RpcServer: {0}] Invoking method: {1}", _rrman.Node.Address, mi);
#endif
      result = mi.Invoke(handler, param_list);
    } catch(ArgumentException argx) {
#if RPC_DEBUG
      Console.Error.WriteLine("[RpcServer: {0}] Argument exception. {1}", _rrman.Node.Address, mi);
#endif
      result = new AdrException(-32602, argx);
    }
    catch(TargetParameterCountException argx) {
#if RPC_DEBUG
      Console.Error.WriteLine("[RpcServer: {0}] Parameter count exception. {1}", _rrman.Node.Address, mi);
#endif
      result = new AdrException(-32602, argx);
    }
    catch(TargetInvocationException x) {
#if RPC_DEBUG
      Console.Error.WriteLine("[RpcServer: {0}] Exception thrown by method: {1}, {2}", _rrman.Node.Address, mi, x.InnerException.Message);
#endif
      if( x.InnerException is AdrException ) {
        result = x.InnerException;
      }
      else {
        result = new AdrException(-32608, x.InnerException);
      }
    }
    catch(Exception x) {
#if RPC_DEBUG
      Console.Error.WriteLine("[RpcServer: {0}] General exception. {1}", _rrman.Node.Address, mi);
#endif
      result = x;
    }
    finally {
      MemoryStream ms = new MemoryStream();
      AdrConverter.Serialize(result, ms);
      ret_path.Send( new CopyList( PType.Protocol.Rpc, MemBlock.Reference( ms.ToArray() ) ) );
    }
  }
  
  protected void RpcMethodFinish(IAsyncResult ar) {
    RpcMethodInvokeDelegate  dlgt = (RpcMethodInvokeDelegate) ar.AsyncState;
    //call EndInvoke to do cleanup
    //ideally no exception should be thrown, since the delegate catches everything
    dlgt.EndInvoke(ar);
  }
  
  /** We need to do the method invocation in a thread from the thrread pool. 
   */
  protected delegate void RpcMethodInvokeDelegate(ISender return_path, MethodInfo mi, 
						  Object handler, 
						  Object[] param_list);

#if DAVID_ASYNC_INVOKE
  protected void RpcCommandRun() {
    while(true) {
      try {
        object[] data = (object[]) _rpc_command.Dequeue();
        ISender ret_path = (ISender) data[0];
        MethodInfo mi = (MethodInfo) data[1];
        Object handler = (Object) data[2];
        Object[] param_list = (Object[]) data[3];
        this.RpcMethodInvoke(ret_path, mi, handler, param_list);
      }
      catch (Exception) {
        if(_rpc_command.Closed) {
          break;
        }
      }// else continue
    }
  }

  protected void RpcCommandStop(Object o, EventArgs args) {
    this._rpc_command.Close();
  }
#endif
}
}
