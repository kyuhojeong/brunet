using System;

namespace Openflow {
	public class ControlPlane {
      public static void Main(string[] args) {
			string[] args0 = new string[1];
			string[] args1 = new string[1];
			args0[0] = "-t pasdf" + args[0];
			args1[0] = "-t asdf" + args[1];
         Controller controller_br0 = new Controller(args0);
         Controller controller_br1 = new Controller(args1);
         controller_br0.Run();
         controller_br1.Run();

         Console.WriteLine("so far so good");
      }
	}
}
