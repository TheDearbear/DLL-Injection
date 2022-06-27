using System;
using DllInjection;

namespace InjectorLauncher
{
    class InjectorLauncher
    {
        static void Main(string[] args)
        {
            // Check arguments
            if (args.Length < 2)
            {
                Console.WriteLine("Usage: InjectorLauncher.exe <target process name | target process id> <path to dll>");
                return;
            }

            try
            {
                Injector.Inject(int.Parse(args[0]), args[1], false);
            }
            catch (Exception)
            {
                Injector.Inject(args[0], args[1], false);
            }

        }
    }
}
