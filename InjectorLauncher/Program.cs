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
                Console.WriteLine("Usage: InjectorLauncher.exe <target process name> <path to dll>");
                return;
            }
            Injector.inject(args[0], args[1], false);
        }
    }
}
