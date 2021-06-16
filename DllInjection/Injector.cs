using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.IO;
using System.Runtime.ConstrainedExecution;
using System.Security;
using System.Text;

namespace DllInjection
{
    public class Injector
    {
        // OpenProcess signture https://www.pinvoke.net/default.aspx/kernel32.openprocess
        [Flags]
        public enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }

        // VirtualAllocEx signture https://www.pinvoke.net/default.aspx/kernel32.virtualallocex
        [Flags]
        public enum AllocationType
        {
            Commit = 0x1000,
            Reserve = 0x2000,
            Decommit = 0x4000,
            Release = 0x8000,
            Reset = 0x80000,
            Physical = 0x400000,
            TopDown = 0x100000,
            WriteWatch = 0x200000,
            LargePages = 0x20000000
        }

        [Flags]
        public enum MemoryProtection
        {
            Execute = 0x10,
            ExecuteRead = 0x20,
            ExecuteReadWrite = 0x40,
            ExecuteWriteCopy = 0x80,
            NoAccess = 0x01,
            ReadOnly = 0x02,
            ReadWrite = 0x04,
            WriteCopy = 0x08,
            GuardModifierflag = 0x100,
            NoCacheModifierflag = 0x200,
            WriteCombineModifierflag = 0x400
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(ProcessAccessFlags processAccess, bool bInheritHandle, int processId);
        public static IntPtr OpenProcess(Process proc, ProcessAccessFlags flags)
        {
            return OpenProcess(flags, false, proc.Id);
        }

        // VirtualFreeEx signture  https://www.pinvoke.net/default.aspx/kernel32.virtualfreeex
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, AllocationType dwFreeType);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, IntPtr dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

        // WriteProcessMemory signture https://www.pinvoke.net/default.aspx/kernel32/WriteProcessMemory.html
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [MarshalAs(UnmanagedType.AsAny)] object lpBuffer, int dwSize, out IntPtr lpNumberOfBytesWritten);

        // GetProcAddress signture https://www.pinvoke.net/default.aspx/kernel32.getprocaddress
        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        // GetModuleHandle signture http://pinvoke.net/default.aspx/kernel32.GetModuleHandle
        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        // CreateRemoteThread signture https://www.pinvoke.net/default.aspx/kernel32.createremotethread
        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        // CloseHandle signture https://www.pinvoke.net/default.aspx/kernel32.closehandle
        [DllImport("kernel32.dll", SetLastError = true)]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        [SuppressUnmanagedCodeSecurity]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CloseHandle(IntPtr hObject);

        public static void inject(string processName, string DllPath, bool silent)
        {
            IntPtr Size = (IntPtr) DllPath.Length;

            // Make sure file exist
            if (!File.Exists(DllPath))
            {
                if (!silent) Console.WriteLine("Cannot find dll at specified path");
                return;
            }
            else
            {
                Process proc;
                // Get processes by name
                try
                {
                    Process[] processes = Process.GetProcessesByName(processName);
                    if (processes == null || processes.Length <= 0)
                    {
                        if (!silent) Console.WriteLine("Processes not found!");
                        return;
                    }
                    else if (processes.Length > 1)
                        if (!silent) Console.WriteLine("Found more than one process by given name! Injecting to the first!");

                    // Make sure we don't touch SYSTEM processe
                    if (processes[0].ProcessName == "System")
                    {
                        if (!silent) Console.WriteLine("Injecting to process SYSTEM is disallowed");
                        return;
                    }

                    proc = processes[0];
                    if (!silent) Console.WriteLine("Inject target is: {0}", proc.ProcessName);
                }
                catch (Exception e)
                {
                    if (!silent) Console.WriteLine("Error: " + e.Message);
                    return;
                }

                // Open handle to the target process
                IntPtr ProcHandle = OpenProcess(
                    ProcessAccessFlags.All,
                    false,
                    proc.Id);
                if (ProcHandle == null)
                {
                    if (!silent) Console.WriteLine("Could not obtain handle of process!");
                    return;
                }

                // Allocate DLL space
                IntPtr DllSpace = VirtualAllocEx(
                    ProcHandle,
                    IntPtr.Zero,
                    Size,
                    AllocationType.Reserve | AllocationType.Commit,
                    MemoryProtection.ExecuteReadWrite);

                if (DllSpace == null)
                {
                    if (!silent) Console.WriteLine("DLL space allocation failed!");
                    return;
                }

                // Write DLL content to VAS of target process
                byte[] bytes = Encoding.ASCII.GetBytes(DllPath);
                bool DllWrite = WriteProcessMemory(
                    ProcHandle,
                    DllSpace,
                    bytes,
                    bytes.Length,
                    out var bytesread
                    );

                if (DllWrite == false)
                {
                    if (!silent) Console.WriteLine("Cannot write DLL to executeable!");
                    return;
                }

                // Get handle to Kernel32.dll and get address for LoadLibraryA
                IntPtr Kernel32Handle = GetModuleHandle("Kernel32.dll");
                IntPtr LoadLibraryAAddress = GetProcAddress(Kernel32Handle, "LoadLibraryA");

                if (LoadLibraryAAddress == null)
                {
                    if (!silent) Console.WriteLine("Obtaining an addess to LoadLibraryA function has failed.");
                    return;
                }

                // Create remote thread in the target process
                IntPtr RemoteThreadHandle = CreateRemoteThread(
                    ProcHandle,
                    IntPtr.Zero,
                    0,
                    LoadLibraryAAddress,
                    DllSpace,
                    0,
                    IntPtr.Zero
                    );

                if (RemoteThreadHandle == null)
                {
                    if (!silent) Console.WriteLine("Obtaining a handle to remote thread in target process failed.");
                    return;
                }

                // Deallocate memory assigned to DLL
                bool FreeDllSpace = VirtualFreeEx(
                    ProcHandle,
                    DllSpace,
                    0,
                    AllocationType.Release);
                if (FreeDllSpace == false)
                {
                    if (!silent) Console.WriteLine("Failed to release DLL memory in target process.");
                    return;
                }
                else
                {
                    if (!silent) Console.WriteLine("DLL released");
                }

                // Close remote thread handle
                CloseHandle(RemoteThreadHandle);

                // Close target process handle
                CloseHandle(ProcHandle);
            }
        }
    }
}
