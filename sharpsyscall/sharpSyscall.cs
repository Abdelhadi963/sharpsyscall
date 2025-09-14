using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;

namespace sharpsyscall
{
    internal class sharpSyscall
    {
        // -------------------------
        // P/Invoke and structs
        // -------------------------
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [DllImport("ntdll.dll", EntryPoint = "RtlGetVersion")]
        static extern int RtlGetVersion(ref OSVERSIONINFOEX lpVersionInformation);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct OSVERSIONINFOEX
        {
            public int dwOSVersionInfoSize;
            public int dwMajorVersion;
            public int dwMinorVersion;
            public int dwBuildNumber;
            public int dwPlatformId;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
            public string szCSDVersion;
        }

        // -------------------------
        // Get Windows & build info
        // -------------------------
        public string GetWindowsVersion()
        {
            string winver = "Unknown";

            var osVersionInfo = new OSVERSIONINFOEX();
            osVersionInfo.dwOSVersionInfoSize = Marshal.SizeOf(typeof(OSVERSIONINFOEX));
            int result = RtlGetVersion(ref osVersionInfo);
            if (result == 0) // STATUS_SUCCESS
            {
                winver = $"{osVersionInfo.dwMajorVersion}.{osVersionInfo.dwMinorVersion} (Build {osVersionInfo.dwBuildNumber})";
                Console.WriteLine($"[+] Detected Windows Version: {winver}");
            }
            else
            {
                Console.WriteLine("[!] Error retrieving Windows version using RtlGetVersion.");
                // Fallback to registry method
                try
                {
                    using (var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion"))
                    {
                        if (key != null)
                        {
                            var productName = key.GetValue("ProductName")?.ToString() ?? "Unknown Product";
                            var currentBuild = key.GetValue("CurrentBuild")?.ToString() ?? "Unknown Build";
                            var ubr = key.GetValue("UBR")?.ToString() ?? "0"; // UBR might not exist on older versions
                            winver = $"{productName} (Build {currentBuild}.{ubr})";
                            Console.WriteLine($"[+] Detected Windows Version from registry: {winver}");
                        }
                        else
                        {
                            Console.WriteLine("[!] Unable to open registry key for Windows version.");
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[!] Exception while accessing registry: {ex.Message}");
                }
            }

            return winver;
        }

        // -------------------------
        // Get syscall number for a given function
        // -------------------------
        public int? GetSyscallNumber(string func)
        {
            IntPtr hNtdll = GetModuleHandle("ntdll.dll");
            if (hNtdll == IntPtr.Zero)
            {
                Console.WriteLine("[!] Error: Unable to get handle for ntdll.dll");
                return null;
            }

            // DEBUG: Print ntdll handle
            //Console.WriteLine($"[DBUG] ntdll.dll handle: 0x{hNtdll.ToInt64():X}");
            IntPtr pFunc = GetProcAddress(hNtdll, func);
            if (pFunc == IntPtr.Zero)
            {
                Console.WriteLine($"[!] Error: Unable to get address for function {func}");
                return null;
            }

            //  mov r10, rcx; mov eax, imm32; syscall; ret
            byte[] funcBytes = new byte[8];
            Marshal.Copy(pFunc, funcBytes, 0, funcBytes.Length);

            // DEBUG: Print Bytes ( i had some trouble to find the right pattern :) )
            //Console.WriteLine($"[DBUG] {func} bytes: {BitConverter.ToString(funcBytes)}");

            // Expected stub: 4C 8B D1 (mov r10, rcx) B8 xx xx xx xx (mov eax, imm32)
            // Pattern: B8 (mov eax, imm32)
            if (funcBytes[0] == 0xB8)
            {
                // Just take the first byte after B8 as the syscall number
                int syscallNumber = funcBytes[1]; // This should be 0x08 = 8
                //Console.WriteLine($"[DBUG] Found syscall number {syscallNumber} for function {func}");
                return syscallNumber;
            }

            Console.WriteLine($"[!] Could not extract syscall number for {func} - pattern not matched");
            return null;
        }
        // ------------------------
        // Generate syscall mapping for a list of functions
        // ------------------------
        public Dictionary<string, int?> GenerateSyscallMapping(string[] functions)
        {
            var mapping = new Dictionary<string, int?>();
            foreach (var func in functions)
            {
                int? syscallNumber = GetSyscallNumber(func);
                if (syscallNumber.HasValue)
                {
                    mapping[func] = syscallNumber;
                    //Console.WriteLine($"[+] Mapped {func} to syscall number {syscallNumber}");
                    //Console.WriteLine($"    {func} -> {syscallNumber:X2}h");
                }
                else
                {
                    mapping[func] = null;
                    Console.WriteLine($"[!] Warning: Syscall number for {func} not found.");
                }
            }
            return mapping;
        }

        // -------------------------
        // Write syscall stubs to file
        // -------------------------
        public void WriteStubToFile(string winver, Dictionary<string, int?> mapping,bool stdout)
        {
            var sb = new StringBuilder();
            sb.AppendLine("; ============================================================");
            sb.AppendLine($";  Syscall Stubs for Windows {winver}");
            sb.AppendLine(";  ------------------------------------------------------------");
            sb.AppendLine(";  These syscall numbers are specific to this Windows build.");
            sb.AppendLine(";  Syscall numbers often change across builds, so regenerate");
            sb.AppendLine(";  this file when targeting a different Windows version.");
            sb.AppendLine("; ============================================================");
            sb.AppendLine();
            sb.AppendLine(".code");
            sb.AppendLine();

            foreach (var func in mapping)
            {
                string funcName = func.Key;
                int? syscallNumber = func.Value;
                string procName = "Sys" + funcName; // Prefix with "Sys" & change it as you need :)

                if (!syscallNumber.HasValue)
                {
                    Console.WriteLine($"[!] Warning: Syscall number for {funcName} not found. Skipping.");
                    continue;
                }

                // Generate the assembly stub
                sb.AppendLine($"    ; {funcName} - Syscall Number: {syscallNumber}");
                sb.AppendLine($"    {procName} proc");
                sb.AppendLine("         mov r10, rcx");
                // masm don't allow hex to start with a number not in 0-9 range
                //sb.AppendLine($"         mov eax, {syscallNumber:X2}h");
                // Ensure MASM hex literals always start with a digit (0-9)
                // Ensure syscallNumber is treated as an int
                int num = (int)syscallNumber;
                string hexValue = num.ToString("X2");

                // Pad with leading 0 if first digit is A-F
                if (hexValue[0] >= 'A' && hexValue[0] <= 'F')
                {
                    hexValue = "0" + hexValue;
                }
                sb.AppendLine($"         mov eax, {hexValue}h");
                sb.AppendLine("         syscall");
                sb.AppendLine("         ret");
                sb.AppendLine($"    {procName} endp");
                sb.AppendLine();
            }

            // Add the end directive once at the end
            sb.AppendLine("end");

            // Construct the filename and write once
            string fileName = $"Syscalls_{winver.Replace(" ", "_").Replace(".", "_").Replace("(", "").Replace(")", "")}.asm";
            //Console.WriteLine($"[DBUG] Writing stubs to {fileName}");

            if (stdout)
            {
                Console.WriteLine("[*] Outputting syscall stubs to stdout:");
                Console.WriteLine("");
                Console.WriteLine(sb.ToString());
                return;
            }

            Console.WriteLine("[*] Writing syscall stubs...");
            try
            {
                File.WriteAllText(fileName, sb.ToString());
                Console.WriteLine($"[+] Successfully wrote syscall stubs to {fileName}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error writing to file {fileName}: {ex.Message}");
            }
        }
    }

    public class UsageOptions
    {
        // -------------------------
        // some default syscalls to generate
        // -------------------------
        static readonly string[] DefaultSyscalls = new[]
        {
            // Note: --------------------------
            // Zw / Nt variants have the same syscall number, but Zw is the kernel-mode variant has some different structures  & prototypes bypassing some type validations
            // Keep both of them & define separate stubs for flexibility
            // Note: --------------------------

            // process / memory / thread
            "NtOpenProcess", "ZwOpenProcess",
            "NtWriteVirtualMemory", "ZwWriteVirtualMemory",
            "NtProtectVirtualMemory", "ZwProtectVirtualMemory",
            "NtCreateThreadEx", "ZwCreateThreadEx",
            "NtClose", "ZwClose",
            "NtQueryInformationProcess", "ZwQueryInformationProcess",
            "NtAllocateVirtualMemory", "ZwAllocateVirtualMemory",
            "NtFreeVirtualMemory", "ZwFreeVirtualMemory",
            "NtOpenThread", "ZwOpenThread",
            "NtResumeThread", "ZwResumeThread",
            "NtSuspendThread", "ZwSuspendThread",

            // file / filesystem related
            "NtCreateFile", "ZwCreateFile",
            "NtOpenFile", "ZwOpenFile",
            "NtReadFile", "ZwReadFile",
            "NtWriteFile", "ZwWriteFile",
            "NtQueryInformationFile", "ZwQueryInformationFile",
            "NtQueryDirectoryFile", "ZwQueryDirectoryFile",
            "NtQueryAttributesFile", "ZwQueryAttributesFile",
            "NtSetInformationFile", "ZwSetInformationFile",
            "NtDeleteFile", "ZwDeleteFile",

            // section / mapping (useful for code injection / mapping payloads)
            "NtCreateSection", "ZwCreateSection",
            "NtMapViewOfSection", "ZwMapViewOfSection",
            "NtUnmapViewOfSection", "ZwUnmapViewOfSection"
        };

        // -------------------------
        // Print usage information
        // -------------------------
        public void Usage()
        {
            Console.WriteLine("");
            Console.WriteLine("SharpSyscall - A C# tool to generate syscall stubs for Windows by @IppY0kai.");
            Console.WriteLine("Usage: SharpSyscallGen.exe [--syscall-func <file>] [--syscall-stdin <func1,func2,...>] [--exclude-default] [--stdout] [--help]");
            Console.WriteLine("Usage examples:");
            Console.WriteLine("  SharpSyscall.exe --syscall-func syscalls.txt");
            Console.WriteLine("  SharpSyscall.exe --syscall-stdin NtCreateFile,NtOpenFile");
            Console.WriteLine("  SharpSyscall.exe --exclude-default --syscall-stdin NtCreateFile,NtOpenFile --stdout");
            Console.WriteLine("");
        }

        // -------------------------
        // Parse command-line arguments
        // -------------------------
        public (string[], bool, bool) ParseArgs(string[] args)
        {
            bool showHelp = false;
            bool excludeDefaults = false;
            bool outputToStdout = false;

            // First pass to check for --exclude-default and --stdout flags
            for (int i = 0; i < args.Length; i++)
            {
                if (args[i] == "--exclude-default")
                    excludeDefaults = true;
                if (args[i] == "--stdout")
                    outputToStdout = true;
                if (args[i] == "--help" || args[i] == "-h" || args[i] == "/?")
                    showHelp = true;
            }

            string[] functions = excludeDefaults ? new string[0] : DefaultSyscalls;

            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "--syscall-func":
                        if (i + 1 < args.Length)
                        {
                            string filePath = args[i + 1];
                            if (File.Exists(filePath))
                            {
                                var fileFunctions = File.ReadAllLines(filePath)
                                                        .Select(line => line.Trim())
                                                        .Where(line => !string.IsNullOrEmpty(line) && !line.StartsWith("#"))
                                                        .ToArray();
                                functions = excludeDefaults ? fileFunctions : DefaultSyscalls.Concat(fileFunctions).ToArray();
                                i++; // Skip next argument as it's the file path
                            }
                            else
                            {
                                Console.WriteLine($"[!] Error: File {filePath} does not exist.");
                                showHelp = true;
                            }
                        }
                        else
                        {
                            Console.WriteLine("[!] Error: --syscall-func requires a file path argument.");
                            showHelp = true;
                        }
                        break;
                    case "--syscall-stdin":
                        if (i + 1 < args.Length)
                        {
                            var stdinFunctions = args[i + 1].Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries)
                                                      .Select(f => f.Trim())
                                                      .ToArray();
                            functions = excludeDefaults ? stdinFunctions : DefaultSyscalls.Concat(stdinFunctions).ToArray();
                            i++; // Skip next argument as it's the function list
                        }
                        else
                        {
                            Console.WriteLine("[!] Error: --syscall-stdin requires a comma-separated list of functions.");
                            showHelp = true;
                        }
                        break;
                    case "--exclude-default":
                        // Handled in the first pass
                        break;
                    case "--stdout":
                        // Handled in the first pass
                        break;
                    case "--help":
                    // Handled in the first pass
                    case "-h":
                        // Handled in the first pass
                        break;
                    case "/?":
                        // Handled in the first pass
                        break;

                    default:
                        Console.WriteLine($"[!] Error: Unknown argument {args[i]}");
                        showHelp = true;
                        break;
                }
            }

            if (excludeDefaults && functions.SequenceEqual(DefaultSyscalls))
            {
                functions = new string[0];
            }

            return (functions, showHelp, outputToStdout);
        }

    }
}