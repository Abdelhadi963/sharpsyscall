using sharpsyscall;
using System;
using System.Linq;

class Program
{
    // --------------------------------------------------------------
    // Just Main method
    // --------------------------------------------------------------
    static void Main(string[] args)
    {
        var options = new UsageOptions();
        var (functions, showHelp, outputToStdout) = options.ParseArgs(args);

        if (showHelp)
        {
            options.Usage();
            return;
        }

        var generator = new sharpSyscallGen();

        Console.WriteLine("[*] SharpSyscallGen - Windows Syscall Stub Generator");
        Console.WriteLine("[*] Detecting Windows version...");

        string winver = generator.GetWindowsVersion();

        Console.WriteLine($"[*] Generating syscall mappings for {functions.Length} functions...");
        var mapping = generator.GenerateSyscallMapping(functions);
        int successfulMappings = mapping.Count(kvp => kvp.Value.HasValue);
        Console.WriteLine($"[+] Complete! Successfully generated {successfulMappings}/{functions.Length} syscall stubs.");

        generator.WriteStubToFile(winver, mapping, outputToStdout);
    }
}
