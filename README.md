**SharSyscall** A simple C# tool to generate a NASM file to use in your visual studeo project for direct syscall in windows.

## How it's works ? 

you know that the syscall numbers change for each windows build  right :) So we are doing the following to locate it :
1. **Loads ntdll.dll** and locates the target function
2. **Parses the first 8 bytes** of each function looking for syscall patterns:
   - `4C 8B D1 B8` (mov r10, rcx; mov eax, syscall_number) - Standard pattern
   - `B8` (mov eax, syscall_number) - Alternative pattern
3. **Extracts the syscall number** and generates NASM-compatible assembly stubs
4. **Outputs organized stubs** with proper sections for default and custom functions

## Usage
help menu
```powershell
PS C:\Users\ippyokai\Desktop> .\sharpsyscall.exe -h

SharpSyscall - A C# tool to generate syscall stubs for Windows by @IppY0kai.
Usage: SharpSyscallGen.exe [--syscall-func <file>] [--syscall-stdin <func1,func2,...>] [--exclude-default] [--stdout] [--help]
Usage examples:
  SharpSyscall.exe --syscall-func syscalls.txt
  SharpSyscall.exe --syscall-stdin NtCreateFile,NtOpenFile
  SharpSyscall.exe --exclude-default --syscall-stdin NtCreateFile,NtOpenFile --stdout
```

1. **--syscall-func** : read  functions names from an input file line by line parese the result in syscalls_XXXX_XXX.nasm file in current directory.
2. **--syscall-stdin** : read functions from stdin separated by "," and parse result to syscalls_XXXX_XXX.nasm file directory.
3. **--exclude-default** : exclude the hardcoded list of functions usefull to when you are generating stubs for your specifc functions.
4. **--stdout** : write the output to stout so is not saved to any file.

## Usage example 
for the seek of our demo let's use syscall's to create a file.

so we nee to generate assembly code for syscall invoked by the native API NtCreateFile we can add NtOpenFile too for arg parser test.
```powershell
.\sharpsyscall.exe --exclude-default --syscall-stdin NtCreateFile,NtOpenFile --stdout
```
<img width="1426" height="726" alt="image" src="https://github.com/user-attachments/assets/de327f45-0d65-4e84-85de-fd29f4d1d4f1" />

just remove  **--stdout** to write to the file or copy it manuly.
```powershell
.\sharpsyscall.exe --exclude-default --syscall-stdin NtCreateFile,NtOpenFile
```
<img width="1544" height="720" alt="image" src="https://github.com/user-attachments/assets/69ef012d-5f16-40a8-9a84-b23e739555b9" />




   
