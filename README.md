**SharSyscall** A simple C# tool to generate a NASM file to use in your visual studeo project for direct syscall in windows.

## How it's works ? 

You know that the syscall numbers change for each Windows build, right? :)
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

1. **--syscall-func**: Read function names from an input file line by line and parse the result into a syscalls_XXXX_XXX.nasm file in the current directory.
2. **--syscall-stdin**: Read functions from stdin, separated by “,”, and parse the result into a syscalls_XXXX_XXX.nasm file in the current directory.
3. **--exclude-default**: Exclude the hardcoded list of functions, useful when generating stubs for your specific functions.
4. **--stdout**: Write the output to stdout, so it is not saved to any file.

## Usage example 
For the sake of our demo, let's use syscalls to create a file.
### generating NASM file
So we need to generate assembly code for the syscall invoked by the native API **NtCreateFile**. We can add **NtOpenFile** too, for testing the argument parser.
```powershell
.\sharpsyscall.exe --exclude-default --syscall-stdin NtCreateFile,NtOpenFile --stdout
```
<img width="1426" height="726" alt="image" src="https://github.com/user-attachments/assets/de327f45-0d65-4e84-85de-fd29f4d1d4f1" />

just remove  **--stdout** to write to the file or copy it manuly.
```powershell
.\sharpsyscall.exe --exclude-default --syscall-stdin NtCreateFile,NtOpenFile
```
We can see that our assembly is generated and saved to the file successfully.
<img width="1544" height="720" alt="image" src="https://github.com/user-attachments/assets/69ef012d-5f16-40a8-9a84-b23e739555b9" />

### Configuring NASM support in VS
Now we can use Visual Studio to create a simple C++ project and add the assembly file to it. We can add NASM support as follows:
Go to **Build Dependencies** → **Build Customizations** → **check the NASM box**.
<img width="846" height="906" alt="image" src="https://github.com/user-attachments/assets/792089f5-117b-4bce-ad4f-d301b297d394" />
<img width="1432" height="382" alt="image" src="https://github.com/user-attachments/assets/b9e2af56-ca23-4dd2-bc82-b9529f263873" />
Now go to your NASM file → **Properties** → scroll to **Microsoft Macro Assembler** (if you didn’t complete the previous step, you will not be able to see this option in the menu).
<img width="1616" height="726" alt="image" src="https://github.com/user-attachments/assets/f55da291-b863-4a45-9f56-dd7a56474b14" />

### invoke the syscall
Now, to use our defined assembly stub, we need to define the **NtCreateFile** prototype. Since this is an NT API, it is not documented in MSDN, so we can use a useful open-source doc: [NtCreateFile Doc](https://ntdoc.m417z.com/ntcreatefile).
We end up with the following prototype:
```C
NTSTATUS SysNtCreateFile(
    _Out_ PHANDLE FileHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_opt_ PLARGE_INTEGER AllocationSize,
    _In_ ULONG FileAttributes,
    _In_ ULONG ShareAccess,
    _In_ ULONG CreateDisposition,
    _In_ ULONG CreateOptions,
    _In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
    _In_ ULONG EaLength
);
```

Then we need to create some helper functions to construct the file path and initial object attributes. We end up with the full following code:
```C
#include <windows.h>
#include <winternl.h>
#include <stdio.h>

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

// inline version of RtlInitUnicodeString
static inline void RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString) {
    if (DestinationString) {
        DestinationString->Length = (USHORT)(wcslen(SourceString) * sizeof(WCHAR));
        DestinationString->MaximumLength = DestinationString->Length + sizeof(WCHAR);
        DestinationString->Buffer = (PWSTR)SourceString;
    }
}


#ifdef __cplusplus
extern "C" {
#endif

    // ------------------- NtCreateFile -------------------

    NTSTATUS SysNtCreateFile(
        _Out_ PHANDLE FileHandle,
        _In_ ACCESS_MASK DesiredAccess,
        _In_ POBJECT_ATTRIBUTES ObjectAttributes,
        _Out_ PIO_STATUS_BLOCK IoStatusBlock,
        _In_opt_ PLARGE_INTEGER AllocationSize,
        _In_ ULONG FileAttributes,
        _In_ ULONG ShareAccess,
        _In_ ULONG CreateDisposition,
        _In_ ULONG CreateOptions,
        _In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
        _In_ ULONG EaLength
    );

#ifdef __cplusplus
}
#endif

int main() {
    OBJECT_ATTRIBUTES oa;
    HANDLE fileHandle = NULL;
    NTSTATUS status;
    UNICODE_STRING fileName;
    IO_STATUS_BLOCK osb;

    // Initialize file path in NT namespace
    RtlInitUnicodeString(&fileName, L"\\??\\C:\\ippyokai\\desktop\\test.txt");
    InitializeObjectAttributes(&oa, &fileName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    ZeroMemory(&osb, sizeof(osb));

    // Call manual syscall stub
    status = SysNtCreateFile(
        &fileHandle,
        FILE_GENERIC_WRITE,
        &oa,
        &osb,
        NULL,                       
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OVERWRITE_IF,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );

    if (status == STATUS_SUCCESS) {
        printf("[+] File created successfully!\n");
        CloseHandle(fileHandle);
    }
    else {
        printf("[-] NtCreateFile failed: 0x%X\n", status);
    }
	return 0;
}
```

Just build your solution. You will see that it assembles the NASM file too, from the path where you added it.
<img width="1772" height="616" alt="image" src="https://github.com/user-attachments/assets/6952aa81-a21d-4eaf-acfd-e57d36d4dbed" />

Time for testing
<img width="1177" height="296" alt="image" src="https://github.com/user-attachments/assets/ce6f6cce-6acb-4b9b-b2ff-c77988c6c694" />

"[+] file Created Sucessfully."!!

### Windbg
We can step through the program using WinDbg to see what exactly is going on.

Break at **SysNtCreateFile** and step through your program. We will hit our assembly stub, and we can see that we are calling the syscall directly.
```
0:000> bp syscall!SysNtCreateFile
0:000> g
Breakpoint 1 hit
syscall!SysNtCreateFile:
00007ff6`02db1160 4c8bd1          mov     r10,rcx
0:000> t
syscall!SysNtCreateFile+0x3:
00007ff6`02db1163 b855000000      mov     eax,55h
0:000> t
syscall!SysNtCreateFile+0x8:
00007ff6`02db1168 0f05            syscall
0:000> t
syscall!SysNtCreateFile+0xa:
00007ff6`02db116a c3              ret
```
<img width="1697" height="930" alt="image" src="https://github.com/user-attachments/assets/b7ba34d1-2f1c-4386-9ade-98866043ee93" />

## Useful Resources

I would like to share the following useful blog to learn more about direct syscalls: [Red Team Tactics: Combining Direct System Calls and SRDI to Bypass AV/EDR](https://www.outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/)









   
