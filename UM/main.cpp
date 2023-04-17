#pragma comment(lib,"ntdll.lib")
#pragma warning(disable : 26451) // Bug in VS according to Stackoverflow.


#include <iostream>

#include "KeInterface.hpp"
#include<TlHelp32.h>
#include "ShObjIdl.h"
#include <tchar.h> // _tcscmp
#include <array>



uintptr_t dwGetModuleBaseAddress(DWORD procId, const char* modName)
{
    uintptr_t modBaseAddr = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);
    if (hSnap != INVALID_HANDLE_VALUE)
    {
        MODULEENTRY32 modEntry;
        modEntry.dwSize = sizeof(modEntry);
        if (Module32First(hSnap, &modEntry))
        {
            do
            {
                if (strcmp(modEntry.szModule, modName) == 0)
                {
                    modBaseAddr = (uintptr_t)modEntry.modBaseAddr;
                    break;
                }
            } while (Module32Next(hSnap, &modEntry));

        }
    }
    CloseHandle(hSnap);
    return modBaseAddr;
}

unsigned long show_module(MEMORY_BASIC_INFORMATION info) {
    unsigned long usage = 0;

    std::cout << info.BaseAddress << "(" << info.RegionSize / 1024 << ")\t";

    switch (info.State) {
    case MEM_COMMIT:
        std::cout << "Committed";
        break;
    case MEM_RESERVE:
        std::cout << "Reserved";
        break;
    case MEM_FREE:
        std::cout << "Free";
        break;
    }
    std::cout << "\t";
    switch (info.Type) {
    case MEM_IMAGE:
        std::cout << "Code Module";
        break;
    case MEM_MAPPED:
        std::cout << "Mapped     ";
        break;
    case MEM_PRIVATE:
        std::cout << "Private    ";
    }
    std::cout << "\t";

    int guard = 0, nocache = 0;

    if (info.AllocationProtect & PAGE_NOCACHE)
        nocache = 1;
    if (info.AllocationProtect & PAGE_GUARD)
        guard = 1;

    info.AllocationProtect &= ~(PAGE_GUARD | PAGE_NOCACHE);

    if ((info.State == MEM_COMMIT) && (info.AllocationProtect == PAGE_READWRITE || info.AllocationProtect == PAGE_READONLY))
        usage += info.RegionSize;

    switch (info.AllocationProtect) {
    case PAGE_READONLY:
        std::cout << "Read Only";
        break;
    case PAGE_READWRITE:
        std::cout << "Read/Write";
        break;
    case PAGE_WRITECOPY:
        std::cout << "Copy on Write";
        break;
    case PAGE_EXECUTE:
        std::cout << "Execute only";
        break;
    case PAGE_EXECUTE_READ:
        std::cout << "Execute/Read";
        break;
    case PAGE_EXECUTE_READWRITE:
        std::cout << "Execute/Read/Write";
        break;
    case PAGE_EXECUTE_WRITECOPY:
        std::cout << "COW Executable";
        break;
    }

    if (guard)
        std::cout << "\tguard page";
    if (nocache)
        std::cout << "\tnon-cacheable";
    std::cout << "\n";
    return usage;
}
unsigned long show_modules(HANDLE process) {

    unsigned long usage = 0;

    unsigned char* p = NULL;
    MEMORY_BASIC_INFORMATION info;

    for (p = NULL;
        VirtualQueryEx(process, p, &info, sizeof(info)) == sizeof(info);
        p += info.RegionSize)
    {
        usage += show_module(info);
    }
    return usage;
}
DWORD GetModuleBaseAddress(TCHAR* lpszModuleName, DWORD pID) {
    DWORD dwModuleBaseAddress = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pID); // make snapshot of all modules within process
    MODULEENTRY32 ModuleEntry32 = { 0 };
    ModuleEntry32.dwSize = sizeof(MODULEENTRY32);

    if (Module32First(hSnapshot, &ModuleEntry32)) //store first Module in ModuleEntry32
    {
        do {
            if (_tcscmp(ModuleEntry32.szModule, lpszModuleName) == 0) // if Found Module matches Module we look for -> done!
            {
                dwModuleBaseAddress = (DWORD)ModuleEntry32.modBaseAddr;
                break;
            }
        } while (Module32Next(hSnapshot, &ModuleEntry32)); // go through Module entries in Snapshot and store in ModuleEntry32


    }
    CloseHandle(hSnapshot);
    return dwModuleBaseAddress;
}
KeInterface Driver = NULL;
DWORD Kv = 0x00030000 + 0x1234F28;


int main()
{
    Driver = KeInterface("\\\\.\\steel");
    HWND Class;
    HANDLE hProcess;
	DWORD Pid = 2968;

    DWORD gameBaseAddress = 0x400000;
    DWORD o = gameBaseAddress + 0x1E1FD0;
    DWORD ModuleBase = gameBaseAddress;
    
    std::cout << "debugginfo: baseaddress = "<< std::hex << o << std::endl;
    unsigned char Buffer[7] = {
            0xE9, 0x00, 0x00, 0x00, 0x00,
            0x90,0x90


    };

    DWORD buffer_offset = 0;

    buffer_offset = (sizeof(Buffer) - 6);
    *(DWORD*)(Buffer + buffer_offset) = (DWORD)((ModuleBase + 0x19E2C0) - (ModuleBase + buffer_offset) - 5 + 1);

    std::array<unsigned char, sizeof(Buffer)> ThreadBuffer;
    for (int i = 0; i < sizeof(Buffer); i++) {
        ThreadBuffer.at(i) = Buffer[i];
    }

    Driver.WriteReadOnlyMemory<std::array<unsigned char, sizeof(Buffer)>>(Pid, ModuleBase + 0x19E2B0, ThreadBuffer, sizeof(Buffer));
    Sleep(50);


    Driver.WriteReadOnlyMemory<std::array<unsigned char, sizeof(Buffer)>>(Pid, 0x00D6E2B0, ThreadBuffer, sizeof(Buffer));
   
	

	return 0;
}