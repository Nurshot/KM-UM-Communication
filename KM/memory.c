#pragma warning( disable : 4100 4047 4024 4022 4201 4311 4057 4213 4189 4081 4189 4706 4214 4459 4273 4457 4133)

#include "memory.h"
#include <minwindef.h>
#include <ntstatus.h>
#include <ntdef.h>
#include <stdlib.h>
#include "ntos.h"
KIRQL WPOFFx64()
{
	KIRQL irql = KeRaiseIrqlToDpcLevel();
	UINT64 cr0 = __readcr0();
	cr0 &= 0xfffffffffffeffff;
	__writecr0(cr0);
	_disable();
	return irql;
}

void WPONx64(KIRQL irql)
{
	UINT64 cr0 = __readcr0();
	cr0 |= 0x10000;
	_enable();
	__writecr0(cr0);
	KeLowerIrql(irql);
}
ULONG GetWindowsBuildNumber()
{
	// Get the Windows Version table.
	RTL_OSVERSIONINFOEXW osversion;
	osversion.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOEXW);
	RtlGetVersion(&osversion);

	return osversion.dwBuildNumber;
}

// https://docs.microsoft.com/en-us/windows/release-information/
// https://www.vergiliusproject.com/kernels/x64/Windows 10 | 2016/1903 19H1 (May 2019 Update)/_EPROCESS
int GetCorrectOffset(CHAR* Name, ULONG BuildNumber)
{
	// 1903 & 1909
	if (BuildNumber == 18362 || BuildNumber == 18363)
	{
		if (strcmp(Name, "ImageFileName") == 0)
		{
			return 0x450;
		}
		if (strcmp(Name, "ActiveThreads") == 0)
		{
			return 0x498;
		}
		if (strcmp(Name, "ActiveProcessLinks") == 0)
		{
			return 0x2F0;
		}
	}
	// 2004 & 2009 & 2104
	else if (BuildNumber == 19041 || BuildNumber == 19042 || BuildNumber == 19043)
	{
		if (strcmp(Name, "ImageFileName") == 0)
		{
			return 0x5a8;
		}
		if (strcmp(Name, "ActiveThreads") == 0)
		{
			return 0x5f0;
		}
		if (strcmp(Name, "ActiveProcessLinks") == 0)
		{
			return 0x448;
		}
	}

	return 0;
}

NTSTATUS KeReadVirtualMemory(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size)
{
	SIZE_T Bytes;
	if (NT_SUCCESS(MmCopyVirtualMemory(Process, SourceAddress, PsGetCurrentProcess(),
		TargetAddress, Size, KernelMode, &Bytes)))
	{
		return STATUS_SUCCESS;
	}
	return STATUS_ACCESS_DENIED;
}

NTSTATUS KeWriteVirtualMemory(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size)
{
	SIZE_T Bytes;
	if (NT_SUCCESS(MmCopyVirtualMemory(PsGetCurrentProcess(), SourceAddress, Process,
		TargetAddress, Size, KernelMode, &Bytes)))
	{
		return STATUS_SUCCESS;
	}
	return STATUS_ACCESS_DENIED;
}


NTSTATUS KeWriteReadOnlyCrMemory(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size)
{
	KIRQL irql = WPOFFx64();
	SIZE_T Bytes;
	if (1)
	{
		if (NT_SUCCESS(MmCopyVirtualMemory(PsGetCurrentProcess(), SourceAddress, Process,
			TargetAddress, Size, KernelMode, &Bytes)))
		{

			WPONx64(irql);

			return STATUS_SUCCESS;
		}
		else {

			

			return STATUS_ACCESS_DENIED;
		}
	}
}

NTSTATUS KeWriteReadOnlyMemory(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size)
{
	//KIRQL irql = WPOFFx64();
	//SIZE_T Bytes;
	NTSTATUS ntStatus = STATUS_SUCCESS;
	KAPC_STATE ApcState;
	PHYSICAL_ADDRESS SourcePhysicalAddress;
	PVOID MappedIoSpace;
	PVOID MappedKva;
	PMDL Mdl;
	BOOLEAN ShouldUseSourceAsUserVa;

	ShouldUseSourceAsUserVa = SourceAddress <= MmHighestUserAddress ? TRUE : FALSE;

	// 1. Attach to the process
	//    Sets specified process's PML4 to the CR3
	KeStackAttachProcess(Process, &ApcState);

	// 2. Get the physical address corresponding to the user virtual memory
	SourcePhysicalAddress = MmGetPhysicalAddress(
		ShouldUseSourceAsUserVa == TRUE ? SourceAddress : TargetAddress);

	// 3. Detach from the process
	//    Restores previous APC state to the current thread
	KeUnstackDetachProcess(&ApcState);

	if (!SourcePhysicalAddress.QuadPart)
	{
		return STATUS_INVALID_ADDRESS;
	}

	DbgPrint("[+] Source Physical Address: 0x%llX\n", SourcePhysicalAddress.QuadPart);

	// 4. Map an IO space for MDL
	MappedIoSpace = MmMapIoSpace(SourcePhysicalAddress, Size, MmNonCached);

	if (!MappedIoSpace)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	DbgPrint("[+] Physical Address 0x%llX is mapped to IO space 0x%p\n",
		SourcePhysicalAddress, MappedIoSpace);

	// 5. Allocate MDL
	Mdl = IoAllocateMdl(MappedIoSpace, sizeof(uintptr_t), FALSE, FALSE, NULL);

	if (!Mdl)
	{
		DbgPrint("[!] Failed to allocate MDL\n");
		MmUnmapIoSpace(MappedIoSpace, Size);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	MmProbeAndLockPages(Mdl, KernelMode, IoReadAccess);

	// 6. Build MDL for non-paged pool
	MmBuildMdlForNonPagedPool(Mdl);

	// 7. Map to the KVA
	MappedKva = MmMapLockedPagesSpecifyCache(
		Mdl,
		KernelMode,
		MmNonCached,
		NULL,
		FALSE,
		NormalPagePriority);

	if (!MappedKva)
	{
		DbgPrint("[!] Failed to map physical pages\n");
		MmUnmapIoSpace(MappedIoSpace, Size);
		IoFreeMdl(Mdl);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	DbgPrint("[+] Mapped to KVA 0x%p\n", MappedKva);

	// 8. copy memory
	RtlCopyMemory(MappedKva, &TargetAddress, sizeof(Size));

	MmUnmapIoSpace(MappedIoSpace, Size);
	MmUnmapLockedPages(MappedKva, Mdl);
	IoFreeMdl(Mdl);

	return ntStatus;
	
		
		return STATUS_ACCESS_DENIED;
	
}


NTSTATUS FindProcessByName(CHAR* process_name, vector* ls)
{
	ULONG BuildNumber = GetWindowsBuildNumber();
	PEPROCESS sys_process = PsInitialSystemProcess;
	PEPROCESS cur_entry = sys_process;

	int ImageFileNameOffset = GetCorrectOffset("ImageFileName", BuildNumber);
	int ActiveThreadsOffset = GetCorrectOffset("ActiveThreads", BuildNumber);
	int ActiveProcessLinksOffset = GetCorrectOffset("ActiveProcessLinks", BuildNumber);

	// Verify atleast one variable so we don't cause BSOD for unsupported builds.
	if (ImageFileNameOffset == 0)
	{
		//DebugMessageNormal("Warning: Unsupported Windows build. Update EPROCESS offsets. See README.md.\n");
		return STATUS_UNSUCCESSFUL;
	}

	CHAR image_name[15];

	do
	{
		RtlCopyMemory((PVOID)(&image_name), (PVOID)((uintptr_t)cur_entry + ImageFileNameOffset) /*EPROCESS->ImageFileName*/, sizeof(image_name));

		if (strstr(image_name, process_name))
		{
			DWORD active_threads;
			RtlCopyMemory((PVOID)&active_threads, (PVOID)((uintptr_t)cur_entry + ActiveThreadsOffset) /*EPROCESS->ActiveThreads*/, sizeof(active_threads));
			if (active_threads)
			{
				vector_add(ls, cur_entry);
			}
		}

		PLIST_ENTRY list = (PLIST_ENTRY)((uintptr_t)(cur_entry)+ActiveProcessLinksOffset) /*EPROCESS->ActiveProcessLinks*/;
		cur_entry = (PEPROCESS)((uintptr_t)list->Flink - ActiveProcessLinksOffset);

	} while (cur_entry != sys_process);

	return STATUS_SUCCESS;
}

MODULEENTRY GetProcessModule(PEPROCESS Process, LPCWSTR ModuleName)
{
	KAPC_STATE KAPC = { 0 };
	MODULEENTRY ret = { 0, 0 };

	KeStackAttachProcess(Process, &KAPC);
	__try
	{
		PPEB32 peb32 = (PPEB32)PsGetProcessWow64Process(Process);
		if (!peb32 || !peb32->Ldr)
		{
			KeUnstackDetachProcess(&KAPC);
			return ret;
		}

		for (PLIST_ENTRY32 plist_entry = (PLIST_ENTRY32)((PPEB_LDR_DATA32)peb32->Ldr)->InLoadOrderModuleList.Flink;
			plist_entry != &((PPEB_LDR_DATA32)peb32->Ldr)->InLoadOrderModuleList;
			plist_entry = (PLIST_ENTRY32)plist_entry->Flink)
		{
			PLDR_DATA_TABLE_ENTRY32 pentry = CONTAINING_RECORD(plist_entry, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);

			if (wcscmp((PWCH)pentry->BaseDllName.Buffer, ModuleName) == 0)
			{
				ret.Address = pentry->DllBase;
				ret.Size = pentry->SizeOfImage;
				break;
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		//DebugMessageNormal("%s: Exception, Code: 0x%X\n", __FUNCTION__, GetExceptionCode());
	}

	KeUnstackDetachProcess(&KAPC);

	return ret;
}

NTSTATUS KeAllocMemory(ULONG ProcessId, PULONG address, ULONG size) {
	PEPROCESS Process;
	if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &Process))) {
		NTSTATUS status;
		ULONG _SwitchPtr = 0x232;

		KAPC_STATE state;
		KeStackAttachProcess(Process, &state);

		PUCHAR pPrevMode = (PUCHAR)PsGetCurrentThread() + _SwitchPtr;
		UCHAR prevMode = *pPrevMode;

		*pPrevMode = KernelMode;

		PVOID dd = 0;
		status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &dd, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		*address = (ULONG)dd;
		*pPrevMode = prevMode;

		KeUnstackDetachProcess(&state);
	}

	return STATUS_SUCCESS;
}

NTSTATUS KeProtectVirtual(ULONG ProcessId, ULONG address, ULONG size, ULONG protect, PULONG oldprotect) {
	PEPROCESS Process;
	if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &Process))) {

		ULONG _SwitchPtr = 0x232;

		KAPC_STATE state;
		KeStackAttachProcess(Process, &state);

		PUCHAR pPrevMode = (PUCHAR)PsGetCurrentThread() + _SwitchPtr;
		UCHAR prevMode = *pPrevMode;
		*pPrevMode = KernelMode;

		PVOID addr = (PVOID)address;
		SIZE_T sz = (SIZE_T)size;
		NTSTATUS status;
		
		status = ZwProtectVirtualMemory(ZwCurrentProcess(), &addr, &sz, protect, oldprotect);

		*pPrevMode = prevMode;

		KeUnstackDetachProcess(&state);
	}

	return STATUS_SUCCESS;
}

NTSTATUS KeFreeMemory(ULONG ProcessId, ULONG address, ULONG size) {
	PEPROCESS Process;
	if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &Process))) {

		ULONG _SwitchPtr = 0x232;

		KAPC_STATE state;
		KeStackAttachProcess(Process, &state);

		PUCHAR pPrevMode = (PUCHAR)PsGetCurrentThread() + _SwitchPtr;
		UCHAR prevMode = *pPrevMode;
		*pPrevMode = KernelMode;

		PVOID addr = (PVOID)address;
		SIZE_T sz = (SIZE_T)size;
		NTSTATUS status;

		status = ZwFreeVirtualMemory(ZwCurrentProcess(), &addr, &sz, MEM_RELEASE);

		*pPrevMode = prevMode;

		KeUnstackDetachProcess(&state);
	}

	return STATUS_SUCCESS;
}