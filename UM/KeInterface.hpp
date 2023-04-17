#pragma once

#include <Windows.h>

#define PAGE_SIZE 0x1000


#define IO_READ_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0641, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#define IO_WRITE_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0642, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#define IO_ALLOC_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0645, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#define IO_VIRTUAL_PROTECT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0646, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#define IO_FREE_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0647, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#define IO_WRITEREADONLY_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0648, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

typedef struct _KERNEL_READ_REQUEST
{
	ULONG ProcessId;

	ULONG Address;
	PVOID pBuff;
	ULONG Size;

} KERNEL_READ_REQUEST, * PKERNEL_READ_REQUEST;

typedef struct _KERNEL_WRITE_REQUEST
{
	ULONG ProcessId;

	ULONG Address;
	PVOID pBuff;
	ULONG Size;

} KERNEL_WRITE_REQUEST, * PKERNEL_WRITE_REQUEST;

typedef struct _KERNEL_GET_ID_REQUEST
{
	const char* ClientName;
	ULONG* pBuff;
} KERNEL_GET_ID_REQUEST, * PKERNEL_GET_ID_REQUEST;

typedef struct _KERNEL_ALLOC_REQUEST
{
	ULONG ProcessId;
	ULONG size;
	ULONG* pBuff;
} KERNEL_ALLOC_REQUEST, * PKERNEL_ALLOC_REQUEST;

typedef struct _KERNEL_VIRTUALPROTECT_REQUEST
{
	ULONG ProcessId;
	ULONG Address;
	ULONG size;
	ULONG Protect;
	ULONG* pBuff;
}KERNEL_VIRTUALPROTECT_REQUEST, * PKERNEL_VIRTUALPROTECT_REQUES;

typedef struct _KERNEL_FREEMEMORY_REQUEST
{
	ULONG ProcessId;
	ULONG Address;
	ULONG size;
}KERNEL_FREEMEMORY_REQUEST, * PKERNEL_FREEMEMORY_REQUEST;

typedef struct _KERNEL_WRITEREADONLY_REQUEST
{
	ULONG ProcessId;

	ULONG Address;
	PVOID pBuff;
	ULONG Size;
} KERNEL_WRITEREADONLY_REQUEST, * PKERNEL_WRITEREADONLY_REQUEST;

class KeInterface
{
public:
	HANDLE hDriver;

	KeInterface(LPCSTR RegistryPath)
	{
		hDriver = CreateFileA(RegistryPath, GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
	}

	template <typename type>
	type ReadVirtualMemory(ULONG ProcessId, ULONG ReadAddress, SIZE_T Size)
	{
		type Buffer;

		DWORD Return, Bytes;
		KERNEL_READ_REQUEST ReadRequest;


		ReadRequest.ProcessId = ProcessId;
		ReadRequest.Address = ReadAddress;

		ReadRequest.pBuff = &Buffer;

		ReadRequest.Size = Size;

		if (DeviceIoControl(hDriver, IO_READ_REQUEST, &ReadRequest, sizeof(ReadRequest), &ReadRequest, sizeof(ReadRequest), 0, 0))
		{
			//return our buffer
			return Buffer;
		}
		return Buffer;
	}

	template <typename type>
	bool WriteVirtualMemory(ULONG ProcessId, ULONG WriteAddress, type WriteValue, SIZE_T WriteSize)
	{
		if (hDriver == INVALID_HANDLE_VALUE)
			return false;
		DWORD Bytes;

		KERNEL_WRITE_REQUEST  WriteRequest;
		WriteRequest.ProcessId = ProcessId;
		WriteRequest.Address = WriteAddress;

		WriteRequest.pBuff = &WriteValue;

		WriteRequest.Size = WriteSize;

		if (DeviceIoControl(hDriver, IO_WRITE_REQUEST, &WriteRequest, sizeof(WriteRequest), 0, 0, &Bytes, NULL))
		{
			return true;
		}
		return false;
	}


	template <typename type>
	bool WriteReadOnlyMemory(ULONG ProcessId, ULONG WriteAddress, type WriteValue, SIZE_T WriteSize)
	{
		if (hDriver == INVALID_HANDLE_VALUE)
			return false;
		DWORD Bytes;

		KERNEL_WRITE_REQUEST  WriteReadOnlyRequest;
		WriteReadOnlyRequest.ProcessId = ProcessId;
		WriteReadOnlyRequest.Address = WriteAddress;

		WriteReadOnlyRequest.pBuff = &WriteValue;

		WriteReadOnlyRequest.Size = WriteSize;

		if (DeviceIoControl(hDriver, IO_WRITEREADONLY_REQUEST, &WriteReadOnlyRequest, sizeof(WriteReadOnlyRequest), 0, 0, &Bytes, NULL))
		{
			return true;
		}
		return false;
	}

	DWORD AllocMem(ULONG ProcessId, ULONG size) {
		if (hDriver == INVALID_HANDLE_VALUE)
			return false;

		DWORD Address;

		KERNEL_ALLOC_REQUEST AllocReq;
		AllocReq.ProcessId = ProcessId;
		AllocReq.size = size;
		AllocReq.pBuff = &Address;

		if (DeviceIoControl(hDriver, IO_ALLOC_REQUEST, &AllocReq, sizeof(AllocReq), &AllocReq, sizeof(AllocReq), 0, 0))
		{
			return Address;
		}
		return Address;
	}

	bool VirtualProtect(ULONG ProcessId, ULONG Address, ULONG size, ULONG Protect, PULONG OldProtect) {
		if (hDriver == INVALID_HANDLE_VALUE)
			return false;


		KERNEL_VIRTUALPROTECT_REQUEST ProtectReq;
		ProtectReq.ProcessId = ProcessId;
		ProtectReq.Address = Address;
		ProtectReq.size = size;
		ProtectReq.Protect = Protect;
		ProtectReq.pBuff = OldProtect;

		if (DeviceIoControl(hDriver, IO_VIRTUAL_PROTECT, &ProtectReq, sizeof(ProtectReq), &ProtectReq, sizeof(ProtectReq), 0, 0))
		{
			return true;
		}
		return false;
	}

	void FreeMemory(ULONG ProcessId, ULONG Address, ULONG size) {
		if (hDriver == INVALID_HANDLE_VALUE)
			return;


		KERNEL_FREEMEMORY_REQUEST FreeMemReq;
		FreeMemReq.ProcessId = ProcessId;
		FreeMemReq.Address = Address;
		FreeMemReq.size = size;

		DeviceIoControl(hDriver, IO_FREE_MEMORY, &FreeMemReq, sizeof(FreeMemReq), &FreeMemReq, sizeof(FreeMemReq), 0, 0);
	}

	

};