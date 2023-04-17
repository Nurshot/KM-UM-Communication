#pragma warning( disable : 4100 4047 4024 4022 4201 4311 4057 4213 4189 4081 4189 4706 4214 4459 4273)

#include "data.h"
#include "memory.h"
#include "communication.h"


NTSTATUS CreateCall(PDEVICE_OBJECT DeviceObject, PIRP irp)
{
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS CloseCall(PDEVICE_OBJECT DeviceObject, PIRP irp)
{
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

// IOCTL Call Handler function

NTSTATUS IoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	NTSTATUS Status;
	ULONG BytesIO = 0;

	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);

	// Code received from user space
	ULONG ControlCode = stack->Parameters.DeviceIoControl.IoControlCode;
	if (ControlCode == IO_READ_REQUEST)
	{
		// Get the input buffer & format it to our struct
		PKERNEL_READ_REQUEST ReadInput = (PKERNEL_READ_REQUEST)Irp->AssociatedIrp.SystemBuffer;

		PEPROCESS Process;

		// Get our process
		if (NT_SUCCESS(PsLookupProcessByProcessId(ReadInput->ProcessId, &Process))) {

			//read from ReadInput->Address and write it to pBuff so we can use the data in our controller
			KeReadVirtualMemory(Process, ReadInput->Address, ReadInput->pBuff, ReadInput->Size);
		}

		//DebugMessageNormal("Read Params:  %lu, %#010x \n", ReadInput->ProcessId, ReadInput->Address);
		//DebugMessageNormal("Value: %lu \n", ReadOutput->Response);

		Status = STATUS_SUCCESS;
		BytesIO = sizeof(KERNEL_READ_REQUEST);
	}
	else if (ControlCode == IO_WRITE_REQUEST)
	{
		// Get the input buffer & format it to our struct
		PKERNEL_WRITE_REQUEST WriteInput = (PKERNEL_WRITE_REQUEST)Irp->AssociatedIrp.SystemBuffer;

		PEPROCESS Process;
		// Get our process
		if (NT_SUCCESS(PsLookupProcessByProcessId(WriteInput->ProcessId, &Process))) {
			// copy the value of pBuff to WriteInput->Address
			KeWriteVirtualMemory(Process, WriteInput->pBuff, WriteInput->Address, WriteInput->Size);
		}

		//DebugMessageNormal("Write Params:  %lu, %#010x \n", WriteInput->Value, WriteInput->Address);

		Status = STATUS_SUCCESS;
		BytesIO = sizeof(KERNEL_WRITE_REQUEST);
	}
	else if (ControlCode == IO_WRITEREADONLY_REQUEST)
	{
		// Get the input buffer & format it to our struct
		PKERNEL_WRITEREADONLY_REQUEST WriteInput = (PKERNEL_WRITEREADONLY_REQUEST)Irp->AssociatedIrp.SystemBuffer;

		PEPROCESS Process;
		// Get our process
		if (NT_SUCCESS(PsLookupProcessByProcessId(WriteInput->ProcessId, &Process))) {
			// copy the value of pBuff to WriteInput->Address
			KeWriteReadOnlyMemory(Process, WriteInput->pBuff, WriteInput->Address, WriteInput->Size);
		}

		//DebugMessageNormal("Write Params:  %lu, %#010x \n", WriteInput->Value, WriteInput->Address);

		Status = STATUS_SUCCESS;
		BytesIO = sizeof(KERNEL_WRITEREADONLY_REQUEST);
	}
	else if (ControlCode == IO_WRITEREADONLYCR_REQUEST)
	{
		// Get the input buffer & format it to our struct
		PKERNEL_WRITEREADONLYCR_REQUEST WriteInput = (PKERNEL_WRITEREADONLYCR_REQUEST)Irp->AssociatedIrp.SystemBuffer;

		PEPROCESS Process;
		// Get our process
		if (NT_SUCCESS(PsLookupProcessByProcessId(WriteInput->ProcessId, &Process))) {
			// copy the value of pBuff to WriteInput->Address
			KeWriteReadOnlyCrMemory(Process, WriteInput->pBuff, WriteInput->Address, WriteInput->Size);
		}

		//DebugMessageNormal("Write Params:  %lu, %#010x \n", WriteInput->Value, WriteInput->Address);

		Status = STATUS_SUCCESS;
		BytesIO = sizeof(KERNEL_WRITEREADONLYCR_REQUEST);
	}
	else if (ControlCode == IO_GET_ID_REQUEST)
	{
		// Get the input buffer & format it to our struct
		DWORD ClientID = 31;
		PKERNEL_GET_ID_REQUEST GetIDReq = (PKERNEL_GET_ID_REQUEST)Irp->AssociatedIrp.SystemBuffer;
		vector processes;
		vector_init(&processes);

		FindProcessByName(GetIDReq->ClientName, &processes);

		if (vector_total(&processes) > 0)
		{
			// First should be good.
			PEPROCESS proc = (PEPROCESS)vector_get(&processes, 0);
			ClientID = (ULONG)PsGetProcessId(proc);
		}
		vector_free(&processes);

		*GetIDReq->pBuff = ClientID;

		Status = STATUS_SUCCESS;
		BytesIO = sizeof(PKERNEL_GET_ID_REQUEST);	
	}
	else if (ControlCode == IO_ALLOC_REQUEST)
	{
		DWORD AllocatedPointer = 0;
		PKERNEL_ALLOC_REQUEST AllocReq = (PKERNEL_ALLOC_REQUEST)Irp->AssociatedIrp.SystemBuffer;

		PEPROCESS Process;

		KeAllocMemory(AllocReq->ProcessId, &AllocatedPointer, AllocReq->size);

		*AllocReq->pBuff = AllocatedPointer;

		Status = STATUS_SUCCESS;
		BytesIO = sizeof(PKERNEL_ALLOC_REQUEST);
	}
	else if (ControlCode == IO_VIRTUAL_PROTECT)
	{
		ULONG OldProtect = 0;
		PKERNEL_VIRTUALPROTECT_REQUES ProtectReq = (PKERNEL_VIRTUALPROTECT_REQUES)Irp->AssociatedIrp.SystemBuffer;

		KeProtectVirtual(ProtectReq->ProcessId, ProtectReq->Address, ProtectReq->size, ProtectReq->Protect, &OldProtect);

		*ProtectReq->pBuff = OldProtect;

		Status = STATUS_SUCCESS;
		BytesIO = sizeof(PKERNEL_VIRTUALPROTECT_REQUES);
	}
	else if (ControlCode == IO_FREE_MEMORY)
	{
		ULONG OldProtect = 0;
		PKERNEL_FREEMEMORY_REQUEST ProtectReq = (PKERNEL_FREEMEMORY_REQUEST)Irp->AssociatedIrp.SystemBuffer;

		KeFreeMemory(ProtectReq->ProcessId, ProtectReq->Address, ProtectReq->size);

		Status = STATUS_SUCCESS;
		BytesIO = sizeof(PKERNEL_FREEMEMORY_REQUEST);
	}
	else
	{
		// if the code is unknown
		Status = STATUS_INVALID_PARAMETER;
	}

	// Complete the request
	Irp->IoStatus.Status = Status;
	Irp->IoStatus.Information = BytesIO;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return Status;

}