/*
 * Copyright (c) 2015 Ahmed Samy  <f.fallen45@gmail.com>
 *
 * A simple or maybe tries to keep-it-simple driver to explore the world
 * of physical memory.
 *
 * (Un)maps physical memory to virtual memory into the calling process
 * address space (and obviously into kernel first).
 * This driver was intended for educational purposes, please do not use this
 * to exploit IRQs or whatever.
 *
 * Currently supported operations:
 *	- Map physical address into virtual address
 *	- Unmap virtual address from both kernel and user address space.
 *
 * Currently unsupported operations:
 *	- Find out what process a virtual address belongs to.
 *
 * NB: I am planning on supporting more operations but as previously stated,
 * this driver was made for educational purposes.
 * Although this is not really that kind of unique (or once in a time see) kind
 * of driver, it is still worth noting.
 *
 *							LICENSE
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
*/
#include <ntifs.h>
#include <ntddk.h>
#include <ntstrsafe.h>

#include "physmem.h"

#pragma warning(disable:4267)	//  'function' : conversion from 'size_t' to 'ULONG', possible loss of data

/*
 * We use this structure to store information about mapped
 * address(es) so we can free them later either via our
 * unload or on-demand.
 */
typedef struct {
	SINGLE_LIST_ENTRY node;	// list node (see mmap_head below)
	PMDL mdl;				// the mdl
	void *vaddr;			// kernel mapped virtual address
							// we could probably skip this and call MmGetSystemAddressForMdlSafe
							// but i like this better
	void *vaddr_user;		// user mapped virtual address
	size_t size;			// memory size
} mmap_t;

// We will push stuff into this thing for later freeing
static SINGLE_LIST_ENTRY	mmap_head;

static NTSTATUS physmem_ctl(IN PDEVICE_OBJECT device, IN PIRP irp)
{
	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION stack;
	rqaddr_t *addr_rq;				// must be passed
	PHYSICAL_ADDRESS phys;			// ...
	void *vaddr;					// physical address mapped to virtual (kernel)
	void *vaddr_user;				// physical address mapped to virtual (user)
	PMDL mdl;						// the mdl
	mmap_t *mapped_memory;			// we allocate this and push it into mmap_head for later
	PSINGLE_LIST_ENTRY node, prev;	// we use this to iterate through mapped memory so we can see
									// if we have previously allocated this particular virtual address
									// or not.  Also we use "prev" here so we can safely remove it from the list.

	UNREFERENCED_PARAMETER(device);
	stack = IoGetCurrentIrpStackLocation(irp);
	if (stack->MajorFunction == IRP_MJ_CREATE || stack->MajorFunction == IRP_MJ_CLOSE)
		goto out;

	if (stack->MajorFunction != IRP_MJ_DEVICE_CONTROL) {
		status = STATUS_INVALID_DEVICE_REQUEST;
		DbgPrint("PhysMem: Something went wrong");
		goto out;
	}

	// First, we have to verify that the size is sizeof(rqaddr_t).
	// This is because all our controls require rqaddr_t passed.
	if (stack->Parameters.DeviceIoControl.InputBufferLength != sizeof(rqaddr_t)) {
		status = STATUS_INFO_LENGTH_MISMATCH;
		DbgPrint("PhysMem: Invalid input buffer length! (%d)\n",
			stack->Parameters.DeviceIoControl.InputBufferLength);
		return STATUS_INFO_LENGTH_MISMATCH;
	}

	addr_rq = (rqaddr_t *)irp->AssociatedIrp.SystemBuffer;
	switch (stack->Parameters.DeviceIoControl.IoControlCode) {
	case IOCTL_PHYSMEM_MAP:	// map physical address into user address space (virtual)
		phys.QuadPart = (uintptr_t)addr_rq->addr;	// Grr...

		// First we map to kernel space
		// NB: We cannot just use MmGetVirtualForPhysical here...
		// since we're going to map this address in user space
		// We need to map it first to our (kernel) space and then
		// allocate a MDL to hold and map it to user space.
		vaddr = MmMapIoSpace(phys, addr_rq->size, MmNonCached);
		if (!vaddr) {
			DbgPrint("PhysMem: MmMapIoSpace(): Failed!\n");
			status = STATUS_INSUFFICIENT_RESOURCES;
			goto out;
		}

		mdl = IoAllocateMdl(vaddr, addr_rq->size, FALSE, FALSE, NULL);
		if (!mdl) {
			MmUnmapIoSpace(vaddr, addr_rq->size);
			DbgPrint("PhysMem: IoAllocateMdl failed!\n");

			status = STATUS_INSUFFICIENT_RESOURCES;
			goto out;
		}

		// Set it up
		MmBuildMdlForNonPagedPool(mdl);

		// map to user
		__try {
			// As per Microsoft documentation, this function can throw
			// an exception.
			// We could use MmMapLockedPages() here but according to Microsoft
			// it's deprecated as per Windows 2000+ or something similar and one should
			// use it only if the driver is to support that version, but we're not.
			// Well, like...  \\Device\\PhysicalMemory is freely openable there anyway
			// from usermode, plus a ZwMapViewOfSection and kaboom.
			vaddr_user = MmMapLockedPagesSpecifyCache(mdl, UserMode,
				MmNonCached, NULL, FALSE, NormalPagePriority);
		} __except (EXCEPTION_CONTINUE_EXECUTION)
		{
			IoFreeMdl(mdl);
			MmUnmapIoSpace(vaddr, addr_rq->size);
			DbgPrint("PhysMem: MmMapLockedPagesSpecifyCache failed!\n");

			status = STATUS_INSUFFICIENT_RESOURCES;
			goto out;
		}

		// Store it for later so we can free it once we're unloaded or
		// user wishes to free it.
		mapped_memory = ExAllocatePoolWithTag(NonPagedPool,
			sizeof(*mapped_memory), PHYSMEM_POOL_TAG);
		if (!mapped_memory) {
			// That's unfortunate...
			MmUnmapLockedPages(vaddr_user, mdl);
			IoFreeMdl(mdl);
			MmUnmapIoSpace(vaddr, addr_rq->size);

			DbgPrint("PhysMem: ExAllocatePoolWithTag failed!\n");
			status = STATUS_INSUFFICIENT_RESOURCES;
			goto out;
		}

		mapped_memory->mdl = mdl;
		mapped_memory->vaddr_user = vaddr_user;
		mapped_memory->vaddr = vaddr;
		mapped_memory->size = addr_rq->size;
		PushEntryList(&mmap_head, &mapped_memory->node);

		// pass it over to user
		irp->IoStatus.Information = sizeof(void *);
		RtlCopyMemory(irp->AssociatedIrp.SystemBuffer, &vaddr_user, sizeof(void *));

		irp->IoStatus.Status = STATUS_SUCCESS;
		IoCompleteRequest(irp, IO_NO_INCREMENT);

		DbgPrint("PhysMem: Successfully mapped physical address %X into kernel virtual address: %X"
					" and user: %X",
					phys.QuadPart, vaddr, vaddr_user);
		return STATUS_SUCCESS;
	case IOCTL_PHYSMEM_UNMAP:		// Request memory unmapping
		node = prev = mmap_head.Next;
		while (node) {
			mapped_memory = CONTAINING_RECORD(node, mmap_t, node);
			if (mapped_memory->vaddr_user == addr_rq->addr
				&& mapped_memory->size == addr_rq->size) {
				// Unmap from user space
				MmUnmapLockedPages(addr_rq->addr, mapped_memory->mdl);
				IoFreeMdl(mapped_memory->mdl);

				// then unmap from kernel space.
				MmUnmapIoSpace(mapped_memory->vaddr, mapped_memory->size);

				// Delete it from the list
				if (node == mmap_head.Next)		// head?
					mmap_head.Next = node->Next;
				else
					prev->Next = node->Next;

				// free da pool
				ExFreePoolWithTag(mapped_memory, PHYSMEM_POOL_TAG);

				irp->IoStatus.Status = STATUS_SUCCESS;
				irp->IoStatus.Information = 0;
				IoCompleteRequest(irp, IO_NO_INCREMENT);

				DbgPrint("PhysMem: Successfully unmapped virtual address %X (kernel: %X)",
					mapped_memory->vaddr_user, mapped_memory->vaddr);
				return STATUS_SUCCESS;
			}

			prev = node;
			node = node->Next;
		}

		// Not found
		DbgPrint("PhysMem: Failed to find specified virtual address: %X",
			addr_rq->addr);

		irp->IoStatus.Information = 0x7FFFFFFF;
		status = STATUS_INVALID_PARAMETER;
		goto out;
	case IOCTL_PHYSMEM_WHOIS:
		irp->IoStatus.Information = 0x7FFFFFFF;
		status = STATUS_NOT_IMPLEMENTED;
		goto out;
	}

out:
	irp->IoStatus.Status = status;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
}

static void driverUnload(IN PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING deviceLink;
	PSINGLE_LIST_ENTRY entry;
	mmap_t *mmap;
	int cleaned = 0;

	UNREFERENCED_PARAMETER(DriverObject);

	// Loop through entries and purge them
	entry = PopEntryList(&mmap_head);
	while (entry) {
		mmap = CONTAINING_RECORD(entry, mmap_t, node);

		// unmap from user space first
		MmUnmapLockedPages(mmap->vaddr_user, mmap->mdl);
		IoFreeMdl(mmap->mdl);

		// unmap from kernel space
		MmUnmapIoSpace(mmap->vaddr, mmap->size);

		// free ourselves
		ExFreePoolWithTag(mmap, PHYSMEM_POOL_TAG);

		// next
		entry = PopEntryList(&mmap_head);
		++cleaned;
	}

	// free device resources
	RtlInitUnicodeString(&deviceLink, L"\\DosDevices\\PhysMem");
	IoDeleteSymbolicLink(&deviceLink);
	IoDeleteDevice(DriverObject->DeviceObject);

	DbgPrint("Physmem: Driver unloaded, cleaned: %d entries\n", cleaned);
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
	NTSTATUS status;
	UNICODE_STRING deviceLink;
	UNICODE_STRING dosDeviceLink;
	PDEVICE_OBJECT deviceObject;

	UNREFERENCED_PARAMETER(RegistryPath);
	RtlInitUnicodeString(&deviceLink, DEVICE_LINK);
	status = IoCreateDevice(DriverObject,
		0,
		&deviceLink,
		FILE_DEVICE_PHYSMEM,
		0,
		TRUE,
		&deviceObject);
	if (!NT_SUCCESS(status)) {
		DbgPrint("Physmem: IoCreateDevice failed because Microsoft sucks\n");
		return status;
	}

	RtlInitUnicodeString(&dosDeviceLink, DEVICE_DOS);
	status = IoCreateSymbolicLink(&dosDeviceLink, &deviceLink);
	if (!NT_SUCCESS(status)) {
		DbgPrint("Physmem: IoCreateSymbolicLink failed because Microsoft sucks\n");
		IoDeleteDevice(deviceObject);
		return status;
	}

	DriverObject->MajorFunction[IRP_MJ_CREATE]			=
	DriverObject->MajorFunction[IRP_MJ_CLOSE]			=
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]	= physmem_ctl;
	DriverObject->DriverUnload = driverUnload;

	DbgPrint("Physmem: Ready for requests\n");
	return status;
}
