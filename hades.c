//
// Author: Jason Raber
// Riverside Research
// http://www.riversideresearch.org/labs/cyber_research_laboratory
//

/*
 *    This program is free software; you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation; either version 2 of the License, or
 *    (at your option) any later version.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 */


#include <ntddk.h>
#include "hades.h"
#include "data_miner.h"
#include "debugger.h"

// globals
WCHAR target_file_loc[] = L"\\Device\\HarddiskVolume1\\Documents and Settings\\Administrator\\Desktop\\Hello.exe";
int is_debug = 1;

PMDL  mdl_sys_call;
unsigned int shared_user_mem = 0x7ffe0800; // user memory
unsigned int shared_kern_mem = 0xffdf0800; // kernel memory
extern unsigned int gCR0;
unsigned int gORIG_ESP = 0;
unsigned int gBP = 0;

//-----------------------------------------------------------------------------
// hooked_ZwLoadDriver - Debugger/Data Code Mining protocol
//-----------------------------------------------------------------------------
NTSTATUS hooked_ZwLoadDriver(PUNICODE_STRING name)
{
	NTSTATUS ret = 0;

	// look for our identifier - our BP was pushed on the stack from shared_mem
	_asm
	{
		push eax
		mov eax, edx        // EDX == ESP 
		mov gORIG_ESP, eax  // Save off the ESP to be restored from the driver.
		                    // however, the alignment is off by 2 DWORDs...
		sub eax, 8          
		mov eax, [eax]
		mov gBP, eax
		pop eax
	}

	debug("\n[ user -> kernel ] hooked_ZwLoadDriver() gateway\n\n");

#if DATA_MINING
	{
		handle_hooked_calls();
		return ret;	
	}
#endif

	// found our breakpoint
#if BREAK_POINT	
	if (gBP == BP1)
	{
		handle_bp();
		return ret;
	}
#endif

	if (name)
	{
		ANSI_STRING strf;
		RtlUnicodeStringToAnsiString(&strf, name, TRUE);
		DbgPrint("\nZwLoadDriver( = ");
		DbgPrint(strf.Buffer);
		DbgPrint(")\n");
	}
	else
		DbgPrint("ZwLoadDriver(NULL)\n");

	ret = ((typeZwLoadDriver)(orig_ZwLoadDriver)) (name);

	DbgPrint("\nZwLoadDriver -> %d \n", ret);

	return ret;
}

//-----------------------------------------------------------------------------
// Hook the system calls to allow us to pass control from user to kernel...
// LoadDriver system call hook is our gateway
//-----------------------------------------------------------------------------
VOID hook_syscalls()
{
	debug("\t add hook to ZwLoadDriver to reroute to our " \
		  "hooked_ZwLoadDriver() \n");

	orig_ZwLoadDriver = 
		(void *)InterlockedExchange(
		(unsigned int *) &syscall_tbl[SYSCALL_INDEX(ZwLoadDriver)], 
		(unsigned int) hooked_ZwLoadDriver);
}

//-----------------------------------------------------------------------------
// Unload driver 
//-----------------------------------------------------------------------------
VOID OnUnload(IN PDRIVER_OBJECT DriverObject)
{
	DbgPrint("---------------- Driver Unloaded\n");

	InterlockedExchange(
		(unsigned int *) &syscall_tbl[SYSCALL_INDEX(ZwLoadDriver)], 
		(unsigned int) orig_ZwLoadDriver);

	if(mdl_sys_call)
	{
		MmUnmapLockedPages(syscall_tbl, mdl_sys_call);
		IoFreeMdl(mdl_sys_call);
	}

	// remove callback
#if BREAK_POINT
	PsRemoveLoadImageNotifyRoutine(add_one_time_bp);
#endif

#if DATA_MINING
	PsRemoveLoadImageNotifyRoutine(add_hooks_for_data_mining);
#endif
}

//-----------------------------------------------------------------------------
// MAIN
//-----------------------------------------------------------------------------
NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object, 
	                 PUNICODE_STRING registry_path)
{
	NTSTATUS ret;

	if (!driver_object)
	{
		DbgPrint("\n!!! ERROR: invalid driver_object in DriverEntry()\n");
		return STATUS_UNSUCCESSFUL;
	}
	driver_object->DriverUnload  = OnUnload;

	DbgPrint("---------------- Driver Loaded\n");

	// routine allocates a memory descriptor list (MDL) 
	mdl_sys_call = IoAllocateMdl(KeServiceDescriptorTable.ServiceTableBase, 
		                         KeServiceDescriptorTable.NumberOfServices * 4, 
								 FALSE, FALSE, NULL);
	if (!mdl_sys_call )
	{
		DbgPrint("\n!!! ERROR: invalid mdl in DriverEntry()\n");
		return STATUS_UNSUCCESSFUL;
	}

	MmBuildMdlForNonPagedPool(mdl_sys_call);

	mdl_sys_call->MdlFlags = mdl_sys_call->MdlFlags | MDL_MAPPED_TO_SYSTEM_VA;

	// map the physical pages 
    syscall_tbl = MmMapLockedPagesSpecifyCache(mdl_sys_call, KernelMode,
											   MmNonCached, NULL, FALSE,
											   HighPagePriority);

	if (!syscall_tbl)
	{
		DbgPrint("\n!!! ERROR: invalid mapped syscall table in DriverEntry()\n");
		return STATUS_UNSUCCESSFUL;
	}

	hook_syscalls();

	debug("register our callback for when our target proc is loaded:\n %ws\n\n",
		     target_file_loc);

#if BREAK_POINT
	// register a callback func that is invoked when our target proc is loaded
	ret = PsSetLoadImageNotifyRoutine(add_one_time_bp);
#endif

#if DATA_MINING
	ret = PsSetLoadImageNotifyRoutine(add_hooks_for_data_mining);
#endif

	if (ret != STATUS_SUCCESS)
		DbgPrint("\n!!! ERROR: PsSetLoadImageNotifyRoutine()\n\n");

	return STATUS_SUCCESS;
}

