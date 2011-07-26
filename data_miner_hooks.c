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
#include "hades.h"
#include "data_miner.h"

static void (__cdecl * target_foo2)(int) = NULL;
static void (__cdecl * target_foo4)(int, int) = NULL;

PMDL mdl_user_proc = NULL;

//-----------------------------------------------------------------------------
// This is the area of memory that will be shared with kernel and user process
// Each ID code block is 0xC bytes in length
//-----------------------------------------------------------------------------
void __declspec(naked) _cdecl shared_mem_data_mining(void)
{  
	_asm {
		pushad             /* push all registers */
		pushfd             /* push flags */
		push 0x409870      /* ID */
		jmp dword ptr MyHandler
		pushad             /* push all registers */
		pushfd             /* push flags */
		push 0x4098B0      /* ID */
		jmp dword ptr MyHandler
MyHandler:
		mov eax, 0x61      /* ZwLoadDriver identifier */
		mov edx, esp
		_emit 0x0F         /* sysenter */
		_emit 0x34
	}
}


//-----------------------------------------------------------------------------
// Hooked functions
//-----------------------------------------------------------------------------
void __cdecl hooked_foo2(int a)
{
	DbgPrint("hooked_foo2(%X)\n", a);
	debug("restore context\n");
	debug("let go\n");

	restore_context_switch_dm();

	_asm
	{
		// Execute stolen bytes
		_emit 0x55                //push ebp
		_emit 0x8B                //mov ebp, esp
		_emit 0xEC
		_emit 0x8B                //mov eax, dword ptr [ebp+8]
		_emit 0x45
		_emit 0x08

		// Jump to user process
		add gID, 6

		// Restore the eflags
		push gDM_EFLAGS
		popfd

		jmp gID
	}
}

void __cdecl hooked_foo4(int a,int b)
{
	DbgPrint("hooked_foo4(%X, %X)\n", a, b);
	debug("restore context\n");
	debug("let go\n");
	
	restore_context_switch_dm();

	_asm
	{
		// Execute stolen bytes
		_emit 0x55                //push ebp
		_emit 0x8B                //mov ebp, esp
		_emit 0xEC
		_emit 0x51                //push ecx
		_emit 0x8B                //mov eax, dword ptr [ebp+8]
		_emit 0x45
		_emit 0x08

		// Jump to user process
		add gID, 7

		// Restore the eflags
		push gDM_EFLAGS
		popfd

		jmp gID
	}
}

//-----------------------------------------------------------------------------
// Target process is loaded in memory - now data mine it
//-----------------------------------------------------------------------------
VOID add_hooks_for_data_mining(PUNICODE_STRING name, HANDLE PID,
	                           PIMAGE_INFO image_info)
{
	UNICODE_STRING target_proc;

	if (!name)
	{
		DbgPrint("\n!!! ERROR: add_hooks_for_data_mining() invalid ptr to name \n");
		return;
	}

	RtlInitUnicodeString(&target_proc, target_file_loc);

	if (RtlCompareUnicodeString(name, &target_proc, TRUE) == 0)
	{
		int image_sz = IMAGE_SZ;
		unsigned int *start_addr = START_ADDR;

		debug("targeted process got loaded - our callback was invoked\n");
		debug("\t add function hooks to target process\n");

		// routine allocates a memory descriptor list (MDL) 
		mdl_user_proc = IoAllocateMdl(start_addr, image_sz, FALSE, FALSE, NULL);
		if (!mdl_user_proc)
		{
			DbgPrint("\n!!! ERROR: invalid mdl in add_hooks_for_data_mining()\n");
			return;
		}
		MmProbeAndLockPages(mdl_user_proc, KernelMode, IoReadAccess);

		//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
		//
		// ADD HOOKED CODE HERE
		//
		//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
		target_foo2 = (int (__cdecl *)(int))0x409870;
		reroute_function(target_foo2, hooked_foo2);
		
		target_foo4 = (int (__cdecl *)(int, int))0x4098B0;
		reroute_function(target_foo4, hooked_foo4);

		// copy shared memory function to shared user space memory
		CLEAR_WP_FLAG;
		RtlCopyMemory((PVOID)shared_kern_mem, shared_mem_data_mining, 
			           SIZE_OF_SHARED_MEM);
		RESTORE_CR0;

		if (mdl_user_proc)
		{
			MmUnlockPages(mdl_user_proc);
			IoFreeMdl(mdl_user_proc);
		}
	}
}
