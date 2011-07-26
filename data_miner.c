
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
#include <ntimage.h>
#include "data_miner.h"


unsigned int gID = 0;
unsigned int array_hooked_calls[2][MAX_ARRAY_HOOKED_CALLS] = {0,0};
unsigned int gDM_EAX = 0;
unsigned int gDM_EBX = 0;
unsigned int gDM_ECX = 0;
unsigned int gDM_EDX = 0;
unsigned int gDM_ESI = 0;
unsigned int gDM_EDI = 0;
unsigned int gDM_ESP = 0;
unsigned int gDM_EBP = 0;
unsigned int gDM_EFLAGS = 0;
unsigned int caller_ret = 0;
unsigned int ret_hooked_func = 0;

//-----------------------------------------------------------------------------
//                 
//                STACK  (Low)
//               -------
//               | ID  | <- Rerouted function address
//               | FGS | <- EFLAGS
//  gORIG_ESP -> | EDI |
//               | ESI |
//               | EBP |
//               | ESP |
//               | EBX |
//               | EDX |
//               | ECX |
//               | EAX | (High)
//               | Ret | <- Callers return address
//               -------
//-----------------------------------------------------------------------------
void save_context()
{
	unsigned int *local_sp = (unsigned int *)gORIG_ESP;

	local_sp--; gDM_EFLAGS = *local_sp; 
	local_sp--; gID        = *local_sp; // get the ID (function address)
	
	local_sp++;

	local_sp++; gDM_EDI = *local_sp; 
	local_sp++; gDM_ESI = *local_sp;
	local_sp++; gDM_EBP = *local_sp; 
	local_sp++; gDM_ESP = *local_sp; 
	local_sp++; gDM_EBX = *local_sp; 
	local_sp++; gDM_EDX = *local_sp; 
	local_sp++; gDM_ECX = *local_sp; 
	local_sp++; gDM_EAX = *local_sp; 

	local_sp++; caller_ret = *local_sp; // get the callers return address

#if 0 // Print registers

	debug("\t save_context()\n");
	debug("\t EAX = %8X, EBX = %8X, ECX = %8X, EDX = %8X    \n",  gDM_EAX, 
		      gDM_EBX, gDM_ECX, gDM_EDX);
	debug("\t ESI = %8X, EDI = %8X, ESP = %8X, EBP = %8X    \n", gDM_ESI, 
		      gDM_EDI, gDM_ESP, gDM_EBP);
	debug("\t caller return = %8X,  gID = %8X, gORIG_ESP = %8X \n", 
		      caller_ret, gID, gORIG_ESP);
	debug("\t Flags = %0.8Xx\n",  gDM_EFLAGS);
	debug("\t ------------------------------------------------------------------------------------------- \n");
#endif

}

//-----------------------------------------------------------------------------
// Find and return the hooked call address
//-----------------------------------------------------------------------------
unsigned int get_hooked_call_addr()
{
	unsigned int hooked_call = 0;
	int i = 0;

	for (i = 0; i < MAX_ARRAY_HOOKED_CALLS; i++)
	{
		if (array_hooked_calls[0][i] == gID)
		{
			hooked_call = array_hooked_calls[1][i];
			break;
		}
	}

	return hooked_call;
}

//-----------------------------------------------------------------------------
//                 
//                STACK  (Low)
//               -------
//               | ID  | <- Identifier (User Hooked Function Addr)
//               | EFG | <- EFLAGS
//  gORIG_ESP -> | EDI |
//               | ESI |
//               | EBP |
//               | ESP |
//               | EBX |
//               | EDX |
//               | ECX |
//               | EAX | (High)
//               | RET | <- Return address of the caller (Orig. stack frame before invokation of function)
//               -------
//-----------------------------------------------------------------------------
void handle_hooked_calls()
{
	unsigned int hooked_call = 0;

	save_context();

	debug("0x%X targeted function exec.  Reroute to our hooked code\n", gID);
	hooked_call = get_hooked_call_addr();

	if (hooked_call == 0)
	{
		DbgPrint("\n!!! ERROR: Invalid hooked_call in handle_hooked_calls()\n");
		return;
	}

	// adjust stack - Just bypass the registers that have been pushed on the 
	// stack and get the stack pointer to point to the return address that 
	// was pushed on the caller
	_asm
	{
		mov eax, gORIG_ESP
		add eax, 0x20  /* Change esp to point to the "RET" on the stack */
		mov esp, eax
		jmp hooked_call
	}
}

//-----------------------------------------------------------------------------
// Restore the context and jumps back to the user process
//-----------------------------------------------------------------------------
void __declspec(naked) _cdecl restore_context_switch_dm()
{
	_asm
	{
		// when calling a "naked" function there is no "Ret"...even if there 
		// was we don't want to do that since we are adjusting the stack to 
		// how it was before the call from user space...So, pop the 
		// return address (hooked_func_funcname defined below) then jmp to 
		// it after :)
		pop ret_hooked_func

		mov eax, gDM_EAX
		mov ebx, gDM_EBX
		mov ecx, gDM_ECX
		mov edx, gDM_EDX
		mov esi, gDM_ESI
		mov edi, gDM_EDI
		mov ebp, gDM_EBP

		mov esp, gDM_ESP

		jmp ret_hooked_func
	}
}

//-----------------------------------------------------------------------------
// Reroute functions in a user space process
//-----------------------------------------------------------------------------
int reroute_function(void *orig_func, void *hooked_func)
{
	static int offset = 0;
	static int idx = 0;
	unsigned int jmp_mine = 0;
	unsigned int jmp_shared = 0; 

	if (!orig_func || !hooked_func)
	{
		DbgPrint("\n!!! ERROR: Invalid ptr in reroute_function()\n\n");
		return FALSE;
	}

	debug("rerouting target function %p -> %p\n", orig_func, hooked_func);

	// Dest - CurrentAddr - SizeJump
	//
	// NOTE: Why offset?  Look at function shared_mem_data_mining()...
	// There are 0xC bytes offset for each hooked function
	// that the user process needs to jump to in shared memory space.  Just 
	// make sure that the order of the hooked functions is important
	if (offset != 0)
	{
		jmp_shared = (shared_user_mem + offset) - 
			         (unsigned int)orig_func - SIZE_OF_JMP;
	}
	else
	{
		jmp_shared = shared_user_mem - (unsigned int)orig_func - SIZE_OF_JMP;
	}

	offset += TRAMPOLINE_OFFSET;
	
	jmp_op[0] = 0xE9;
	memcpy(jmp_op+1, &jmp_shared, SIZE_OF_JMP);

	// inject jmp into user space (reroute instruction pointer)
	CLEAR_WP_FLAG;
	RtlCopyMemory(orig_func, jmp_op, SIZE_OF_JMP);
	RESTORE_CR0;

	// save off the hooked function addresses
	if (idx < MAX_ARRAY_HOOKED_CALLS)
	{
		array_hooked_calls[0][idx] = (unsigned int)orig_func;
		array_hooked_calls[1][idx] = (unsigned int)hooked_func;
		idx++;
	}
	else
		DbgPrint("\n!!! ERROR: MAX_ARRAY_HOOKED_CALLS exceeded\n");

	return TRUE;
}

