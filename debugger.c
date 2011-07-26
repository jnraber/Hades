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
#include "ntimage.h"
#include "debugger.h"

unsigned int gCR0 = 0;
unsigned char stolen_code[SIZE_OF_JMP+1] = {0};
unsigned char jmp_op[SIZE_OF_JMP+1] = {0};

unsigned int gEIP = 0;
unsigned int *breakpoint = NULL;
unsigned int gEAX = 0;
unsigned int gEBX = 0;
unsigned int gECX = 0;
unsigned int gEDX = 0;
unsigned int gESI = 0;
unsigned int gEDI = 0;
unsigned int gESP = 0;
unsigned int gEBP = 0;

unsigned int *g_ESI_ADDR = 0;
unsigned int *g_EBP_ADDR = 0;
unsigned int *g_EAX_ADDR = 0;
unsigned int *g_EBX_ADDR = 0;
unsigned int *g_ECX_ADDR = 0;
unsigned int *g_EDX_ADDR = 0;
unsigned int *g_ESP_ADDR = 0;
unsigned int *g_EDI_ADDR = 0;

//-----------------------------------------------------------------------------
// This is the area of memory that will be shared with kernel and user process 
//-----------------------------------------------------------------------------
void __declspec(naked) _cdecl shared_mem(void)
{  
	_asm {
		pushad         /* push all registers         */
		push BP1       /* my identifier to filter on */
		mov eax, 0x61  /* ZwLoadDriver identifier    */
		mov edx, esp
		_emit 0x0F     /* sysenter                   */
		_emit 0x34
	}

	// this code should never be hit due to hooked_ZwLoadDriver() jmping back 
	// to userspace :)
	//_asm {
	//	jmp breakpointAddr
	//}
}

//-----------------------------------------------------------------------------
// This function is used for the driver debugger, adjusts the stack and jumps 
// back to the user process
//-----------------------------------------------------------------------------
void __declspec(naked) _cdecl return_to_user_app()
{
	_asm
	{
		// since the gORIG_ESP is not the real orignal ESP I need to adjust it
		// to really be pointing to the real stack before restoring registers 
		// and changing control back to the debuggee
		mov eax, gORIG_ESP
		sub eax, 8 

		// now adjust the stack pointer to point to were it was
		mov esp, eax

		pop eax  // this is the BP
		popad    // pop all registers that were stored on the stack in  
		         // shared_mem()

		jmp gEIP
	}
}

//-----------------------------------------------------------------------------
// Interrupt from user space allows us to gain control to now act as a debugger 
//-----------------------------------------------------------------------------
void handle_bp(void)
{
	unsigned int endian = 0;

	debug("\t now handle the bp\n");
	
	save_context_dbg();

	// replace stolen bytes
	if (breakpoint)
	{
		debug("\t replace stolen bytes\n");
		debug("\t before: ");
		print_memory(breakpoint, 5);

		CLEAR_WP_FLAG;
		RtlCopyMemory(breakpoint, stolen_code, SIZE_OF_JMP);
		RESTORE_CR0;

		debug("\t after: ");
		print_memory(breakpoint, 5);
	
		// how to change registers
		//modify_register(my_EAX, 1);

		// now jump back right from the kernel to the user space where the BP.
		// NOTE: 
		// if you would like to change the EIP then instead of assigning the 
		// EIP to the BP you can change it to were ever you would like the 
		// instruction pointer to go
		debug("\t return control back to user space at loc 0x%X\n", BP1);
		gEIP = gBP;
		return_to_user_app();
	}
	else
		DbgPrint("\n!!! ERROR: breakpoint = NULL\n");
}
//-----------------------------------------------------------------------------
// Inject breakpoint into user space 
//-----------------------------------------------------------------------------
int add_bp(void)
{
	// dest - currentAddr - sizeJump
	unsigned int jmp_mine = (unsigned int)&shared_mem - BP1 - SIZE_OF_JMP;
	unsigned int jmp_shared = shared_user_mem - BP1 - SIZE_OF_JMP;

	// steal memory to be patched later...this will be were the breakpoint 
	// will be added - stolen_code is were stored
	RtlCopyMemory(stolen_code, breakpoint, SIZE_OF_JMP);

	if (jmp_mine > 0)
	{
		debug("\t\t\t adding bp to va 0x%X\n", BP1);

		jmp_op[0] = 0xE9;
		memcpy(jmp_op + 1, &jmp_shared, SIZE_OF_JMP);

		debug("\t\t\t generated bp jump ins to shared mem: ");
		print_memory(jmp_op, 5);

		// inject jmp into user space (reroute instruction pointer)
		CLEAR_WP_FLAG;
		RtlCopyMemory(breakpoint, jmp_op, SIZE_OF_JMP);
		RESTORE_CR0;
	}

	// copy shared memory function to shared user space memory
	CLEAR_WP_FLAG;
	RtlCopyMemory((PVOID)shared_kern_mem, shared_mem, SIZE_OF_SHARED_MEM);
	RESTORE_CR0;

	return 0;
}

//-----------------------------------------------------------------------------
// Target process loaded - this callback works well, however, if you 
// unload the driver it will cause a blue screen
//-----------------------------------------------------------------------------
VOID add_one_time_bp(PUNICODE_STRING name, HANDLE PID, PIMAGE_INFO image_info)
{
	unsigned int endian = 0;
	unsigned int addr = BP1;  
	UNICODE_STRING targ_proc;

	if (!name)
	{
		DbgPrint("\n!!! ERROR: add_hooks_for_data_mining() invalid name \n");
		return;
	}

	breakpoint = (unsigned int) addr;

	RtlInitUnicodeString(&targ_proc, target_file_loc);

	if (RtlCompareUnicodeString(name, &targ_proc, TRUE) == 0)
	{
		debug("targeted process got loaded - our callback was invoked\n");
		debug("\t add a one time bp to target process\n");
		debug("\t before memory bp = ");
		print_memory((unsigned int *)addr , 5);
		
		add_bp();

		debug("\t stolen bytes = ");
		print_memory(stolen_code, 5);

		debug("bp successfully added to user land at 0x%X\n\n", 
			     breakpoint);

		debug("let go\n\n");
	}
}

//-----------------------------------------------------------------------------
// Display contents of registers at a breakpoint      
//
// Print out the registers
//                 
//                STACK  (Low)
//               -------
//               | BP  | <- Breakpoint
//               | EDI |
//  gORIG_ESP -> | ESI |
//               | EBP |
//               | ESP |
//               | EBX |
//               | EDX |
//               | ECX |
//               | EAX | (High)
//               -------
//-----------------------------------------------------------------------------
void save_context_dbg()
{
	unsigned int *local_sp = (unsigned int *)gORIG_ESP;

	DbgPrint("\n\t\t !!! BREAKPOINT HIT @ %X!!!\n", gBP);

	// subtract first to point to EDI
	local_sp--; gEDI = *local_sp; g_EDI_ADDR = local_sp; 

	local_sp++; gESI = *local_sp; g_ESI_ADDR = local_sp;
	local_sp++; gEBP = *local_sp; g_EBP_ADDR = local_sp;
	local_sp++; gESP = *local_sp; g_ESP_ADDR = local_sp;
	local_sp++; gEBX = *local_sp; g_EBX_ADDR = local_sp;
	local_sp++; gEDX = *local_sp; g_EDX_ADDR = local_sp;
	local_sp++; gECX = *local_sp; g_ECX_ADDR = local_sp;
	local_sp++; gEAX = *local_sp; g_EAX_ADDR = local_sp;

	DbgPrint("\t\t EAX = 0x%.8X, EBX = 0x%.8X, ECX = 0x%.8X, EDX = 0x%.8X \n", 
		     gEAX, gEBX, gECX, gEDX);
	DbgPrint("\t\t ESI = 0x%.8X, EDI = 0x%.8X, ESP = 0x%.8X, EBP = 0x%.8X \n\n", 
		     gESI, gEDI, gESP, gEBP);
}

//-----------------------------------------------------------------------------
// Saved off registers and assigned an address to the registers.  Use that 
// address to save off the changed register
//-----------------------------------------------------------------------------
void modify_register(int reg, int value) 
{
	int badptr = 0;

	switch (reg) 
	{
	case EAX_ID: 
		if (g_EAX_ADDR) *g_EAX_ADDR = value;
		else             badptr = 1;
		break;
	case EBX_ID: 
		if (g_EBX_ADDR) *g_EBX_ADDR = value;
		else             badptr = 1;
		break;
	case ECX_ID: 
		if (g_ECX_ADDR) *g_ECX_ADDR = value;
		else             badptr = 1;
		break;
	case EDX_ID: 
		if (g_EDX_ADDR) *g_EDX_ADDR = value;
		else             badptr = 1;
		break;
	case ESI_ID: 
		if (g_ESI_ADDR) *g_ESI_ADDR = value;
		else             badptr = 1;
		break;
	case EDI_ID: 
		if (g_EDI_ADDR) *g_EDI_ADDR = value;
		else             badptr = 1;
		break;
	case EBP_ID: 
		if (g_EBP_ADDR) *g_EBP_ADDR = value;
		else             badptr = 1;
		break;
	case ESP_ID: 
		if (g_ESP_ADDR) *g_ESP_ADDR = value;
		else             badptr = 1;
		break;
	default:
		DbgPrint("internal Error modify_register() - No matching register");
		break;
	}

	if (badptr) 
		DbgPrint("\n!!! ERROR: Bad Address - modify_register()");
} 

