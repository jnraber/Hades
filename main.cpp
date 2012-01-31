
#include <fstream>
#include <string>

#define _WIN32_WINNT        0x0400
#define WIN32
#define NT

#include <windows.h>
#include <iostream>
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>

//-----------------------------------------------------------------------------
// TIB is a data structure in Win32 on x86 that stores info 
// about the currently running thread
// it can be accessed through the Segment register 
// FS (fs:[#])
bool IsDebuggerLoaded() 
{
	_asm 
	{
		mov eax, fs:[30h]		     // pointer to PEB through TIB
		movzx eax, byte ptr[eax+0x2] // offset to BeingDebugged
		or al,al
		jz normal_
		jmp out_
	out_:
		mov eax, 0x1
		jmp my_exit
	normal_:
		xor eax, eax

	my_exit:
		nop
	}
}

//-----------------------------------------------------------------------------
__inline bool CheckForCCs(void *address) 
{
	_asm 
	{
		mov esi, address	// load function address
		mov al, [esi]		// load the opcode
		cmp al, 0xCC		// check if the opcode is CCh
		je BPXed		// yes, there is a breakpoint

		// jump to return true
		xor eax, eax		// false,
		jmp NOBPX		// no breakpoint
	BPXed:
		mov eax, 1		// breakpoint found
	NOBPX:
	}
}

//-----------------------------------------------------------------------------
bool dll_loaded(const char *dll_name)
{
	bool ret = false;
	HMODULE mods[1024] = {0};
    unsigned long needed;
    unsigned int i;

	HANDLE proc = GetCurrentProcess();
    if (!proc)
		return false;

    if(EnumProcessModules(proc, mods, sizeof(mods), &needed))
    {
        for ( i = 0; i < (needed / sizeof(HMODULE)); i++ )
        {
			char name[MAX_PATH] = TEXT("<unknown>");
			
			GetModuleBaseName(proc, mods[i], name, sizeof(name)/sizeof(char));
			
			if (!strcmp(name, dll_name))
			{
				ret = true;
				break;
			}
        }
    }

    CloseHandle(proc);

	return ret;
}
using namespace std ;

int main(void)
{
	if (IsDebuggerPresent()) 
		printf("Debugger detected - IsDebuggerPresent\n");
	else printf("No debugger detected - IsDebuggerPresent\n");

	if (IsDebuggerLoaded()) 
		printf("Debugger detected - PEB\n");
	else printf("No debugger detected - PEB\n");

	if(CheckForCCs(&main)) 
		printf("Debugger detected - CC\n");
	else printf("No debugger detected - CC\n");

	if (dll_loaded("detoured.dll"))
		printf("Detours detected - detoured.dll\n");
	else printf("No Detours detected - detoured.dll\n");

	return 0;
}
