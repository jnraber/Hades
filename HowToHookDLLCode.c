
// THIS FILE IS GENERATED
#include "hades.h"
#include "GeneratedDataMiner.h"

static int ( * Real___tmainCRTStartup)(void) = NULL;
static int ( * Real__GetCommandLineA)(void) = NULL;


//TODO: update these 2 globals + Filename
//Also update the file.exe name in DataMining_OGA
int gsizeofImage = 0xDFFF;
unsigned int *gpStartAddr = 0x401000;
extern PMDL gmdlUserProcess;
extern unsigned int gCallerRet;
extern unsigned int gDM_EFLAGS;


//-----------------------------------------------------------------------------------------------------------------------------
// Shared Memory
//-----------------------------------------------------------------------------------------------------------------------------
void __declspec(naked) _cdecl SharedMemory_DataMining_OGA(void)
{
	_asm {

	 pushad
	 pushfd
	 push 0x401232  /* ID */
	 jmp dword ptr MyHandler
 	 pushad
	 pushfd
	 push 0x7C812C8D  /* ID */
	 jmp dword ptr MyHandler
MyHandler:
	 mov eax, 0x61   /* ZwLoadDriver identifier */
	 mov edx, esp
	 _emit 0x0F    /* sysenter */
	 _emit 0x34
	 }
}

//-----------------------------------------------------------------------------------------------------------------------------
// DLL hooked
//-----------------------------------------------------------------------------------------------------------------------------
int  Mine__GetCommandLineA(void)
{
	DbgPrint(" [[[ %X ]]] \n ", gCallerRet);
	
	DbgPrint("_GetCommandLineA@0 (void)\n");

	 restore_context_switch_OGA();

	 _asm { 
	 add gID, 5

	 // Restore the eflags
	 push gDM_EFLAGS
	 popfd
	 _emit 0xA1
	 _emit 0xF4
	 _emit 0x35
	 _emit 0x88
	 _emit 0x7C

	 jmp gID
	}
}

//-----------------------------------------------------------------------------------------------------------------------------
// MainCRTStartup code - must be hooked first
//-----------------------------------------------------------------------------------------------------------------------------
int  Mine___tmainCRTStartup(void)
{
	DbgPrint(" [[[ %X ]]] \n ", gCallerRet);
	
	DbgPrint("__tmainCRTStartup (void)\n");

	    //++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
	    // Added DLL hooked code here
	    //++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
		Real__GetCommandLineA = (int ( *)(void))0x7C812C8D;
		add_RerouteCode_OGA(Real__GetCommandLineA, Mine__GetCommandLineA);

	 restore_context_switch_OGA();

	 _asm { 
	 add gID, 7

	 // Restore the eflags
	 push gDM_EFLAGS
	 popfd
	 _emit 0x6A
	 _emit 0x1C
	 _emit 0x68
	 _emit 0xF0
	 _emit 0xE6
	 _emit 0x40
	 _emit 0x0

	 jmp gID
	}
}


//--------------------------------------------------------------------------
// Process loaded - now data mine it
//--------------------------------------------------------------------------
VOID DataMining_OGA(IN PUNICODE_STRING  FullImageName, IN HANDLE  ProcessId, IN PIMAGE_INFO  ImageInfo)
{
	UNICODE_STRING u_targetProcess;
	RtlInitUnicodeString(&u_targetProcess, L"\\Device\\HarddiskVolume1\\Documents and Settings\\hp1\\Desktop\\Hades\\Hello.exe");

	if (RtlCompareUnicodeString(FullImageName, &u_targetProcess, TRUE) == 0)
	{
		// Probes the specified virtual memory pages, makes them resident, and locks them in memory
		gmdlUserProcess = MmCreateMdl(NULL, gpStartAddr, gsizeofImage);
		MmProbeAndLockPages(gmdlUserProcess, KernelMode, IoReadAccess);

		//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
		// ADD HOOKED CODE HERE
		//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
		Real___tmainCRTStartup = (int ( *)(void))0x401232;
		add_RerouteCode_OGA(Real___tmainCRTStartup, Mine___tmainCRTStartup);

		//-------------------------------------------------------------------------------------------------------------------------
		// Copy shared memory function to shared user space memory
		//-------------------------------------------------------------------------------------------------------------------------

		CLEAR_WP_FLAG;
		RtlCopyMemory((PVOID)g_shared_kernelMem, SharedMemory_DataMining_OGA, SIZE_OF_SHARED_MEM);
		RESTORE_CR0;

		if (gmdlUserProcess)
		{
			MmUnlockPages(gmdlUserProcess);
			IoFreeMdl(gmdlUserProcess);
		}
	}
}

