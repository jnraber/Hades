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

wchar_t working_dir_dump[] = L"\\Device\\HarddiskVolume1\\Documents and Settings\\Administrator\\Desktop\\dump.bin";;

//-----------------------------------------------------------------------------
// D'oh 
//-----------------------------------------------------------------------------
unsigned int endian_swap(unsigned int x)
{
	unsigned int ret;

    ret = (x>>24) | 
        ((x<<8) & 0x00FF0000) |
        ((x>>8) & 0x0000FF00) |
        (x<<24);

	return ret;
}

//-----------------------------------------------------------------------------
// Print memory to DebugView
//-----------------------------------------------------------------------------
int print_memory(unsigned int *addr, int bytes)
{
	unsigned char buf[100] = {0};
	int num_bytes;

	memcpy(buf, addr, bytes);

	//DbgPrint("MEMORY READ @ %p - bytes %d\n", addr, bytes);

	for (num_bytes = 0; num_bytes < bytes; num_bytes += 5)
		debug("%.2X %.2X %.2X %.2X %.2X\n", buf[num_bytes],
		                                    buf[num_bytes+1], 
											buf[num_bytes+2], 
											buf[num_bytes+3], 
											buf[num_bytes+4]);


	return TRUE;
}

//-----------------------------------------------------------------------------
// Pretty much says it all
//-----------------------------------------------------------------------------
void dump_memory_to_file(unsigned int src_addr, int len)
{
	unsigned int *memory = NULL;
	UNICODE_STRING  kdump;
    NTSTATUS        ret; 
    HANDLE              Handle;
    IO_STATUS_BLOCK     IoStatusBlock;
    OBJECT_ATTRIBUTES   ObjectAttributes;

	RtlInitUnicodeString(&kdump, working_dir_dump);

    InitializeObjectAttributes(&ObjectAttributes, &kdump,
                               OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE,
                               NULL, NULL);

	ret = ZwCreateFile(&Handle, GENERIC_WRITE, &ObjectAttributes, 
		               &IoStatusBlock, NULL, 0, FILE_SHARE_WRITE, 
		               FILE_OPEN_IF, 
					   FILE_SYNCHRONOUS_IO_NONALERT|FILE_NON_DIRECTORY_FILE, 
					   NULL, 0); 

	// OK file created, now try and write to our file
    if (STATUS_SUCCESS == ret)
	{
		memory = (unsigned int *)src_addr;

		ret = ZwWriteFile(Handle, NULL, NULL, NULL, &IoStatusBlock,
			              memory, len,  NULL, NULL);

		if (!NT_SUCCESS(ret)) 
			DbgPrint( "\n!!! ERROR:ZwWriteFile Failed 0x%08X\n", ret);

		ret = ZwClose(Handle);
		if (!NT_SUCCESS(ret)) 
			DbgPrint( "\n!!! ERROR:ZwClose Failed 0x%08X\n", ret); 
	}
	else
		 DbgPrint("ZwCreateFile Failed 0x%08X\n", ret);

}

//-----------------------------------------------------------------------------
// Print out a memory range in dwords to file
//-----------------------------------------------------------------------------
void print_memory_range_file(int beginAddr, int num_dwords)
{
	int j = 0;
	int i = 0;
	char *ptrByte;
	int *ptrMem;
	int dwords = 0;
	int hexval[4] = {0};
	char ascval[4][4] = {0};

	ptrMem = (int *)beginAddr;

	DbgPrint( "---- Begin Memory Dump ----\n");

	for (dwords = 0; dwords < num_dwords; dwords += 4)
	{
		for (i = 0; i < 4; i++)
		{
			hexval[i] = *ptrMem;
			for (j = 0; j < 4; j++)
			{
				ptrByte = (char *)ptrMem;
				if (*ptrByte != 0x0a && *ptrByte+1 != 0)
					ascval[i][j] = *ptrByte;
				else
					ascval[i][j] = ' ';
				ptrByte++;
			}
			ptrMem++;
		}

		DbgPrint("%08.4X %08.4X %08.4X %08.4X\n", hexval[0], hexval[1], 
			                                      hexval[2], hexval[3]);
	}

	DbgPrint( "---- End Memory Dump ----\n");
}
