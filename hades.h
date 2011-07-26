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
#ifndef HADES_H
#define HADES_H

#include <ntddk.h>

// defines
#define DATA_MINING             0  
#define BREAK_POINT             1 

#define EAX_ID 1
#define ECX_ID 2
#define EDX_ID 3
#define EBX_ID 4
#define ESI_ID 5
#define EDI_ID 6
#define EBP_ID 7
#define ESP_ID 8
#define SIZE_OF_JMP 5
#define SIZE_OF_SHARED_MEM 0x800

// globals
extern unsigned int gORIG_ESP;
extern unsigned int gEAX;
extern unsigned int gEBX;
extern unsigned int gECX;
extern unsigned int gEDX;
extern unsigned int gESI;
extern unsigned int gEDI;
extern unsigned int gESP;
extern unsigned int gEBP;
extern unsigned int gBP;
void **syscall_tbl;
extern WCHAR target_file_loc[];

// Macros
#define CLEAR_WP_FLAG    \
{                        \
	__asm push eax       \
	__asm mov eax, cr0   \
	__asm mov gCR0, eax  \
	__asm and eax, 0xfffeffff   \
	__asm mov cr0,eax    \
	__asm pop eax        \
}

#define RESTORE_CR0      \
{                        \
	__asm push eax       \
	__asm mov eax, gCR0  \
	__asm mov cr0, eax   \
	__asm pop eax        \
}

extern int is_debug;
#define debug(f, ...) if (is_debug) DbgPrint(f, __VA_ARGS__) 

// Protypes
VOID add_one_time_bp(PUNICODE_STRING name, HANDLE PID, PIMAGE_INFO image_info);
VOID add_hooks_for_data_mining(PUNICODE_STRING name, HANDLE PID,
	                           PIMAGE_INFO image_info);
void save_context_dbg();
void modify_register(int reg, int value);
void handle_hooked_calls();
void handle_bp(void);
unsigned int endian_swap(unsigned int x);
int print_memory(unsigned int *addr, int bytes);

#define SYSCALL_INDEX(_Function) *(PULONG)((PUCHAR)_Function+1)
#pragma pack(1)
typedef struct sde 
{
	unsigned int *ServiceTableBase;
	unsigned int *ServiceCounterTableBase;
	unsigned int NumberOfServices;
	unsigned char *ParamTableBase;
} sdte, *Psdte;
#pragma pack()

__declspec(dllimport)  sdte KeServiceDescriptorTable;
#define SYSTEMSERVICE(_function)  KeServiceDescriptorTable.ServiceTableBase[ *(PULONG)((PUCHAR)_function+1)]

// function pointers
typedef NTSTATUS (*typeZwLoadDriver)(PUNICODE_STRING name);
typeZwLoadDriver orig_ZwLoadDriver;

#endif // HADES_H