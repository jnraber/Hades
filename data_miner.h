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
#ifndef DATA_MINE_H 
#define DATA_MINE_H 

// defines
#define MAX_ARRAY_HOOKED_CALLS 200
#define START_ADDR        0x401000
#define IMAGE_SZ          0x9000
#define TRAMPOLINE_OFFSET 0xC

// prototypes
void _cdecl shared_mem_data_mining(void);
int reroute_function(void *orig_func, void *hooked_func);
void _cdecl restore_context_switch_dm();

// globals
extern unsigned int shared_user_mem; // user memory
extern unsigned int shared_kern_mem; // kernel memory
extern unsigned char stolen_code[SIZE_OF_JMP+1];
extern unsigned char jmp_op[SIZE_OF_JMP+1];
extern unsigned int gCR0;
extern unsigned int gID;
extern unsigned int gDM_EFLAGS;
extern unsigned int gEIP;

#endif