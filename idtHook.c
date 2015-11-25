/* Author: Shp
 * Website: http://www.shp-box.fr
 * Date: the 4th of December 2010
 * Name: anti-debug IDT hook
 
 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.
 
 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU General Public License for more details.
 
 You should have received a copy of the GNU General Public License
 along with this program. If not, see http://www.gnu.org/licenses/
 
*/
 
#include <wdm.h>
 
/******************/
/*** Declarations ***/
/*****************/
 
typedef unsigned short WORD;
typedef unsigned long DWORD;
typedef long LONG;
typedef unsigned char BYTE;
 
typedef struct
{
   WORD IDTLimit;
   WORD LowIDTbase;
   WORD HiIDTbase;
} IDTINFO;
 
#define MAKELONG(a, b)((LONG)(((WORD)(a))|((DWORD)((WORD)(b))) << 16))
#define MAKELOW(a) ((WORD) a)
#define MAKEHIGH(a) ((WORD) ((LONG) ( ((LONG)a) >> 16) ))
 
#pragma pack(1)
typedef struct
{
    WORD LowOffset;
    WORD selector;
    BYTE unused_lo;
    unsigned char unused_hi:5; // stored TYPE ?
    unsigned char DPL:2;
    unsigned char P:1;         // vector is present
    WORD HiOffset;
} IDTENTRY;
#pragma pack()
 
void (*SaveInterrupt1ToHook)(); // the saves of the interrupts 0x01 and 0x03 we hook
void (*SaveInterrupt3ToHook)();
IDTENTRY *OurInterrupt1ToHook;
IDTENTRY *OurInterrupt3ToHook;
 
/***********/
/*** Core ***/
/***********/
 
__declspec(naked) HookInt1()
{
    __asm {
        iretd
    }
}
 
void HookInt3()
{
    __asm {
        iretd
    }
}
 
void HookIDT()
{
	IDTINFO IdtInfo;
	IDTENTRY *BeginArray;
 
	__asm {
		push ecx
		lea ecx, IdtInfo
		sidt fword ptr [ecx] // We get idt properties address
		pop ecx
	}
 
	BeginArray = (PVOID) ((IdtInfo.LowIDTbase)|((ULONG)IdtInfo.HiIDTbase<<16)); // The begin of the array of idt entries
 
	SaveInterrupt1ToHook = (unsigned long) MAKELONG(BeginArray[0x01].LowOffset, BeginArray[0x01].HiOffset);
	OurInterrupt1ToHook = (IDTENTRY *) &(BeginArray[0x01]); // We want to hook 0x01 interruption (used for debugging)
	SaveInterrupt3ToHook = (unsigned long) MAKELONG(BeginArray[0x03].LowOffset, BeginArray[0x03].HiOffset);
	OurInterrupt3ToHook = (IDTENTRY *) &(BeginArray[0x03]); // We want to hook 0x03 interruption (used for debugging)
 
	OurInterrupt1ToHook->LowOffset = MAKELOW(HookInt1);
	OurInterrupt1ToHook->HiOffset = MAKEHIGH(HookInt1);
	OurInterrupt3ToHook->LowOffset = MAKELOW(HookInt3);
	OurInterrupt3ToHook->HiOffset = MAKEHIGH(HookInt3);
}
 
VOID unloadFunction(PDRIVER_OBJECT pDriverObject)
{
	OurInterrupt1ToHook->LowOffset = MAKELOW(SaveInterrupt1ToHook);
	OurInterrupt1ToHook->HiOffset = MAKEHIGH(SaveInterrupt1ToHook);
 
	OurInterrupt3ToHook->LowOffset = MAKELOW(SaveInterrupt3ToHook);
	OurInterrupt3ToHook->HiOffset = MAKEHIGH(SaveInterrupt3ToHook);
 
	DbgPrint("[+] Driver unloaded\n");
}
 
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
	DbgPrint("[+] Driver loaded\n");
	pDriverObject->DriverUnload = unloadFunction;
 
	HookIDT();
 
	return STATUS_SUCCESS;
}
 
 
 
 

