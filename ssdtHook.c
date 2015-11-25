/* Author: Shp
 * Website: http://www.shp-box.fr
 * Date: the 9th of October 2010
 * Name: ssdt hook ZwSetValueKey
 
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
 
/****************/
/* Declarations */
/****************/
 
#pragma pack(1)
typedef struct ServiceDescriptorEntry {
    unsigned int *ServiceTableBase;
    unsigned int *ServiceCounterTableBase;
    unsigned int NumberOfServices;
    unsigned char *ParamTableBase;
} SSDT_Entry;
#pragma pack()
 
__declspec(dllimport) SSDT_Entry KeServiceDescriptorTable; // We import KeServiceDescriptorTable (ntoskrnl.exe)
 
// SYSTEMSERVICE returns the address of the Nt* function corresponding to the Zw* function we put in argument
#define SYSTEMSERVICE(_func) \
  KeServiceDescriptorTable.ServiceTableBase[ *(PULONG)((PUCHAR)_func+1)]
 
typedef NTSTATUS (*ZWSETVALUEKEY)( // The type of the target function
    HANDLE  KeyHandle,
    PUNICODE_STRING  ValueName,
    ULONG  TitleIndex  OPTIONAL,
    ULONG  Type,
    PVOID  Data,
    ULONG  DataSize
);
 
ZWSETVALUEKEY ZwSetValueKeyOriginal; // We will call this function to call the original target function when its address will be replaced by our hook function address in the SSDT
 
 
/*******************/
/* The Hook Function */
/*******************/
 
// Our hook function will avoid values writing for "Run" and "RunOnce" key: in this way it prevents malwares from writing their path in those keys in order to open up at each reboot.
NTSTATUS ZwSetValueKeyHook(
    IN HANDLE  KeyHandle,
    IN PUNICODE_STRING  ValueName,
    IN ULONG  TitleIndex  OPTIONAL,
    IN ULONG  Type,
    IN PVOID  Data,
    IN ULONG  DataSize
)
{
	PKEY_BASIC_INFORMATION pKeyInformation = NULL;
	int i, flag = 1;
	NTSTATUS ret;
	WCHAR targetKey1[] = L"Run"; // first key target
	WCHAR targetKey2[] = L"RunOnce"; // second key target
	unsigned long size = 0, sizeNeeded = 0;
 
	DbgPrint("[+] In da hook function =)\n");
 
	ret = ZwQueryKey(KeyHandle, KeyBasicInformation, pKeyInformation, size, &sizeNeeded); // We use this function in order to get the current key name. If it Run or RunOnce we prevent from writing.
	if((ret == STATUS_BUFFER_TOO_SMALL) || (ret == STATUS_BUFFER_OVERFLOW)) { // If size not enough => we allocate more space memory
		size = sizeNeeded;
        pKeyInformation = (PKEY_BASIC_INFORMATION) ExAllocatePoolWithTag(NonPagedPool, sizeNeeded, 'aaaa');
 
		ret = ZwQueryKey(KeyHandle, KeyBasicInformation, pKeyInformation, size, &sizeNeeded);
    }
 
	if(ret != STATUS_SUCCESS)
		return ZwSetValueKeyOriginal(KeyHandle, ValueName, TitleIndex, Type, Data, DataSize);
 
	if( (pKeyInformation->NameLength / sizeof(WCHAR)) == 3) { // 3 == strlen("Run")
		for(i = 0; i < strlen(targetKey1); i++) {
			if(pKeyInformation->Name[i] != targetKey1[i]) { // if one character is different from Run key name, flag = 0
				flag = 0;
				break;
			}
		}
	}
	else if((pKeyInformation->NameLength / sizeof(WCHAR)) == 7) { // 7 == strlen("RunOnce")
		for(i = 0; i < strlen(targetKey2); i++) {
			if(pKeyInformation->Name[i] != targetKey2[i]) { // if one character is different from RunOnce key name, flag = 0
				flag = 0;
				break;
			}
		}
	}
	else flag = 0;
 
	if(!flag) // If flag == 0 => normal work ...
		return ZwSetValueKeyOriginal(KeyHandle, ValueName, TitleIndex, Type, Data, DataSize);
 
	DbgPrint("[+] Bypassing Run key writing\n");
 
	return STATUS_SUCCESS; // ... else the function will not be executed so no value writing ...
}
 
/*****************/
/* SSDT Functions */
/*****************/
 
void HookSSDT()
{
    DbgPrint("[+] SSDTHOOK: in HookSSDT()\n");
 
    ZwSetValueKeyOriginal = (ZWSETVALUEKEY) SYSTEMSERVICE(ZwSetValueKey); // We save target function address
 
    // unprotect CR0
    __asm
    {
        push eax
        mov  eax, CR0
        and  eax, 0FFFEFFFFh
        mov  CR0, eax
        pop  eax
    }
    //
 
    SYSTEMSERVICE(ZwSetValueKey) = (unsigned long *) ZwSetValueKeyHook; // We replace target function address by the address of our hook function
 
    // protect cr0
    __asm
    {
        push eax
        mov  eax, CR0
        or   eax, NOT 0FFFEFFFFh
        mov  CR0, eax
        pop  eax
    }
    //
 
}
 
void UnHookSSDT()
{
    DbgPrint("[+] SSDTHOOK: in UnHookSSDT()\n");
 
    // unprotect CR0
    __asm
    {
        push eax
        mov  eax, CR0
        and  eax, 0FFFEFFFFh
        mov  CR0, eax
        pop  eax
    }
    //
 
    SYSTEMSERVICE(ZwSetValueKey) = (ZWSETVALUEKEY) ZwSetValueKeyOriginal; // We delete hook by rewriting the good function address instead of our hook function address
 
    // protect cr0
    __asm
    {
        push eax
        mov  eax, CR0
        or   eax, NOT 0FFFEFFFFh
        mov  CR0, eax
        pop  eax
    }
    //
}
 
VOID unloadFunction(PDRIVER_OBJECT pDriverObject)
{
    UnHookSSDT(); // unhook function
}
 
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
    HookSSDT(); // hook function
 
	pDriverObject->DriverUnload = unloadFunction;
 
	return STATUS_SUCCESS;
}
 

