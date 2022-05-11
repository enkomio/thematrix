#include <Windows.h>
#include "hooks.h"

static hook_info* g_VirtualAlloc_hook = 0;

int __cdecl hook_VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
{
	return 0;
}

int hooks_kernel32(void)
{
	return 0;
}