#include <Windows.h>
#include "hooks.h"

static hook_info* g_VirtualAlloc_hook = 0;

int __cdecl hook_VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
{
	//int ret = (int)hook_call_original(g_VirtualAlloc_hook, lpAddress, dwSize, flAllocationType, flProtect);
	//return ret;
	return 0;
}

int hooks_kernel32(void)
{
	//g_VirtualAlloc_hook = hook_add("Kernel32.dll", "VirtualAlloc", hook_VirtualAlloc);
	//hook_set_log_folder(g_VirtualAlloc_hook, "C:\\Users\\antonio.parata\\Desktop\\");
	return 0;
}