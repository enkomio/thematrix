#include <Windows.h>
#include "hooks.h"

static hook_info* g_VirtualFree_hook = 0;

LPVOID __cdecl VirtualFree_hook(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)
{
	LPVOID allocated_buffer = hook_call_original(g_VirtualFree_hook, lpAddress, dwSize, dwFreeType);
	return allocated_buffer;
}

int hooks_kernel32(void)
{
	g_VirtualFree_hook = hook_add("Kernel32.dll", "VirtualFree", VirtualFree_hook);
	return 0;
}