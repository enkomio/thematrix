#include <Windows.h>
#include "hooks.h"
#include "utility.h"

static hook_info* g_VirtualFree_hook = 0;
static hook_info* g_VirtualAlloc_hook = 0;

typedef struct mem_allocated mem_allocated;
struct mem_allocated {
	LPVOID address;
	SIZE_T size;
	mem_allocated* next;
};

static mem_allocated* g_mem_root = 0;
static mem_allocated* g_mem_tail = 0;

LPVOID __stdcall VirtualAlloc_hook(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
{
	LPVOID res = hook_call_original(g_VirtualAlloc_hook, lpAddress, dwSize, flAllocationType, flProtect);
	if (res) {
		// save details of the allocation size
		if (!g_mem_root) {
			g_mem_root = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(mem_allocated));
			if (g_mem_root) {
				g_mem_root->address = res;
				g_mem_root->size = dwSize;
				g_mem_tail = g_mem_root;
			}
		}
		else {
			g_mem_tail->next = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(mem_allocated));
			if (g_mem_tail->next) {
				g_mem_tail = g_mem_tail->next;
				g_mem_tail->address = res;
				g_mem_tail->size = dwSize;
			}
		}
	}
	return res;
}

LPVOID __stdcall VirtualFree_hook(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)
{
	// find the allocation info and save content to file
	mem_allocated* m = g_mem_root;
	while (m) {
		if (m->address == lpAddress) {
			char name[MAX_PATH] = { 0 };
			snprintf(name, sizeof(name), "mem_%llx_%lld", (uint64_t)lpAddress, m->size);
			log_data(m->size, lpAddress, name);
			break;
		}
		m = m->next;
	}

	LPVOID res = hook_call_original(g_VirtualFree_hook, lpAddress, dwSize, dwFreeType);
	return res;
}

int hooks_kernel32(void)
{
	g_VirtualFree_hook = hook_add("Kernel32.dll", "VirtualFree", VirtualFree_hook);
	g_VirtualAlloc_hook = hook_add("Kernel32.dll", "VirtualAlloc", VirtualAlloc_hook);
	return 0;
}