#include <Windows.h>
#include "hooks.h"
#include "utility.h"

typedef struct mem_allocated mem_allocated;
struct mem_allocated {
	LPVOID address;
	SIZE_T size;
	mem_allocated* next;
};

static mem_allocated* g_mem_root = 0;
static mem_allocated* g_mem_tail = 0;

LPVOID __stdcall hook_VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
{
	LPVOID res = call_original(lpAddress, dwSize, flAllocationType, flProtect);
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

LPVOID __stdcall hook_VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)
{
	// find the allocation info and save content to file
	mem_allocated* m = g_mem_root;
	while (m) {
		if (m->address == lpAddress) {
			char name[MAX_PATH] = { 0 };
			snprintf(name, sizeof(name), "VirtualFree_%llx_%d", (uint64_t)lpAddress, m->size);
			log_data(m->size, lpAddress, name);
			break;
		}
		m = m->next;
	}

	LPVOID res = call_original(lpAddress, dwSize, dwFreeType);
	return res;
}

LPVOID __stdcall hook_SHFileOperationW(LPSHFILEOPSTRUCTW lpFileOp)
{
	LPVOID result = call_original(lpFileOp);
	if (result) {
		char name[MAX_PATH] = { 0 };
		snprintf(name, sizeof(name), "SHFileOperationW_%llx_%d", (uint64_t)lpFileOp, result);
		log_data(4, &result, name);
	}
	return result;
}

LPVOID __stdcall hook_CreateProcessW(
	LPCWSTR               lpApplicationName,
	LPWSTR                lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL                  bInheritHandles,
	DWORD                 dwCreationFlags,
	LPVOID                lpEnvironment,
	LPCWSTR               lpCurrentDirectory,
	LPSTARTUPINFOW        lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
)
{
	char name[MAX_PATH] = { 0 };
	int s = 0;
	if (lpApplicationName)
		snprintf(name, sizeof(name), "CreateProcessW_%llx", (uint64_t)lpApplicationName);
	else
		snprintf(name, sizeof(name), "CreateProcessW_%llx", (uint64_t)lpCommandLine);

	if (lpApplicationName)
		s = lstrlenW(lpApplicationName);

	if (lpCommandLine)
		s += lstrlenW(lpCommandLine);

	s += 10;
	unsigned char* buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, s * sizeof(WCHAR));
	if (buffer) {
		if (lpApplicationName) {
			lstrcatW(buffer, lpApplicationName);
			lstrcatW(buffer, L"\n");
		}
		if (lpCommandLine)
			lstrcatW(buffer, lpCommandLine);

		s = lstrlenW(buffer) * sizeof(WCHAR);
		if (s)
			log_data(s, buffer, name);
	}

	return call_original(
		lpApplicationName,
		lpCommandLine,
		lpProcessAttributes,
		lpThreadAttributes,
		bInheritHandles,
		dwCreationFlags,
		lpEnvironment,
		lpCurrentDirectory,
		lpStartupInfo,
		lpProcessInformation
	);
}

int hooks_kernel32(void)
{
	hook_add("Kernel32.dll", "VirtualFree", hook_VirtualFree);
	hook_add("Kernel32.dll", "VirtualAlloc", hook_VirtualAlloc);
	hook_add("Kernel32.dll", "CreateProcessW", hook_CreateProcessW);
	hook_add("Shell32.dll", "SHFileOperationW", hook_SHFileOperationW);
	return 0;
}