#include <stdint.h>
#include <stdbool.h>
#include <Windows.h>
#include "hooks.h"

extern void hooks_kernel32(void);
extern void hooks_bcrypt(void);

// pointer to function that calls the original function
extern void* g_hook_call_original;

__declspec(naked) LPVOID __stdcall call_original(void) {
	((LPVOID(*)())g_hook_call_original)();
}

bool hooks_init(uint8_t* hMod)
{
	hooks_kernel32();
	hooks_bcrypt();
	return true;
}