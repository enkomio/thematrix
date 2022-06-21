#include <stdint.h>
#include <stdbool.h>
#include <Windows.h>
#include "hooks.h"

extern void hooks_kernel32(void);
extern void hooks_bcrypt(void);

#ifndef _WIN64
// pointer to function that calls the original function
extern void* g_hook_call_original;

__declspec(naked) LPVOID __stdcall call_original(void) {
	((LPVOID(*)())g_hook_call_original)();
}
#endif

bool hooks_init(uint8_t* hMod)
{
	// add function hooks here
	hooks_kernel32();
	hooks_bcrypt();
	hooks_Wininet();
	hooks_Shell32();
	return true;
}