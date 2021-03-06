#ifndef HOOKS_H
#define HOOKS_H

#include <stdint.h>

typedef struct hook_info hook_info;

// hook a specific Windows function
extern hook_info* hook_add(char* dll_name, char* func_name, void* (__stdcall *hook_func)());

#ifdef _WIN64
extern LPVOID call_original(void);
#else
// call the original function
LPVOID __stdcall call_original(void);
#endif

#endif