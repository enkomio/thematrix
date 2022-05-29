#ifndef HOOKS_H
#define HOOKS_H

#include <stdint.h>

typedef struct hook_info hook_info;

// hook a specific Windows function
extern hook_info* hook_add(char* dll_name, char* func_name, void* (__stdcall *hook_func)());

// call the original function
extern void* hook_call_original();

#endif