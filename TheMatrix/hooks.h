#ifndef HOOKS_H
#define HOOKS_H

#include <stdint.h>

typedef struct hook_info hook_info;

// hook a specific Windows function
extern hook_info* hook_add(char* dll_name, char* func_name, void (__cdecl *hook_func)());

// call the original function
extern  void* hook_call_original(hook_info* hook, ...);

// log the specific data to an hardcoded directory
extern void hook_log_data(hook_info* hook, size_t data_size, uint8_t* data);

// set the output log folder to write logs
extern void hook_set_log_folder(hook_info* hook, char* folder);

#endif