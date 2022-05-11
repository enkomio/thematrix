#include <stdint.h>
#include <stdbool.h>
#include "hooks.h"

extern void hooks_kernel32(void);
extern void hooks_bcrypt(void);

bool hooks_init(uint8_t* hMod)
{
	hooks_kernel32();
	hooks_bcrypt();
	return true;
}