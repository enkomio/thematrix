#include <Windows.h>
#include "hooks.h"
#include "utility.h"

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

int hooks_Shell32(void)
{
	hook_add("Shell32.dll", "SHFileOperationW", hook_SHFileOperationW);
	return 0;
}