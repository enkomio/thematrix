#include <Windows.h>
#include <shlobj_core.h>
#include "hooks.h"

static hook_info* g_BCryptEncrypt_hook = 0;
static hook_info* g_BCryptDecrypt_hook = 0;

int __cdecl hook_BCryptDecrypt(BCRYPT_KEY_HANDLE hKey, PUCHAR pbInput, ULONG cbInput, VOID* pPaddingInfo, PUCHAR pbIV, ULONG cbIV, PUCHAR pbOutput, ULONG cbOutput, ULONG* pcbResult, ULONG dwFlags)
{	
	NTSTATUS ret = (NTSTATUS)hook_call_original(
		g_BCryptDecrypt_hook,
		hKey,
		pbInput,
		cbInput,
		pPaddingInfo,
		pbIV,
		cbIV,
		pbOutput,
		cbOutput,
		pcbResult,
		dwFlags
	);
	return ret;
}

int __cdecl hook_BCryptEncrypt(BCRYPT_KEY_HANDLE hKey, PUCHAR pbInput, ULONG cbInput, VOID* pPaddingInfo, PUCHAR pbIV, ULONG cbIV, PUCHAR pbOutput, ULONG cbOutput, ULONG* pcbResult, ULONG dwFlags)
{
	NTSTATUS ret = (NTSTATUS)hook_call_original(
		g_BCryptEncrypt_hook,
		hKey,
		pbInput,
		cbInput,
		pPaddingInfo,
		pbIV,
		cbIV,
		pbOutput,
		cbOutput,
		pcbResult,
		dwFlags
	);
	return ret;
}

int hooks_bcrypt(void)
{
	char log_directory[MAX_PATH] = { 0 };
	if (SHGetFolderPathA(HWND_DESKTOP, CSIDL_DESKTOP, NULL, SHGFP_TYPE_DEFAULT, log_directory) == S_OK) {
		strcat_s(log_directory, sizeof log_directory, "\\");
		g_BCryptEncrypt_hook = hook_add("Bcrypt.dll", "BCryptEncrypt", hook_BCryptEncrypt);
		g_BCryptDecrypt_hook = hook_add("Bcrypt.dll", "BCryptDecrypt", hook_BCryptDecrypt);
	}

	return 0;
}