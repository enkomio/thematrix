#include <Windows.h>
#include <shlobj_core.h>
#include "hooks.h"
#include "utility.h"

LPVOID __stdcall hook_BCryptDecrypt(BCRYPT_KEY_HANDLE hKey, PUCHAR pbInput, ULONG cbInput, VOID* pPaddingInfo, PUCHAR pbIV, ULONG cbIV, PUCHAR pbOutput, ULONG cbOutput, ULONG* pcbResult, ULONG dwFlags)
{
	LPVOID ret = call_original(
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

	if (!ret && *pcbResult) {
		// save decrypted data
		char name[MAX_PATH] = { 0 };
		snprintf(name, sizeof(name), "BCryptDecrypt_%llx_%d", (uint64_t)pbOutput, *pcbResult);
		log_data(*pcbResult, pbOutput, name);
	}

	return ret;
}

LPVOID __stdcall hook_BCryptEncrypt(BCRYPT_KEY_HANDLE hKey, PUCHAR pbInput, ULONG cbInput, VOID* pPaddingInfo, PUCHAR pbIV, ULONG cbIV, PUCHAR pbOutput, ULONG cbOutput, ULONG* pcbResult, ULONG dwFlags)
{
	// save plain data
	if (cbInput) {
		char name[MAX_PATH] = { 0 };
		snprintf(name, sizeof(name), "BCryptEncrypt_%llx_%d", (uint64_t)pbInput, cbInput);
		log_data(cbInput, pbInput, name);
	}

	LPVOID ret = call_original(
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

LPVOID __stdcall hook_BCryptImportKeyPair(BCRYPT_ALG_HANDLE hAlgorithm, BCRYPT_KEY_HANDLE hImportKey, LPCWSTR pszBlobType, BCRYPT_KEY_HANDLE* phKey, PUCHAR pbInput, ULONG cbInput, ULONG dwFlags)
{
	// save imported key bytes
	char name[MAX_PATH] = { 0 };
	snprintf(name, sizeof(name), "BCryptImportKeyPair_%llx_%d", (uint64_t)pbInput, cbInput);
	log_data(cbInput, pbInput, name);

	LPVOID ret = call_original(
		hAlgorithm,
		hImportKey,
		pszBlobType,
		phKey,
		pbInput,
		cbInput,
		dwFlags
	);
	return ret;
}

int hooks_bcrypt(void)
{
	hook_add("Bcrypt.dll", "BCryptEncrypt", hook_BCryptEncrypt);
	hook_add("Bcrypt.dll", "BCryptDecrypt", hook_BCryptDecrypt);
	hook_add("Bcrypt.dll", "BCryptImportKeyPair", hook_BCryptImportKeyPair);
	return 0;
}