#include <Windows.h>
#include <WinInet.h>
#include "hooks.h"
#include "utility.h"

LPVOID __stdcall hook_InternetConnectW(
	HINTERNET     hInternet,
	LPCWSTR       lpszServerName,
	INTERNET_PORT nServerPort,
	LPCWSTR       lpszUserName,
	LPCWSTR       lpszPassword,
	DWORD         dwService,
	DWORD         dwFlags,
	DWORD_PTR     dwContext
)
{
	char name[MAX_PATH] = { 0 };
	snprintf(name, sizeof(name), "InternetConnectW_%llx_%d", (uint64_t)lpszServerName, (uint16_t)nServerPort);
	log_data(lstrlenW(lpszServerName) * sizeof(WCHAR), lpszServerName, name);

	LPVOID ret = call_original(
		hInternet,
		lpszServerName,
		nServerPort,
		lpszUserName,
		lpszPassword,
		dwService,
		dwFlags,
		dwContext
	);
	return ret;
}

LPVOID __stdcall hook_HttpOpenRequestW(
	HINTERNET hConnect,
	LPCWSTR   lpszVerb,
	LPCWSTR   lpszObjectName,
	LPCWSTR   lpszVersion,
	LPCWSTR   lpszReferrer,
	LPCWSTR* lplpszAcceptTypes,
	DWORD     dwFlags,
	DWORD_PTR dwContext
)
{
	char name[MAX_PATH] = { 0 };
	snprintf(name, sizeof(name), "HttpOpenRequestW_%llx", (uint64_t)lpszObjectName);
	log_data(lstrlenW(lpszObjectName) * sizeof(WCHAR), lpszObjectName, name);

	LPVOID ret = call_original(
		hConnect,
		lpszVerb,
		lpszObjectName,
		lpszVersion,
		lpszReferrer,
		lplpszAcceptTypes,
		dwFlags,
		dwContext
	);
	return ret;
}

LPVOID __stdcall hook_HttpSendRequestW(
	HINTERNET hRequest,
	LPCWSTR   lpszHeaders,
	DWORD     dwHeadersLength,
	LPVOID    lpOptional,
	DWORD     dwOptionalLength
)
{
	char name[MAX_PATH] = { 0 };
	int header_length = dwHeadersLength;
	int optional_length = dwOptionalLength;

	if (dwHeadersLength == -1 && lpszHeaders)
		header_length = lstrlenW(lpszHeaders);

	if (dwOptionalLength == -1 && lpOptional)
		optional_length = lstrlenW(lpOptional);

	optional_length *= sizeof(WCHAR);
	header_length *= sizeof(WCHAR);

	snprintf(name, sizeof(name), "HttpSendRequestW_%llx_%d", (uint64_t)lpszHeaders, header_length);

	unsigned char* buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, header_length + optional_length + 10);
	if (buffer) {
		if (lpszHeaders) {
			lstrcatW(buffer, lpszHeaders);
			lstrcatW(buffer, L"\n");
		}
		if (lpOptional)
			lstrcatW(buffer, lpOptional);

		int s = lstrlenW(buffer) * sizeof(WCHAR);
		if (s)
			log_data(s, buffer, name);
	}

	LPVOID ret = call_original(
		hRequest,
		lpszHeaders,
		dwHeadersLength,
		lpOptional,
		dwOptionalLength
	);
	return ret;
}

LPVOID __stdcall hook_InternetReadFile(
	HINTERNET hFile,
	LPVOID    lpBuffer,
	DWORD     dwNumberOfBytesToRead,
	LPDWORD   lpdwNumberOfBytesRead
)
{
	LPVOID ret = call_original(
		hFile,
		lpBuffer,
		dwNumberOfBytesToRead,
		lpdwNumberOfBytesRead
	);

	if (*lpdwNumberOfBytesRead) {
		char name[MAX_PATH] = { 0 };
		snprintf(name, sizeof(name), "InternetReadFile_%llx_%d", (uint64_t)lpBuffer, *lpdwNumberOfBytesRead);
		log_data(*lpdwNumberOfBytesRead, lpBuffer, name);
	}

	return ret;
}

int hooks_Wininet(void)
{
	hook_add("Wininet.dll", "InternetConnectW", hook_InternetConnectW);
	hook_add("Wininet.dll", "HttpOpenRequestW", hook_HttpOpenRequestW);
	hook_add("Wininet.dll", "HttpSendRequestW", hook_HttpSendRequestW);
	hook_add("Wininet.dll", "InternetReadFile", hook_InternetReadFile);
	return 0;
}