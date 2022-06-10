#include <Windows.h>
#include <shlobj_core.h>
#include "utility.h"

void log_data(size_t data_size, uint8_t* data, char* name)
{
	HANDLE hFile = INVALID_HANDLE_VALUE;
	DWORD nCount = 0;
	char log_file[MAX_PATH] = { 0 };

	if (SHGetFolderPathA(HWND_DESKTOP, CSIDL_DESKTOP, NULL, SHGFP_TYPE_DEFAULT, log_file) == S_OK) {
		char proc_id[32] = { 0 };
		_itoa_s(GetCurrentProcessId(), proc_id, sizeof(proc_id), 10);

		strcat_s(log_file, sizeof(log_file) , "\\");
		strcat_s(log_file, sizeof(log_file), "thematrix");
		strcat_s(log_file, sizeof(log_file), "\\");
		strcat_s(log_file, sizeof(log_file), proc_id);
		SHCreateDirectoryExA(NULL, log_file, NULL);

		strcat_s(log_file, sizeof(log_file), "\\");
		strcat_s(log_file, sizeof(log_file), name);
		strcat_s(log_file, sizeof(log_file), ".log");

		hFile = CreateFileA(
			log_file,
			GENERIC_READ | GENERIC_WRITE,
			0,
			NULL,
			OPEN_ALWAYS,
			FILE_ATTRIBUTE_NORMAL,
			NULL
		);

		if (hFile) {
			if (hFile != INVALID_HANDLE_VALUE) {
				WriteFile(hFile, data, (DWORD)data_size, &nCount, NULL);
				CloseHandle(hFile);
			}
		}
	}
}