#include <Windows.h>
#include <shlobj_core.h>
#include "utility.h"

void log_data(uint32_t data_size, uint8_t* data, char* name)
{
	HANDLE hFile = INVALID_HANDLE_VALUE;
	DWORD nCount = 0;
	char log_file[MAX_PATH] = { 0 };

	if (SHGetFolderPathA(HWND_DESKTOP, CSIDL_DESKTOP, NULL, SHGFP_TYPE_DEFAULT, log_file) == S_OK) {
		strcat_s(log_file, sizeof(log_file) , "\\");
		strcat_s(log_file, sizeof(log_file), "thematrix");
		CreateDirectoryA(log_file, NULL);

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

		if (hFile != INVALID_HANDLE_VALUE) {
			WriteFile(hFile, data, data_size, &nCount, NULL);
			CloseHandle(hFile);
		}
	}
}