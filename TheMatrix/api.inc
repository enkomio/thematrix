BeginUpdateResourceA proto pFileName:ptr char, bDeleteExistingResources:dword
CommandLineToArgvW proto lpCmdLine:ptr word, pNumArgs:ptr dword
CreateDirectoryA proto lpPathName:ptr char, lpSecurityAttributes:ptr void
CopyFileA proto lpExistingFileName:ptr char, lpNewFileName:ptr char, bFailIfExists:dword
CreateFileW proto lpFileName:ptr word, dwDesiredAccess:dword, dwShareMode:dword, lpSecurityAttributes:ptr void, dwCreationDisposition:dword, dwFlagsAndAttributes:dword, hTemplateFile:ptr void
CreateFileA proto lpFileName:ptr char, dwDesiredAccess:dword, dwShareMode:dword, lpSecurityAttributes:ptr void, dwCreationDisposition:dword, dwFlagsAndAttributes:dword, hTemplateFile:ptr void
CloseHandle proto hObject:ptr void
EndUpdateResourceA proto hUpdate:ptr void, fDiscard:dword
FindResourceA proto hModule:ptr word, lpName:ptr char, lpType:ptr char
FlushInstructionCache proto hProcess:ptr void, lpBaseAddress:ptr void, dwSize:ptr void
FreeResource proto hResData:ptr void
GetCommandLineW proto 
GetCurrentProcessId proto
GetFileSize proto hFile:ptr void, lpFileSizeHigh:ptr dword
GetLastError proto
GetModuleFileNameA proto hModule:ptr void, lpFilename:ptr char, nSize:dword
GetProcAddress proto hModule:ptr void, lpProcName:ptr char
GetProcessHeap proto
GetProcessId proto Process:ptr void
GetStdHandle proto nStdHandle:dword
HeapAlloc proto hHeap:ptr void, dwFlags:dword, dwBytes:ptr void
HeapFree proto hHeap:ptr void, dwFlags:dword, lpMem:ptr void
LoadLibraryA proto lpLibFileName:ptr char
LoadResource proto hModule:ptr void, hResInfo:ptr void
LockResource proto hResData:ptr void
ReadFile proto hFile:ptr void, lpBuffer:ptr void, nNumberOfBytesToRead:dword, lpNumberOfBytesRead:ptr dword, lpOverlapped:ptr void
SetConsoleMode proto hConsoleHandle:ptr void, dwMode:dword
SizeofResource proto hModule:ptr void, hResInfo:ptr void
UpdateResourceA proto hUpdate:ptr void, lpType:ptr char, lpName:ptr char, wLanguage:word, lpData:ptr void, cb:dword
VirtualAlloc proto lpAddress:ptr void, dwSize:ptr void, flAllocationType:dword, flProtect:dword
VirtualFree proto lpAddress:ptr void, dwSize:ptr void, dwFreeType:dword
VirtualProtect proto lpAddress:ptr void, dwSize:ptr void, flNewProtect:dword, lpflOldProtect:ptr dword
VirtualQuery proto lpAddress:ptr void, lpBuffer:ptr void, dwLength:ptr long
WriteConsoleA proto hConsoleOutput:ptr void, lpBuffer:ptr void, nNumberOfCharsToWrite:dword, lpNumberOfCharsWritten:ptr dword, lpReserved:ptr void
WriteFile proto hFile:ptr void, lpBuffer:ptr void, nNumberOfBytesToWrite:dword, lpNumberOfBytesWritten:ptr dword, lpOverlapped:ptr void