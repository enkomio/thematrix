g_string_DllRegisterServer byte "DllRegisterServer", 0h
g_string_add_opt byte '-',0h,'a',0h,'d',0h,'d',0h ; "-add" unicode 
g_string_file_create byte "Activator file created", 0h
g_string_load_error byte "Resource file not found. Please run it with '-add' option first", 0h
g_string_ntdll byte "ntdll.dll",0h
g_string_RtlHashUnicodeString byte "RtlHashUnicodeString",0h


; Windows constants
RT_VERSION equ 16
VS_VERSION_INFO equ 1
GENERIC_READ equ 80000000h
GENERIC_WRITE equ 40000000h
GENERIC_READ_WRITE equ GENERIC_READ or GENERIC_WRITE
CREATE_NEW equ 1
OPEN_EXISTING equ 3
ERROR_FILE_NOT_FOUND equ 2
INVALID_FILE_SIZE equ 0FFFFFFFFh
INVALID_HANDLE_VALUE equ 0FFFFFFFFh
MEM_COMMIT equ 1000h
MEM_DECOMMIT equ 4000h
PAGE_READWRITE equ 4h
PAGE_EXECUTE_READWRITE equ 40h
IMAGE_FILE_DLL equ 02000h
ERROR_ALREADY_EXISTS equ 183
GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS equ 4h
DLL_PROCESS_ATTACH equ 1h
IMAGE_SIZEOF_SHORT_NAME equ 8
IMAGE_NUMBEROF_DIRECTORY_ENTRIES equ 16
IMAGE_ORDINAL_FLAG32 equ 080000000h
IMAGE_BASE_RELOCATIONENTRY record _Type:4, _Offset:12
HEAP_ZERO_MEMORY equ 8h
STD_OUTPUT_HANDLE equ -11
FILE_BEGIN equ 0h
INVALID_SET_FILE_POINTER equ -1
RTL_BALANCED_NODE_RESERVED_PARENT_MASK equ 3