;-------------------------------------------------------------------------
; PEB data structures (I don't need the full definition, 
; only the parts that I need for my purpose)
;-------------------------------------------------------------------------
LIST_ENTRY struct
	Flink				dword ?
	Blink				dword ?
LIST_ENTRY ends

UNICODE_STRING  struct
	_Length				word ?
	MaximumLength		word ?
	Buffer				dword ?
UNICODE_STRING ends

RTL_BALANCED_NODE struct
	Left					dword ?
	Right					dword ?
	ParentValue				dword ?
RTL_BALANCED_NODE ends

LDR_DATA_TABLE_ENTRY struct
	InLoadOrderLinks				LIST_ENTRY <>
	InMemoryOrderLinks				LIST_ENTRY <>
	InInitializationOrderLinks		LIST_ENTRY <>
	DllBase							dword ?
	EntryPoint						dword ?
	SizeOfImage						dword ?
	FullDllName						UNICODE_STRING  <>
	BaseDllName						UNICODE_STRING  <>
	Flags							dword ?
	LoadCount						word ?
	TlsIndex						word ?
	HashLinks						LIST_ENTRY <>
	TimeDateStamp					dword ?
	EntryPointActivationContext		dword ?
	_Lock							dword ?
	DgaNode							dword ?
	NodeModuleLink					LIST_ENTRY <>	
	LoadContext						dword ?
	ParentDllBase					dword ?
	SwitchBackContext				dword ?
	BaseAddressIndexNode			RTL_BALANCED_NODE <>
	MappingInfoIndexNode			RTL_BALANCED_NODE <>
	OriginalBase					dword ?
	__padding1                      dword ?
	LoadTime						qword ?
	BaseNameHashValue				dword ?
	LoadReason						dword ?
LDR_DATA_TABLE_ENTRY ends

PEB_LDR_DATA struct
	_Length							dword ?
	Initialized						dword ?
	SsHandle						dword ?
	InLoadOrderModuleList			LIST_ENTRY <>
	InMemoryOrderModuleList			LIST_ENTRY <>
	InInitializationOrderModuleList	LIST_ENTRY <>
	EntryInProgress					dword ?
	ShutdownInProgress				dword ?
	ShutdownThreadId				dword ?
PEB_LDR_DATA ends

PEB struct
	Reserved1			byte 2 dup (<>)
	BeingDebugged		byte ?
	Reserved2			byte ?
	Mutant				dword ?
	ImageBaseAddress	dword ?
	Ldr					dword ?
	ProcessParameters	dword ?
PEB ends

;-------------------------------------------------------------------------
; PE data structures
;-------------------------------------------------------------------------
IMAGE_BASE_RELOCATION struct
	VirtualAddress          dword ?
	SizeOfBlock             dword ?
IMAGE_BASE_RELOCATION ends

IMAGE_IMPORT_BY_NAME struct
	Hint                    word ?
	_Name                   byte ?
IMAGE_IMPORT_BY_NAME ends

IMAGE_THUNK_DATA32 union
	ForwarderString         dword ?
	Function                dword ?
	Ordinal                 dword ?
	AddressOfData           dword ?
IMAGE_THUNK_DATA32 ends

IMAGE_IMPORT_DESCRIPTOR_union union
    Characteristics         dword ?
    OriginalFirstThunk      dword ?
IMAGE_IMPORT_DESCRIPTOR_union ends

IMAGE_IMPORT_DESCRIPTOR struct
    u                       IMAGE_IMPORT_DESCRIPTOR_union <>
    TimeDateStamp           dword ?
    ForwarderChain          dword ?
    _Name                   dword ?
    FirstThunk              dword ?
IMAGE_IMPORT_DESCRIPTOR ends

IMAGE_EXPORT_DIRECTORY struct
    Characteristics			dword ?
    TimeDateStamp			dword ?
    MajorVersion			word ?
    MinorVersion			word ?
    _Name					dword ? 
    Base					dword ?
    NumberOfFunctions		dword ?
    NumberOfNames			dword ?
    AddressOfFunctions		dword ?
    AddressOfNames			dword ?
    AddressOfNameOrdinals	dword ?
IMAGE_EXPORT_DIRECTORY ends

IMAGE_DATA_DIRECTORY struct
    VirtualAddress          dword ?
    _Size                   dword ?
IMAGE_DATA_DIRECTORY ends

IMAGE_OPTIONAL_HEADER32 struct
    ;
    ; Standard fields.
    ;
    Magic                   word ?
    MajorLinkerVersion      byte ?
    MinorLinkerVersion      byte ?
    SizeOfCode              dword ?
    SizeOfInitializedData   dword ?
    SizeOfUninitializedData dword ?
    AddressOfEntryPoint     dword ?
    BaseOfCode              dword ?
    BaseOfData              dword ?

    ;
    ; NT additional fields.
    ;
    ImageBase               dword ?
    SectionAlignment        dword ?
    FileAlignment           dword ?
    MajorOperatingSystemVersion word ?
    MinorOperatingSystemVersion word ?
    MajorImageVersion       word ?
    MinorImageVersion       word ?
    MajorSubsystemVersion   word ?
    MinorSubsystemVersion   word ?
    Win32VersionValue       dword ?
    SizeOfImage             dword ?
    SizeOfHeaders           dword ?
    CheckSum                dword ?
    Subsystem               word ?
    DllCharacteristics      word ?
    SizeOfStackReserve      dword ?
    SizeOfStackCommit       dword ?
    SizeOfHeapReserve       dword ?
    SizeOfHeapCommit        dword ?
    LoaderFlags             dword ?
    NumberOfRvaAndSizes     dword ?
    DataDirectory           IMAGE_DATA_DIRECTORY IMAGE_NUMBEROF_DIRECTORY_ENTRIES dup (<>)
IMAGE_OPTIONAL_HEADER32 ends

IMAGE_FILE_HEADER struct
    Machine                 word ?
    NumberOfSections        word ?
    TimeDateStamp           dword ?
    PointerToSymbolTable    dword ?
    NumberOfSymbols         dword ?
    SizeOfOptionalHeader    word ?
    Characteristics         word ?
IMAGE_FILE_HEADER ends

IMAGE_NT_HEADERS32 struct
    Signature       dword ?
    FileHeader      IMAGE_FILE_HEADER<> 
    OptionalHeader  IMAGE_OPTIONAL_HEADER32<>
IMAGE_NT_HEADERS32 ends

IMAGE_DOS_HEADER struct
    e_magic		word	?
    e_cblp		word	?
    e_cp		word	?
    e_crlc		word	?
    e_cparhdr	word	?
    e_minalloc	word	?
    e_maxalloc	word	?
    e_ss		word	?
    e_sp		word	?
    e_csum		word	?
    e_ip		word	?
    e_cs		word	?
    e_lfarlc	word	?
    e_ovno		word	?
    e_res		word 4 dup (?)
    e_oemid		word	?
    e_oeminfo	word	?
    e_res2		word 10 dup (?)
    e_lfanew	dword	?
IMAGE_DOS_HEADER ends

IMAGE_SECTION_HEADER struct
    _Name byte IMAGE_SIZEOF_SHORT_NAME dup (?)
    VirtualSize             dword ?
    VirtualAddress          dword ?
    SizeOfRawData           dword ?
    PointerToRawData        dword ?
    PointerToRelocations    dword ?
    PointerToLinenumbers    dword ?
    NumberOfRelocations     word ?
    NumberOfLinenumbers     word ?
    Characteristics         dword ?
IMAGE_SECTION_HEADER ends

;-------------------------------------------------------------------------
; Functions
;-------------------------------------------------------------------------

;
; Compute the Hash value of the given UNICODE_STRING.
;	Args: <unicode string ptr>
;	Ret: the hash value DWORD
;
pe_hash_data proc buffer:ptr byte
	local hash_value:dword

	; resolve function RtlHashUnicodeString
	invoke LoadLibraryA, offset g_string_ntdll
	test eax, eax
	jz @fail

	invoke GetProcAddress, eax, offset g_string_RtlHashUnicodeString
	test eax, eax
	jz @fail

	; hash data
	lea ecx, hash_value
	push ecx
	push 0h
	push 1h
	push buffer
	call eax
	test eax, eax
	jnz @fail

	mov eax, hash_value

@exit:
	ret

@fail:
	xor eax, eax
	jmp @exit
pe_hash_data endp


pe_map proc buffer:ptr byte
	local base_addr:ptr byte
	local pe_file:ptr byte

	mov eax, buffer
	mov eax, IMAGE_DOS_HEADER.e_lfanew[eax]
	add eax, buffer
	mov pe_file, eax

	; allocate space
	mov ecx, IMAGE_NT_HEADERS32.OptionalHeader.SizeOfImage[eax]
	invoke VirtualAlloc, 0h, ecx, MEM_COMMIT, PAGE_EXECUTE_READWRITE
	test eax, eax
	jz @fail
	mov base_addr, eax	

	; copy headers
	mov esi, buffer
	mov edi, eax
	mov eax, pe_file
	mov ecx, IMAGE_NT_HEADERS32.OptionalHeader.SizeOfHeaders[eax]
	rep movsb
		
	movzx ecx, IMAGE_NT_HEADERS32.FileHeader.NumberOfSections[eax]
	movzx ebx, IMAGE_NT_HEADERS32.FileHeader.SizeOfOptionalHeader[eax]
	add ebx, sizeof IMAGE_FILE_HEADER + sizeof IMAGE_NT_HEADERS32.Signature
	add ebx, pe_file
@@:
	push ecx ; save value
	mov ecx, IMAGE_SECTION_HEADER.SizeOfRawData[ebx]	
	mov esi, IMAGE_SECTION_HEADER.PointerToRawData[ebx]
	add esi, buffer
	mov edi, IMAGE_SECTION_HEADER.VirtualAddress[ebx]
	add edi, base_addr
	rep movsb
	add ebx, sizeof IMAGE_SECTION_HEADER
	pop ecx ; restorevalue
	loop @b

	mov eax, base_addr

@exit:
	ret

@fail:
	xor eax, eax
	jmp @exit
pe_map endp

;
; Adjust the PEB module list in order to insert the embedded binary among the loaded modules
;	Args: <loaded pe base address>
;	Ret: TRUE on success, FALSE otherwise
;
pe_adjust_PEB proc base_addr:ptr byte
	local pe_addr:ptr byte	
	local mem_info:MEMORY_BASIC_INFORMATION
	local ldr_entry_target:dword
	local ldr_entry_new:dword
	local full_dll_name:ptr byte

	mov eax, base_addr
	mov ebx, IMAGE_DOS_HEADER.e_lfanew[eax]
	add ebx, base_addr
	mov pe_addr, ebx

	; set image base address in PEB if it is not a DLL
	movzx ecx, word ptr IMAGE_NT_HEADERS32.FileHeader.Characteristics[ebx]
	test ecx, IMAGE_FILE_DLL
	jnz @add_to_Ldr

	assume fs:nothing
	mov ecx, fs:[30h]
	assume fs:error
	mov PEB.ImageBaseAddress[ecx], eax	

@add_to_Ldr:
	; save to EAX my base in order to use it to identify the module in Ldr
	call get_module_base

	assume fs:nothing
	mov esi, fs:[30h]
	assume fs:error
	mov esi, PEB.Ldr[esi]
	mov esi, PEB_LDR_DATA.InLoadOrderModuleList[esi]	
	mov ecx, LDR_DATA_TABLE_ENTRY.DllBase[esi]
	cmp ecx, eax
	jz @add_module

	; save the head value
	mov edx, esi
@find_module:
	mov esi, LDR_DATA_TABLE_ENTRY.InLoadOrderLinks.Flink[esi]	
	cmp esi, edx ; reached the head of the list again?
	jz @finish

	mov ecx, LDR_DATA_TABLE_ENTRY.DllBase[esi]	
	cmp ecx, eax
	jz @add_module
	jmp @find_module

@add_module:
	; got to the next module, this should be ntdll.dll
	mov esi, LDR_DATA_TABLE_ENTRY.InLoadOrderLinks.Flink[esi]
	mov ldr_entry_target, esi

	; compute allocation size for the new LDR_DATA_TABLE_ENTRY
	invoke VirtualQuery, ldr_entry_target, addr mem_info, sizeof MEMORY_BASIC_INFORMATION
	test eax, eax
	jz @fail
		
	; starting from the target entry, calculate how much space is left till the end of the region
	lea eax, mem_info
	mov ebx, MEMORY_BASIC_INFORMATION.BaseAddress[eax]
	sub esi, ebx	
	mov eax, MEMORY_BASIC_INFORMATION.RegionSize[eax]
	sub eax, esi ; this is the remaining space until the end of the region

	; 600h is enough for a full LDR_DATA_TABLE_ENTRY definition. Use the minor value
	mov ebx, 0600h
	cmp eax, ebx
	cmovbe ebx, eax

	; allocate mem for new entry
	invoke heap_alloc, ebx
	test eax, eax
	jz @fail
	mov ldr_entry_new, eax

	; copy value
	mov ecx, ebx
	mov edi, ldr_entry_new
	mov esi, ldr_entry_target
	rep movsb

	; modify the entry
	mov eax, base_addr
	mov ebx, pe_Addr

	; set the DllBase
	mov esi, ldr_entry_new	
	mov LDR_DATA_TABLE_ENTRY.DllBase[esi], eax	
	
	; set the EntryPoint
	mov eax, IMAGE_NT_HEADERS32.OptionalHeader.AddressOfEntryPoint[ebx]
	add eax, base_addr
	mov LDR_DATA_TABLE_ENTRY.EntryPoint[esi], eax
	
	; set the ImageSize
	mov eax, IMAGE_NT_HEADERS32.OptionalHeader.SizeOfImage[ebx]
	mov LDR_DATA_TABLE_ENTRY.SizeOfImage[esi], eax

	; set the FullDllName
	invoke heap_alloc, 512h
	test eax, eax
	jz @fail
	mov full_dll_name, eax

	call get_module_base
	test eax, eax
	jz @fail

	; get the module name
	invoke GetModuleFileNameW, eax, full_dll_name, 512h
	test eax, eax
	jz @fail

	; account space for unicode char
	shl eax, 1

	; set the FullDllName
	mov ecx, full_dll_name
	mov LDR_DATA_TABLE_ENTRY.FullDllName.Buffer[esi], ecx
	mov LDR_DATA_TABLE_ENTRY.FullDllName.MaximumLength[esi], ax
	mov LDR_DATA_TABLE_ENTRY.FullDllName._Length[esi], ax	

	; go to the DLL name
	add ecx, eax

	; save value
	push ecx

	mov edi, ecx
	std
	mov ecx, eax
	mov eax, 05ch
	repnz scasb
	cld

	; restore value
	pop ecx

	add edi, 3h ; base dll name
	sub ecx, edi ; base dll name size

	; save size to non-volatile
	mov ebx, ecx

	; allocate space for the DLL base name
	invoke heap_alloc, ecx
	test eax, eax
	jz @fail

	; save value
	push esi

	; copy the value
	mov esi, edi
	mov edi, eax
	mov ecx, ebx
	rep movsb	

	; restore value
	pop esi

	; set the BaseDllName
	mov LDR_DATA_TABLE_ENTRY.BaseDllName.Buffer[esi], eax	
	mov LDR_DATA_TABLE_ENTRY.BaseDllName.MaximumLength[esi], bx
	mov LDR_DATA_TABLE_ENTRY.BaseDllName._Length[esi], bx

	; set BaseNameHashValue
	invoke pe_hash_data, addr LDR_DATA_TABLE_ENTRY.BaseDllName[esi]
	test eax, eax
	jz @fail
	mov dword ptr LDR_DATA_TABLE_ENTRY.BaseNameHashValue[esi], eax

	; check if it is at least Win8 (6.2). If so I have to update more structures
	; If not, I don't care about these fields, since in Windows 7 the BaseAddressIndexNode
	; and the HashLinks fields are not used to resolve DLL and functions
	assume fs:nothing
	mov eax, fs:[30h]
	assume fs:error
	cmp dword ptr [eax + 0a4h], 6h ; check OSMajorVersion
	ja @update_node_rbl
	cmp dword ptr [eax + 0a8h], 2h ; check OSMinorVersion
	jae @update_node_rbl
	jmp @additional_fields_update_completed

@update_node_rbl:
	; update the BaseAddressIndexNode with a new node
	; more info: https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/shared/ntdef/rtl_balanced_node.htm?tx=210
	lea ecx, LDR_DATA_TABLE_ENTRY.BaseAddressIndexNode[esi]
@find_node_root:
	mov edx, RTL_BALANCED_NODE.ParentValue[ecx]
	and edx, not RTL_BALANCED_NODE_RESERVED_PARENT_MASK
	test edx, edx
	jz @root_node_found
	mov ecx, edx
	jmp @find_node_root
@root_node_found:
	; point to the LDR_DATA_TABLE_ENTRY
	
	; add the node to the correct position starting from the root
	mov ebx, LDR_DATA_TABLE_ENTRY.DllBase[esi]
@insert_node_loop:	
	sub ecx, 068h
	cmp ebx, LDR_DATA_TABLE_ENTRY.DllBase[ecx]
	je @node_added_completed
	jb @check_node_left

	; checking Right node
	; did I found an empty spot? if so, add the node
	cmp LDR_DATA_TABLE_ENTRY.BaseAddressIndexNode.Right[ecx], 0h
	je @add_node_rigth

	; move down the tree and continue to search
	mov ecx, LDR_DATA_TABLE_ENTRY.BaseAddressIndexNode.Right[ecx]
	jmp @insert_node_loop

@check_node_left:
	; did I found an empty spot? if so, add the node
	cmp LDR_DATA_TABLE_ENTRY.BaseAddressIndexNode.Left[ecx], 0h
	je @add_node_left

	; move down the tree and continue to search
	mov ecx, LDR_DATA_TABLE_ENTRY.BaseAddressIndexNode.Left[ecx]
	jmp @insert_node_loop

@add_node_left:
	lea ebx, LDR_DATA_TABLE_ENTRY.BaseAddressIndexNode[esi]
	mov LDR_DATA_TABLE_ENTRY.BaseAddressIndexNode.Left[ecx], ebx
	jmp @node_added_completed

@add_node_rigth:
	lea ebx, LDR_DATA_TABLE_ENTRY.BaseAddressIndexNode[esi]
	mov LDR_DATA_TABLE_ENTRY.BaseAddressIndexNode.Right[ecx], ebx
@node_added_completed:

	; Fix HashLinks list
	lea eax, LDR_DATA_TABLE_ENTRY.HashLinks[esi]

	; Update the HashLinks linked list, fix pre entry
	mov ecx, LIST_ENTRY.Blink[eax]
	test ecx, ecx
	jz @f
	mov LIST_ENTRY.Flink[ecx], eax
@@:

	; Update the HashLinks linked list, fix post entry
	mov ecx, LIST_ENTRY.Flink[eax]
	test ecx, ecx
	jz @f
	mov LIST_ENTRY.Blink[ecx], eax
@@:

@additional_fields_update_completed:

	; finally, add the new entry to all the lists
	mov edi, ldr_entry_new
	mov esi, ldr_entry_target
	mov ecx, 3

@insert_entry:
	; fix all lists
	mov ebx, dword ptr [esi]		; save value
	mov dword ptr [esi], edi		; Modify pre-FLink
	mov dword ptr [ebx + 4], edi	; Modify pre-BLink
	mov dword ptr [edi], ebx		; Modify post-FLink
	mov dword ptr [edi + 4], esi	; Modify post-BLink
	
	; move to next list
	add edi, sizeof LIST_ENTRY
	add esi, sizeof LIST_ENTRY
	loop @insert_entry
		
@finish:
	mov eax, 1

@exit:
	ret

@fail:
	xor eax, eax
	jmp @exit
pe_adjust_PEB endp

;
; Resolve PE imports
;	Args: <mapped PE>
;	Ret: TRUE on success, FALSE otherwise
;
pe_resolve_imports proc base_addr:ptr byte
	local lib_dll_handle:dword

	; goto PE
	mov eax, base_addr
	mov eax, IMAGE_DOS_HEADER.e_lfanew[eax]
	add eax, base_addr
	
	lea eax, IMAGE_NT_HEADERS32.OptionalHeader.DataDirectory[eax + sizeof IMAGE_DATA_DIRECTORY]
	mov ecx, IMAGE_DATA_DIRECTORY._Size[eax]
	test ecx, ecx
	jz @finish
	
	mov esi, IMAGE_DATA_DIRECTORY.VirtualAddress[eax]
	add esi, base_addr
	
@resolve_DLL_imports:
	cmp IMAGE_IMPORT_DESCRIPTOR.u.Characteristics[esi], 0h
	jz @finish

	; load DLL
	mov eax, IMAGE_IMPORT_DESCRIPTOR._Name[esi]
	add eax, base_addr
	invoke LoadLibraryA, eax
	test eax, eax
	jz @fail
	mov lib_dll_handle, eax

	; load Thunk tables
	mov ebx, IMAGE_IMPORT_DESCRIPTOR.u.OriginalFirstThunk[esi]
	add ebx, base_addr
	mov ecx, IMAGE_IMPORT_DESCRIPTOR.FirstThunk[esi]
	add ecx, base_addr

@resolve_DLL_import:	
	mov eax, IMAGE_THUNK_DATA32.Ordinal[ebx]
	test eax, eax
	jz @goto_next_DLL

	test eax, IMAGE_ORDINAL_FLAG32
	jz @resolve_import_by_names
	and eax, 0ffffh
	jmp @resolve_function_address	

@resolve_import_by_names:
	mov eax, IMAGE_THUNK_DATA32.AddressOfData[ebx]
	add eax, base_addr
	lea eax, IMAGE_IMPORT_BY_NAME._Name[eax]

@resolve_function_address:
	push ebx
	push ecx	
	invoke GetProcAddress, lib_dll_handle, eax
	pop ecx
	pop ebx

	; write resolved address
	mov IMAGE_THUNK_DATA32.Function[ecx], eax

	; move next function
	add ebx, sizeof dword
	add ecx, sizeof dword
	jmp @resolve_DLL_import

@goto_next_DLL:
	add esi, sizeof IMAGE_IMPORT_DESCRIPTOR
	jmp @resolve_DLL_imports

@finish:
	mov eax, 1

@exit:
	ret

@fail:
	xor eax, eax
	jmp @exit
pe_resolve_imports endp

;
; Relocate the mapped PE
;	Args: <mapped pe address>
;	Ret: TRUE on success, FALSE otherwise
;
pe_relocate proc base_addr:ptr byte
	local relocation_delta:dword
	local relocation_block_base:dword
	local pe_file:dword

	mov eax, base_addr
	mov eax, IMAGE_DOS_HEADER.e_lfanew[eax]
	add eax, base_addr
	mov pe_file, eax

	lea eax, IMAGE_NT_HEADERS32.OptionalHeader.DataDirectory[eax + sizeof IMAGE_DATA_DIRECTORY * 5]
	mov ecx, IMAGE_DATA_DIRECTORY._Size[eax]
	test ecx, ecx
	jz @finish

	; go to relocation directory data
	mov esi, IMAGE_DATA_DIRECTORY.VirtualAddress[eax]
	add esi, base_addr

	; compute relocation delta
	mov eax, pe_file
	mov eax, IMAGE_NT_HEADERS32.OptionalHeader.ImageBase[eax]
	mov edi, base_addr
	mov relocation_delta, edi
	sub relocation_delta, eax
	
@relocate_block:
	; compute number or entries in the current block
	mov ecx, IMAGE_BASE_RELOCATION.SizeOfBlock[esi]
	test ecx, ecx
	jz @finish

	; each relocation block is a word, need to remove the header and div by 2
	sub ecx, sizeof IMAGE_BASE_RELOCATION
	shr ecx, 1

	; get the VA of the current relocation block
	mov eax, IMAGE_BASE_RELOCATION.VirtualAddress[esi]
	add eax, base_addr
	mov relocation_block_base, eax

	; move to the entry list
	add esi, sizeof IMAGE_BASE_RELOCATION
	
@relocate_block_entry:
	movzx eax, word ptr [esi]
	mov ebx, eax
	and ebx, mask IMAGE_BASE_RELOCATIONENTRY._Offset	
	and eax, mask IMAGE_BASE_RELOCATIONENTRY._Type
	shr eax, 0ch

	cmp eax, 1h
	je @IMAGE_REL_BASED_HIGH
	cmp eax, 2h
	je @IMAGE_REL_BASED_LOW
	cmp eax, 3h
	je @IMAGE_REL_BASED_HIGHLOW
	jmp @next_relocation_entry	

@IMAGE_REL_BASED_HIGH:	
	add ebx, relocation_block_base
	mov eax, relocation_delta
	shr eax, 10h
	add word ptr [ebx], ax
	jmp @next_relocation_entry

@IMAGE_REL_BASED_LOW:	
	add ebx, relocation_block_base
	mov edi, relocation_delta
	add word ptr [ebx], di	
	jmp @next_relocation_entry

@IMAGE_REL_BASED_HIGHLOW:
	add ebx, relocation_block_base
	mov edi, relocation_delta
	add dword ptr [ebx], edi

@next_relocation_entry:
	add esi, sizeof word
	loop @relocate_block_entry
	jmp @relocate_block

@finish:
	mov eax, 1h

@exit:
	ret

@fail:
	xor eax, eax
	jmp @exit

pe_relocate endp

;
; Load the buffer containing the PE file
;	Args: <PE buffer>
;	Ret: Loaded PE VA on success, NULL on error
;
pe_load proc buffer:ptr byte
	local base_addr:ptr byte
	
	invoke pe_map, buffer
	test eax, eax
	jz @fail
	mov base_addr, eax

	invoke pe_resolve_imports, base_addr
	test eax, eax
	jz @fail

	invoke pe_relocate, base_addr
	test eax, eax
	jz @fail

	invoke pe_adjust_PEB, base_addr
	test eax, eax
	jz @fail

	mov eax, base_addr
	
@exit:
	ret

@fail:
	xor eax, eax
	jmp @exit
pe_load endp

;
; Resolve an exported function from the input DLL.
;	Args: <DLL base>, <function name>
;	Ret: The address containing the function RVA on success, or NULL otherwise
;
pe_resolve_exported_function proc base_addr:dword, func_name:dword
	local pe_file:dword

	; go to PE
	mov eax, base_addr
	mov eax, IMAGE_DOS_HEADER.e_lfanew[eax]
	add eax, base_addr
	mov pe_file, eax

	; ensure we have an export directory
	lea eax, IMAGE_NT_HEADERS32.OptionalHeader.DataDirectory[eax]
	mov ecx, IMAGE_DATA_DIRECTORY._Size[eax]
	test ecx, ecx
	jz @exit

	; go to the export directory
	mov ebx, IMAGE_DATA_DIRECTORY.VirtualAddress[eax]
	add ebx, base_addr

	; get export information, ECX = Numbers of Names, esi = Address of Names
	mov ecx, IMAGE_EXPORT_DIRECTORY.NumberOfNames[ebx]
	mov esi, IMAGE_EXPORT_DIRECTORY.AddressOfNames[ebx]
	add esi, base_addr

	; zero index
	xor edx, edx
@find_exported_function:
	; get the i-th function name
	mov eax, dword ptr [esi + edx * sizeof dword]	
	add eax, base_addr

	; save value
	push ecx

	; check if the name matches
	invoke string_equals, func_name, eax
	test eax, eax
	jnz @function_found

	; restore value
	pop ecx
	
	; go to the next function
	inc edx
	loop @find_exported_function
	jmp @fail

@function_found:
	; get the i-th function ordinal
	mov esi, IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals[ebx]
	add esi, base_addr
	movzx eax, word ptr [esi + sizeof word * edx]

	; get the i-th function RVA 
	mov esi, IMAGE_EXPORT_DIRECTORY.AddressOfFunctions[ebx]
	add esi, base_addr
	lea eax, dword ptr [esi + eax * sizeof dword]
	
@exit:	
	ret

@fail:
	xor eax, eax
	jmp @exit
pe_resolve_exported_function endp
