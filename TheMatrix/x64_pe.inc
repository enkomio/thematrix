;-------------------------------------------------------------------------
; PEB data structures (I don't need the full definition, 
; only the parts that I need for my purpose)
;-------------------------------------------------------------------------
LIST_ENTRY struct
	Flink				qword ?
	Blink				qword ?
LIST_ENTRY ends

UNICODE_STRING  struct
	_Length				word ?
	MaximumLength		word ?
    __padding           dword ?
	Buffer				qword ?
UNICODE_STRING ends

UNICODE_STRING_SIZE equ sizeof UNICODE_STRING

RTL_BALANCED_NODE struct
	Left					qword ?
	Right					qword ?
	ParentValue				qword ?
RTL_BALANCED_NODE ends

LDR_DATA_TABLE_ENTRY struct
	InLoadOrderLinks				LIST_ENTRY <>
	InMemoryOrderLinks				LIST_ENTRY <>
	InInitializationOrderLinks		LIST_ENTRY <>
	DllBase							qword ?
	EntryPoint						qword ?
	SizeOfImage						dword ?
    __padding0                      dword ?
	FullDllName						UNICODE_STRING  <>
	BaseDllName						UNICODE_STRING  <>
	Flags							dword ?
	LoadCount						word ?
	TlsIndex						word ?
	HashLinks						LIST_ENTRY <>
	TimeDateStamp					dword ?
    __padding1                      dword ?
	EntryPointActivationContext		qword ?
	_Lock							qword ?
	DgagNode						qword ?
	NodeModuleLink					LIST_ENTRY <>
	LoadContext						qword ?
	ParentDllBase					qword ?
	SwitchBackContext				qword ?
	BaseAddressIndexNode			RTL_BALANCED_NODE <>
	MappingInfoIndexNode			RTL_BALANCED_NODE <>
	OriginalBase					qword ?
	LoadTime						qword ?
	BaseNameHashValue				dword ?
	__padding2                      dword ?
	LoadReason						dword ?
LDR_DATA_TABLE_ENTRY ends

PEB_LDR_DATA struct
	_Length							dword ?
	Initialized						dword ?
	SsHandle						qword ?
	InLoadOrderModuleList			LIST_ENTRY <>
	InMemoryOrderModuleList			LIST_ENTRY <>
	InInitializationOrderModuleList	LIST_ENTRY <>
	EntryInProgress					qword ?
	ShutdownInProgress				dword ?
	ShutdownThreadId				qword ?
PEB_LDR_DATA ends

PEB struct
	Reserved1			byte 2 dup (<>)
	BeingDebugged		byte ?
	Reserved2			byte ?
    __padding           dword ?
	Mutant				qword ?
	ImageBaseAddress	qword ?
	Ldr					qword ?
	ProcessParameters	qword ?
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

IMAGE_THUNK_DATA64 union
	ForwarderString         qword ?
	Function                qword ?
	Ordinal                 qword ?
	AddressOfData           qword ?
IMAGE_THUNK_DATA64 ends

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

IMAGE_OPTIONAL_HEADER64 struct
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

    ;
    ; NT additional fields.
    ;
    ImageBase               qword ?
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
    SizeOfStackReserve      qword ?
    SizeOfStackCommit       qword ?
    SizeOfHeapReserve       qword ?
    SizeOfHeapCommit        qword ?
    LoaderFlags             dword ?
    NumberOfRvaAndSizes     dword ?
    DataDirectory           IMAGE_DATA_DIRECTORY IMAGE_NUMBEROF_DIRECTORY_ENTRIES dup (<>)
IMAGE_OPTIONAL_HEADER64 ends

IMAGE_FILE_HEADER struct
    Machine                 word ?
    NumberOfSections        word ?
    TimeDateStamp           dword ?
    PointerToSymbolTable    dword ?
    NumberOfSymbols         dword ?
    SizeOfOptionalHeader    word ?
    Characteristics         word ?
IMAGE_FILE_HEADER ends

IMAGE_NT_HEADERS64 struct
    Signature       dword ?
    FileHeader      IMAGE_FILE_HEADER<> 
    OptionalHeader  IMAGE_OPTIONAL_HEADER64<>
IMAGE_NT_HEADERS64 ends

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
; Allocate the needed space and map the PE headers and sections
;	Args: <pe buffer>
;	Ret: <base address> on success, NULL otherwise
;
pe_map proc frame
	pem_file_mz EQU pem_OffsetHomeRCX
	pem_file_pe EQU LOCALS.Local1
	pem_va_mz EQU LOCALS.Local2
	pem_va_pe EQU LOCALS.Local3

	_CreateFrame pem_,LOCALS_SIZE,0,rsi,rdi
	_EndProlog
	_AllocHomeArea

	mov qword ptr pem_file_mz[rbp], rcx

	; allocate space for PE file
	mov eax, IMAGE_DOS_HEADER.e_lfanew[rcx]
	add rax, rcx
	mov qword ptr pem_file_pe[rbp], rax
	mov r9, PAGE_EXECUTE_READWRITE
	mov r8, MEM_COMMIT	
	mov edx, IMAGE_NT_HEADERS64.OptionalHeader.SizeOfImage[rax]
	xor rcx, rcx
	call VirtualAlloc
	test rax, rax
	jz @fail
	mov qword ptr pem_va_mz[rbp], rax

	; copy headers
	mov rax, qword ptr pem_file_pe[rbp]
	mov ecx, IMAGE_NT_HEADERS64.OptionalHeader.SizeOfHeaders[rax]
	mov rsi, qword ptr pem_file_mz[rbp]
	mov rdi, qword ptr pem_va_mz[rbp]
	rep movsb

	; copy all sections
	mov rax, qword ptr pem_file_pe[rbp]
	movzx rcx, IMAGE_NT_HEADERS64.FileHeader.NumberOfSections[rax]
	movzx r10, IMAGE_NT_HEADERS64.FileHeader.SizeOfOptionalHeader[rax]
	add r10, sizeof IMAGE_FILE_HEADER + sizeof IMAGE_NT_HEADERS64.Signature
	add r10, qword ptr pem_file_pe[rbp]

@@:
	; get pointer to section data	
	mov esi, IMAGE_SECTION_HEADER.PointerToRawData[r10]
	add rsi, qword ptr pem_file_mz[rbp]

	; get pointer to section memory
	mov edi, IMAGE_SECTION_HEADER.VirtualAddress[r10]
	add rdi, qword ptr pem_va_mz[rbp]

	; write section content
	mov r11, rcx ; save value
	mov ecx, IMAGE_SECTION_HEADER.SizeOfRawData[r10]	
	rep movsb
	mov rcx, r11 ; restore value

	; goto next section
	add r10, sizeof IMAGE_SECTION_HEADER
	loop @b

	; adjust the PEB to inserd the newly mapped module in the modules list
	mov rcx, qword ptr pem_va_mz[rbp]
	call pe_adjust_PEB
	test rax, rax
	jz @fail

	; return base address
	mov rax, qword ptr pem_va_mz[rbp]

@exit:
	_DeleteFrame rsi,rdi
	ret

@fail:
	xor rax, rax
	jmp @exit
pe_map endp


;
; Compute the Hash value of the given UNICODE_STRING.
;	Args: <unicode string ptr>
;	Ret: the hash value DWORD
;
pe_hash_data proc frame
	pehd_RtlHashUnicodeString EQU LOCALS.Local1
	pehd_HashValue EQU LOCALS.Local2
	_CreateFrame pehd_,LOCALS_SIZE,0
	_EndProlog
	_AllocHomeArea
	
	mov qword ptr pehd_OffsetHomeRCX[rbp], rcx

	; resolve function RtlHashUnicodeString
	mov rcx, offset g_string_ntdll
	call LoadLibraryA
	test rax, rax
	jz @fail

	mov rcx, rax
	mov rdx, offset g_string_RtlHashUnicodeString
	call GetProcAddress
	test rax, rax
	jz @fail
	mov qword ptr pehd_RtlHashUnicodeString[rbp], rax

	; hash data
	mov rcx, qword ptr pehd_OffsetHomeRCX[rbp]
	mov rdx, 1
	xor r8, r8
	lea r9, qword ptr pehd_HashValue[rbp]
	call qword ptr pehd_RtlHashUnicodeString[rbp]
	test rax, rax
	jnz @fail

	mov eax, dword ptr pehd_HashValue[rbp]

@exit:
	_DeleteFrame
	ret

@fail:
	xor rax, rax
	jmp @exit
pe_hash_data endp

;
; Adjust the PEB module list in order to insert the embedded binary among the loaded modules
;	Args: <loaded pe base address>
;	Ret: TRUE on success, FALSE otherwise
;
pe_adjust_PEB proc frame	
	peap_va_pe EQU LOCALS.Local1
	peap_mod_base EQU LOCALS.Local2
	peap_entry_src EQU LOCALS.Local3
	peap_buffer EQU LOCALS.Local4
	peap_STACK_SIZE EQU LOCALS_SIZE + MEMORY_BASIC_INFORMATION_SIZE
	_CreateFrame peap_,peap_STACK_SIZE,0,rbx,rsi,rdi,r12,r13
	_EndProlog
	_AllocHomeArea

	mov qword ptr peap_OffsetHomeRCX[rbp], rcx
	mov eax, IMAGE_DOS_HEADER.e_lfanew[rcx]
	add rax, rcx
	mov qword ptr peap_va_pe[rbp], rax

	; set image base address in PEB if it is not a DLL
	movzx eax, word ptr IMAGE_NT_HEADERS64.FileHeader.Characteristics[rax]
	test eax, IMAGE_FILE_DLL
	jnz @add_to_Ldr

	mov rax, gs:[60h]
	mov PEB.ImageBaseAddress[rax], rcx	

@add_to_Ldr:
	; get my module base in order to identify the entry in Peb.Ldr
	call get_module_base
	mov qword ptr peap_mod_base[rbp], rax

	; navigate the PEB to InLoadOrderModuleList
	mov rax, gs:[60h]
	mov rax, PEB.Ldr[rax]
	mov rbx, PEB_LDR_DATA.InLoadOrderModuleList[rax]	
	mov r10, rbx ; save the head

@find_module:
	; check if I found my module
	mov rax, LDR_DATA_TABLE_ENTRY.DllBase[rbx]
	cmp rax, qword ptr peap_mod_base[rbp]
	jz @add_module
		
	; go to the next module
	mov rbx, LDR_DATA_TABLE_ENTRY.InLoadOrderLinks.Flink[rbx]	
	
	; reached the head of the list?
	cmp rbx, r10 
	jz @exit
	jmp @find_module

@add_module:
	; modify the next module, this should be ntdll.dll
	mov rbx, LDR_DATA_TABLE_ENTRY.InLoadOrderLinks.Flink[rbx]
	mov qword ptr peap_entry_src[rbp], rbx

	; compute allocation size for the new LDR_DATA_TABLE_ENTRY
	mov r8, MEMORY_BASIC_INFORMATION_SIZE
	lea rdx, LOCALS[rbp]
	add rdx, LOCALS_SIZE ; pointer to MEMORY_BASIC_INFORMATION
	mov rcx, qword ptr peap_entry_src[rbp]
	call VirtualQuery
	test rax, rax
	jz @fail

	; starting from the target entry, calculate how much space is left till the end of the region
	lea rax, LOCALS[rbp]
	add rax, LOCALS_SIZE ; pointer to MEMORY_BASIC_INFORMATION
	mov rcx, MEMORY_BASIC_INFORMATION.BaseAddress[rax]
	sub rbx, rcx ; this is the gap between the start of the region and the LDR_DATA_TABLE_ENTRY
	mov rax, MEMORY_BASIC_INFORMATION.RegionSize[rax]
	sub rax, rbx ; this is the size of the memory that contains at least all the LDR_DATA_TABLE_ENTRY data
	mov rsi, rax ; save to non-volatile register

	; allocate memory
	mov rcx, rax
	call heap_alloc
	test rax, rax
	jz @fail

	; copy the LDR_DATA_TABLE_ENTRY data to the allocated memory
	mov rcx, rsi
	mov rsi, qword ptr peap_entry_src[rbp]
	mov rdi, rax 
	rep movsb

	; set the DllBase
	mov rcx, qword ptr peap_OffsetHomeRCX[rbp]
	mov qword ptr LDR_DATA_TABLE_ENTRY.DllBase[rax], rcx ; set the DLL base	
	
	; set the EntryPoint
	mov rcx, qword ptr peap_va_pe[rbp]
	mov ecx, IMAGE_NT_HEADERS64.OptionalHeader.AddressOfEntryPoint[rcx]
	add rcx, qword ptr peap_OffsetHomeRCX[rbp]
	mov qword ptr LDR_DATA_TABLE_ENTRY.EntryPoint[rax], rcx ; set the entry-point

	; set the ImageSize
	mov rcx, qword ptr peap_va_pe[rbp]
	mov ecx, IMAGE_NT_HEADERS64.OptionalHeader.SizeOfImage[rcx]
	mov qword ptr LDR_DATA_TABLE_ENTRY.SizeOfImage[rax], rcx ; set the image size
		
	; save to non-volatile register
	mov r13, rax

	; get module name
	mov rcx, 512h
	call heap_alloc
	test rax, rax
	jz @fail
	
	mov r12, rax ; save to non-volatile register

	call get_module_base
	test rax, rax
	jz @fail

	mov rdx, r12	
	mov r8, 512h	
	mov rcx, rax
	call GetModuleFileNameW
	test rax, rax
	jz @fail
	shl rax, 1

	; set the FullDllName
	mov qword ptr LDR_DATA_TABLE_ENTRY.FullDllName.Buffer[r13], r12
	mov LDR_DATA_TABLE_ENTRY.FullDllName.MaximumLength[r13], ax
	mov LDR_DATA_TABLE_ENTRY.FullDllName._Length[r13], ax
		
	; go to the DLL name
	add r12, rax	
	mov rdi, r12	
	std
	mov rcx, rax
	mov rax, 05ch
	repnz scasb
	cld

	add rdi, 3h ; base dll name
	sub r12, rdi ; base dll name size

	; allocate space for the DLL base name
	mov rcx, r12
	call heap_alloc
	test rax, rax
	jz @fail

	; copy the value
	mov rsi, rdi
	mov rdi, rax
	mov rcx, r12
	rep movsb	

	; set the BaseDllName
	mov qword ptr LDR_DATA_TABLE_ENTRY.BaseDllName.Buffer[r13], rax	
	mov rax, r12
	mov LDR_DATA_TABLE_ENTRY.BaseDllName.MaximumLength[r13], ax
	mov LDR_DATA_TABLE_ENTRY.BaseDllName._Length[r13], ax

	; set BaseNameHashValue
	lea rcx, qword ptr LDR_DATA_TABLE_ENTRY.BaseDllName[r13]
	call pe_hash_data
	test rax, rax
	jz @fail
	mov dword ptr LDR_DATA_TABLE_ENTRY.BaseNameHashValue[r13], eax

	; check if it is at least Win8 (6.2). If so I have to update more structures
	; If not, I don't care about these fields, since in Windows 7 the BaseAddressIndexNode
	; and the HashLinks fields are not used to resolve DLL and functions
	mov rcx, gs:[60h]
	mov edx, dword ptr [rcx + 0118h] ; OSMajorVersion
	cmp rdx, 6h
	ja @update_node_rbl
	mov edx, dword ptr [rcx + 011ch] ; OSMinorVersion
	cmp rdx, 2h
	jae @update_node_rbl
	jmp @additional_fields_update_completed

@update_node_rbl:	
	; update the BaseAddressIndexNode with a new node
	; more info: https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/shared/ntdef/rtl_balanced_node.htm?tx=210
	lea rcx, LDR_DATA_TABLE_ENTRY.BaseAddressIndexNode[r13]
@find_node_root:
	mov rdx, RTL_BALANCED_NODE.ParentValue[rcx]
	and rdx, not RTL_BALANCED_NODE_RESERVED_PARENT_MASK
	test rdx, rdx
	jz @root_node_found
	mov rcx, rdx
	jmp @find_node_root
@root_node_found:
	; point to the LDR_DATA_TABLE_ENTRY
	
	; add the node to the correct position starting from the root
	mov rbx, LDR_DATA_TABLE_ENTRY.DllBase[r13]
@insert_node_loop:	
	sub rcx, 0c8h
	cmp rbx, LDR_DATA_TABLE_ENTRY.DllBase[rcx]
	je @node_added_completed
	jb @check_node_left

	; checking Right node
	; did I found an empty spot? if so, add the node
	cmp LDR_DATA_TABLE_ENTRY.BaseAddressIndexNode.Right[rcx], 0h
	je @add_node_rigth

	; move down the tree and continue to search
	mov rcx, LDR_DATA_TABLE_ENTRY.BaseAddressIndexNode.Right[rcx]
	jmp @insert_node_loop
	
@check_node_left:
	; did I found an empty spot? if so, add the node
	cmp LDR_DATA_TABLE_ENTRY.BaseAddressIndexNode.Left[rcx], 0h
	je @add_node_left

	; move down the tree and continue to search
	mov rcx, LDR_DATA_TABLE_ENTRY.BaseAddressIndexNode.Left[rcx]
	jmp @insert_node_loop

@add_node_left:
	lea rbx, LDR_DATA_TABLE_ENTRY.BaseAddressIndexNode[r13]
	mov LDR_DATA_TABLE_ENTRY.BaseAddressIndexNode.Left[rcx], rbx
	jmp @node_added_completed

@add_node_rigth:
	lea rbx, LDR_DATA_TABLE_ENTRY.BaseAddressIndexNode[r13]
	mov LDR_DATA_TABLE_ENTRY.BaseAddressIndexNode.Right[rcx], rbx
@node_added_completed:	
		
	; Fix HashLinks list
	lea rdi, LDR_DATA_TABLE_ENTRY.HashLinks[r13]

	; Save the Flink value
	mov r10, LIST_ENTRY.Blink[rdi]
	mov r11, qword ptr LIST_ENTRY.Flink[r10]		

	; Update the HashLinks linked list, fix pre entry
	mov qword ptr LIST_ENTRY.Flink[r10], rdi
	mov qword ptr LIST_ENTRY.Blink[rdi], r10
	
	; Update the HashLinks linked list, fix post entry
	mov qword ptr LIST_ENTRY.Blink[r11], rdi
	mov qword ptr LIST_ENTRY.Flink[rdi], r11

@additional_fields_update_completed:

	 ; restore value
	mov rax, r13

	; finally, add the new entry to all the lists
	mov rcx, 3
	mov rsi, qword ptr peap_entry_src[rbp]

@insert_entry:
	mov r10, qword ptr LIST_ENTRY.Flink[rsi] ; save FLink value
	
	; fix pre entry
	mov qword ptr LIST_ENTRY.Flink[rsi], rax
	mov qword ptr LIST_ENTRY.Blink[rax], rsi

	; fix post entry
	mov qword ptr LIST_ENTRY.Blink[r10], rax
	mov qword ptr LIST_ENTRY.Flink[rax], r10
	
	; move to next list
	add rsi, sizeof LIST_ENTRY
	add rax, sizeof LIST_ENTRY
	loop @insert_entry

	mov rax, 1

@exit:
	_DeleteFrame rbx,rsi,rdi,r12,r13
	ret

@fail:
	xor rax, rax
	jmp @exit
pe_adjust_PEB endp

;
; Resolve PE imports
;	Args: <mapped PE>
;	Ret: TRUE on success, FALSE otherwise
;
pe_resolve_imports proc frame
	pri_va_pe EQU LOCALS.Local1
	pri_dll_handle EQU LOCALS.Local2
	_CreateFrame pri_,LOCALS_SIZE,0,rbx,rsi,rdi
	_EndProlog
	_AllocHomeArea
	mov qword ptr pri_OffsetHomeRCX[rbp], rcx

	; goto PE header
	mov eax, IMAGE_DOS_HEADER.e_lfanew[rcx]
	add rax, rcx
	mov qword ptr pri_va_pe[rbp], rax

	; check if we have an import directory
	lea rax, IMAGE_NT_HEADERS64.OptionalHeader.DataDirectory[rax+sizeof IMAGE_DATA_DIRECTORY]
	mov ecx, IMAGE_DATA_DIRECTORY._Size[rax]
	test rcx, rcx
	jz @finish

	; got to the import directory
	mov ebx, IMAGE_DATA_DIRECTORY.VirtualAddress[rax]
	add rbx, qword ptr pri_OffsetHomeRCX[rbp]

	; resolve all imports
@resolve_DLL_imports:
	cmp IMAGE_IMPORT_DESCRIPTOR.u.Characteristics[rbx], 0h
	jz @finish

	; load DLL
	mov ecx, IMAGE_IMPORT_DESCRIPTOR._Name[rbx]
	add rcx, qword ptr pri_OffsetHomeRCX[rbp]
	call LoadLibraryA
	test rax, rax
	jz @fail
	mov qword ptr pri_dll_handle[rbp], rax

	; load Thunk tables
	mov esi, IMAGE_IMPORT_DESCRIPTOR.u.OriginalFirstThunk[rbx]
	add rsi, qword ptr pri_OffsetHomeRCX[rbp]
	mov edi, IMAGE_IMPORT_DESCRIPTOR.FirstThunk[rbx]
	add rdi, qword ptr pri_OffsetHomeRCX[rbp]

@resolve_DLL_import:
	; get function ordinal
	mov rax, IMAGE_THUNK_DATA64.Ordinal[rsi]
	test rax, rax
	jz @goto_next_DLL

	; should it be resolved by ordinal?
	test rax, IMAGE_ORDINAL_FLAG32
	jz @resolve_import_by_names
	and rax, 0ffffh
	jmp @resolve_function_address	

@resolve_import_by_names:
	mov rax, IMAGE_THUNK_DATA64.AddressOfData[rsi]
	add rax, qword ptr pri_OffsetHomeRCX[rbp]
	lea rax, IMAGE_IMPORT_BY_NAME._Name[rax]

@resolve_function_address:
	mov rdx, rax
	mov rcx, qword ptr pri_dll_handle[rbp]
	call GetProcAddress
	test rax, rax
	jz @fail

	; write resolved address
	mov IMAGE_THUNK_DATA64.Function[rdi], rax

	; move next function
	add rsi, sizeof qword
	add rdi, sizeof qword
	jmp @resolve_DLL_import

@goto_next_DLL:
	add rbx, sizeof IMAGE_IMPORT_DESCRIPTOR
	jmp @resolve_DLL_imports

@finish:
	mov rax, 1

@exit:
	_DeleteFrame rbx,rsi,rdi
	ret

@fail:
	xor rax, rax
	jmp @exit
pe_resolve_imports endp

;
; Relocate the mapped PE
;	Args: <mapped pe address>
;	Ret: TRUE on success, FALSE otherwise
;
pe_relocate proc frame
	pere_va_pe EQU LOCALS.Local1
	pere_reloc_delta EQU LOCALS.Local2
	pere_reloc_size EQU LOCALS.Local3
	_CreateFrame pere_,LOCALS_SIZE,0,rbx
	_EndProlog
	_AllocHomeArea
	mov qword ptr pere_OffsetHomeRCX[rbp], rcx

	; goto PE header
	mov eax, IMAGE_DOS_HEADER.e_lfanew[rcx]
	add rax, rcx
	mov qword ptr pere_va_pe[rbp], rax

	; check if we have a relocation directory
	lea rax, IMAGE_NT_HEADERS64.OptionalHeader.DataDirectory[rax+sizeof IMAGE_DATA_DIRECTORY * 5]
	mov r10d, IMAGE_DATA_DIRECTORY._Size[rax]
	test r10, r10
	jz @finish

	; save the size to use it as a counter
	mov qword ptr pere_reloc_size[rbp], r10

	; got to the relocation directory
	mov ebx, IMAGE_DATA_DIRECTORY.VirtualAddress[rax]
	add rbx, qword ptr pere_OffsetHomeRCX[rbp]

	; compute relocation delta
	mov rax, qword ptr pere_va_pe[rbp]
	mov rax, IMAGE_NT_HEADERS64.OptionalHeader.ImageBase[rax]
	mov qword ptr pere_reloc_delta[rbp], rcx
	sub qword ptr pere_reloc_delta[rbp], rax

@relocate_block:
	; block size validation
	mov eax, IMAGE_BASE_RELOCATION.SizeOfBlock[rbx]
	test rax, rax
	jz @finish

	; each relocation block is a word, need to remove the header
	; and div by 2 to obtain the number of entries. RCX = # entries
	mov rcx, rax
	sub rcx, sizeof IMAGE_BASE_RELOCATION
	shr rcx, 1

	; update counter
	sub qword ptr pere_reloc_size[rbp], rax

	; get the VA of the current relocation block. R11 = reloc block base
	mov r11d, IMAGE_BASE_RELOCATION.VirtualAddress[rbx]
	add r11, qword ptr pere_OffsetHomeRCX[rbp]

	; move to the entry list. RBX = current reloc entry
	add rbx, sizeof IMAGE_BASE_RELOCATION

@relocate_block_entry:
	; R8 = VA entry offset, R9 = entry type
	movzx r9, word ptr [rbx]
	mov r8, r9	
	and r8, mask IMAGE_BASE_RELOCATIONENTRY._Offset	
	and r9, mask IMAGE_BASE_RELOCATIONENTRY._Type
	shr r9, 0ch

	; pre-compute values
	add r8, r11 ; VA
	mov rax, qword ptr pere_reloc_delta[rbp] ; delta 

	; check entry type
	cmp r9, 1h
	je @IMAGE_REL_BASED_HIGH
	cmp r9, 2h
	je @IMAGE_REL_BASED_LOW
	cmp r9, 3h
	je @IMAGE_REL_BASED_HIGHLOW
	cmp r9, 0ah
	je @IMAGE_REL_BASED_DIR64
	jmp @next_relocation_entry	

	; apply relocation according to the entry type
@IMAGE_REL_BASED_HIGH:	
	shr rax, 10h
	add word ptr [r8], ax
	jmp @next_relocation_entry

@IMAGE_REL_BASED_LOW:	
	add word ptr [r8], ax
	jmp @next_relocation_entry

@IMAGE_REL_BASED_HIGHLOW:
	add dword ptr [r8], eax

@IMAGE_REL_BASED_DIR64:
	add qword ptr [r8], rax

@next_relocation_entry:
	add rbx, sizeof word
	loop @relocate_block_entry

	; check remaining size
	cmp qword ptr pere_reloc_size[rbp], 0h
	jnz @relocate_block

@finish:
	mov rax, 1

@exit:
	_DeleteFrame rbx
	ret

@fail:
	xor rax, rax
	jmp @exit
pe_relocate endp

;
; Load the buffer containing the PE file
;	Args: <Mapped PE>
;	Ret: Loaded PE VA on success, NULL on error
;
pe_load proc frame
	_CreateFrame pl_,LOCALS
	_EndProlog
	_AllocHomeArea

	mov qword ptr pl_OffsetHomeRCX[rbp], rcx

	; resolve imports
	call pe_resolve_imports
	test rax, rax
	jz @fail	

	; relocate PE addresses
	mov rcx, qword ptr pl_OffsetHomeRCX[rbp]
	call pe_relocate
	test rax, rax
	jz @fail

	mov rax, 1

@exit:
	_DeleteFrame
	ret

@fail:
	xor rax, rax
	jmp @exit
pe_load endp

;
; Resolve an exported function from the input DLL.
;	Args: <DLL base>, <function name>
;	Ret: The address containing the function RVA on success, or NULL otherwise
;
pe_resolve_exported_function proc frame	
	peresex_dir_size EQU LOCALS.Local1
	peresex_dir EQU LOCALS.Local2
	peresex_pe EQU LOCALS.Local3
	peresex_counter EQU LOCALS.Local4
	_CreateFrame peresex_,LOCALS_SIZE,0,r11,r12
	_EndProlog
	_AllocHomeArea
	mov qword ptr peresex_OffsetHomeRCX[rbp], rcx
	mov qword ptr peresex_OffsetHomeRDX[rbp], rdx

	; go to PE
	mov r8d, IMAGE_DOS_HEADER.e_lfanew[rcx]
	add r8, rcx
	mov qword ptr peresex_pe[rbp], r8

	; ensure we have an export directory
	lea r8, IMAGE_NT_HEADERS64.OptionalHeader.DataDirectory[r8]
	mov eax, IMAGE_DATA_DIRECTORY._Size[r8]
	test rax, rax
	jz @exit
	mov qword ptr peresex_dir_size[rbp], rax

	; go to the export directory
	mov eax, IMAGE_DATA_DIRECTORY.VirtualAddress[r8]
	add rax, rcx
	mov qword ptr peresex_dir[rbp], rax

	; get export information, RCX = Numbers of Names, r11 = Address of Names
	mov ecx, IMAGE_EXPORT_DIRECTORY.NumberOfNames[rax]	
	mov r11d, IMAGE_EXPORT_DIRECTORY.AddressOfNames[rax]
	add r11, qword ptr peresex_OffsetHomeRCX[rbp]

	; index
	xor r12, r12
@find_exported_function:
	mov qword ptr peresex_counter[rbp], rcx

	; get the i-th function name
	mov ecx, dword ptr [r11 + r12 * sizeof dword]
	add rcx, qword ptr peresex_OffsetHomeRCX[rbp]
	
	; check if the name matches
	mov rdx, qword ptr peresex_OffsetHomeRDX[rbp]	
	call string_equals
	test rax, rax
	jnz @function_found

	; go to the next function
	inc r12
	mov rcx, qword ptr peresex_counter[rbp]
	loop @find_exported_function
	jmp @fail

@function_found:	
	; get the i-th function ordinal
	mov rax, qword ptr peresex_dir[rbp]
	mov r8d, IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals[rax]
	add r8, qword ptr peresex_OffsetHomeRCX[rbp]
	movzx r8, word ptr [r8 + r12 * sizeof word]

	; get the i-th function RVA 
	mov r9d, IMAGE_EXPORT_DIRECTORY.AddressOfFunctions[rax]
	add r9, qword ptr peresex_OffsetHomeRCX[rbp]
	lea rax, dword ptr [r9 + r8 * sizeof dword]

@exit:
	_DeleteFrame r11,r12
	ret

@fail:
	xor rax, rax
	jmp @exit
pe_resolve_exported_function endp