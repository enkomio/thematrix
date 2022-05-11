MEMORY_BASIC_INFORMATION struct
	BaseAddress			qword ?
	AllocationBase		qword ?
	AllocationProtect	dword ?
	PartitionId			word ?
	__padding0			word ?
	RegionSize			qword ?
	State				dword ?
	Protect				dword ?
	_Type				dword ?
	__padding1			dword ?
MEMORY_BASIC_INFORMATION ends

MEMORY_BASIC_INFORMATION_SIZE equ sizeof MEMORY_BASIC_INFORMATION

;
; Query the memory to obtain the allocation base address
;	Args: None
;	Ret: The memory base address of the currently executing code
;
get_module_base proc frame
	_CreateFrame gmb_,MEMORY_BASIC_INFORMATION_SIZE
	_EndProlog

	_AllocHomeArea
		
	mov qword ptr gmb_OffsetHomeRCX[rbp], rcx
	mov qword ptr gmb_OffsetHomeRDX[rbp], rdx
	mov qword ptr gmb_OffsetHomeR8[rbp], r8

	mov rcx, offset get_module_base
	mov rdx, rbp ; mem_info
	mov r8, sizeof MEMORY_BASIC_INFORMATION
	call VirtualQuery
	test rax, rax
	jz @exit

	mov rax, MEMORY_BASIC_INFORMATION.AllocationBase[rbp]

@exit:
	_DeleteFrame
	ret
get_module_base endp

;
; Allocate memory
;	Args: <size>
;	Ret: the allocated region or NULL on error
;
heap_alloc proc frame
	_CreateFrame ha_
	_EndProlog
	_AllocHomeArea
	mov qword ptr ha_OffsetHomeRCX[rbp], rcx

	call GetProcessHeap
	mov rcx, rax
	mov rdx, HEAP_ZERO_MEMORY
	mov r8, qword ptr ha_OffsetHomeRCX[rbp]
	call HeapAlloc
	_DeleteFrame
	ret
heap_alloc endp

;
; Free memory
;	Args: <buffer>
;	Ret: void
;
heap_free proc frame
	_CreateFrame hf_
	_EndProlog
	_AllocHomeArea
	mov qword ptr hf_OffsetHomeRCX[rbp], rcx

	call GetProcessHeap
	mov r8, qword ptr hf_OffsetHomeRCX[rbp]
	xor rdx, rdx
	mov rcx, rax
	call HeapFree
	_DeleteFrame
	ret
heap_free endp