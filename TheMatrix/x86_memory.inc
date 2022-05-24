MEMORY_BASIC_INFORMATION struct
	BaseAddress			dword ?
	AllocationBase		dword ?
	AllocationProtect	dword ?
	PartitionId			word ?
	RegionSize			dword ?
	State				dword ?
	Protect				dword ?
	_Type				dword ?
MEMORY_BASIC_INFORMATION ends

;
; Query the memory to obtain the allocation base address
;	Args: None
;	Ret: The memory base address of the currently executing code
;
get_module_base proc
	local mem_info:MEMORY_BASIC_INFORMATION

	lea eax, mem_info
	invoke VirtualQuery, offset get_module_base, eax, sizeof MEMORY_BASIC_INFORMATION
	test eax, eax
	jz @fail

	lea eax, mem_info
	mov eax, MEMORY_BASIC_INFORMATION.AllocationBase[eax]

@exit:
	ret

@fail:
	mov eax, ebx
	jmp @exit
get_module_base endp

;
; Allocate memory
;	Args: <size>
;	Ret: the allocated region or NULL on error
;
heap_alloc proc allocation_size:dword
	call GetProcessHeap
	push allocation_size
	push HEAP_ZERO_MEMORY	
	push eax
	call HeapAlloc
	ret
heap_alloc endp

;
; Free memory
;	Args: <buffer>
;	Ret: void
;
heap_free proc buffer_addr:dword
	call GetProcessHeap
	push buffer_addr
	push 0h	
	push eax
	call HeapFree
	ret
heap_free endp