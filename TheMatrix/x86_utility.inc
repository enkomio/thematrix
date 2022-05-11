;
; Allocate a chunk of memory
;
mem_alloc proc allocation_size:dword
	call GetProcessHeap
	push allocation_size
	push HEAP_ZERO_MEMORY	
	push eax
	call HeapAlloc
	ret
mem_alloc endp

;
; Free a chunk of memory
;
mem_free proc buffer_addr:dword
	call GetProcessHeap
	push buffer_addr
	push 0h	
	push eax
	call HeapFree
	ret
mem_free endp

;
; Compute the string length
;
string_len proc buffer:dword
	xor eax, eax
	mov edi, buffer
	mov ecx, -1
	repnz scasb
	neg ecx
	dec ecx
	mov eax, ecx
	ret
string_len endp

;
; clone the given string
;
string_clone proc buffer:dword
	local l:dword
	local cloned_string:dword

	invoke string_len, buffer
	inc eax
	mov l, eax

	invoke mem_alloc, l
	test eax, eax
	jz @exit
	mov cloned_string, eax

	mov edi, cloned_string
	mov esi, buffer
	mov ecx, l
	rep movsb

	mov eax, cloned_string

@exit:
	ret
@fail:
	xor eax, eax
	jmp @exit
string_clone endp