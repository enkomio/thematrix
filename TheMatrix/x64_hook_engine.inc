HOOK_DEF struct
	func_name		qword ?
	lib_name		qword ?
	orig_func		qword ?
	hook_func		qword ?
	trampoline		qword ?	
	trampoline_size	qword ?
	saved_reg1		qword ?
	saved_reg2		qword ?
	saved_reg3		qword ?
	saved_reg4		qword ?
HOOK_DEF ends

@trampoline_code_start:
	mov rax, 011223344aabbccddh ; store the address of the origin function
	mov qword ptr gs:[28h], rax
	mov rax, 011223344aabbccddh ; hook function address
	jmp rax
trampoline_code_size EQU $ - @trampoline_code_start

;
; Try to find a code cave in the mapped pe_resolve_exported_function
;	Args: <PE base address>
;	Ret: code cade VA on success, NULL on error
;
find_code_cave proc frame	
	findcc_hDll EQU LOCALS.Local1 
	findcc_num_sections EQU LOCALS.Local2
	findcc_STACK_SIZE EQU LOCALS_SIZE + MEMORY_BASIC_INFORMATION_SIZE
	_CreateFrame findcc_,findcc_STACK_SIZE,0,rbx,rsi,rdi,r11
	_EndProlog
	_AllocHomeArea
	mov qword ptr hset_OffsetHomeRCX[rbp], rcx
	mov findcc_hDll[rbp], rcx

	; find a code cave in the DLL (in general at the end of a section)
	; RCX = number of section, RBX = current section base
	mov r8d, IMAGE_DOS_HEADER.e_lfanew[rcx]
	add r8, rcx
	movzx rcx, IMAGE_NT_HEADERS64.FileHeader.NumberOfSections[r8]
	
	movzx rbx, IMAGE_NT_HEADERS64.FileHeader.SizeOfOptionalHeader[r8]
	add rbx, sizeof IMAGE_FILE_HEADER + sizeof IMAGE_NT_HEADERS64.Signature
	add rbx, r8

@check_section_for_cave:
	; update section index
	mov findcc_num_sections[rbp], rcx

	; get pointer to section data		
	mov esi, IMAGE_SECTION_HEADER.VirtualAddress[rbx]
	add rsi, qword ptr findcc_hDll[rbp]

	; compute section allocation size
	mov r8, MEMORY_BASIC_INFORMATION_SIZE
	lea rdx, LOCALS[rbp + LOCALS_SIZE] ; pointer to MEMORY_BASIC_INFORMATION
	mov rcx, rsi
	call VirtualQuery
	test rax, rax
	jz @fail

	; compute boundaries: section end (RSI) and allocation end (RDI).
	mov r9d, IMAGE_SECTION_HEADER.VirtualSize[rbx]
	add rsi, r9

	lea rax, LOCALS[rbp + LOCALS_SIZE] ; pointer to MEMORY_BASIC_INFORMATION
	mov rdi, MEMORY_BASIC_INFORMATION.BaseAddress[rax]
	add rdi, MEMORY_BASIC_INFORMATION.RegionSize[rax]
	sub rdi, trampoline_code_size
		
@search_cave:
	; verify that I haven't reached the section end
	cmp rsi, rdi
	jae @check_next_section

	; check if I have a slack of size trampoline_code_size of zero bytes
	mov rcx, trampoline_code_size
	xor r11, r11

@@:	
	movzx rax, byte ptr [rsi+rcx]
	add r11, rax
	loop @b	
	test r11, r11
	jz @cave_found
	add rsi, trampoline_code_size
	jmp @search_cave

@check_next_section:
	; no cave in this section, check the next one
	add rbx, sizeof IMAGE_SECTION_HEADER	
	mov rcx, findcc_num_sections[rbp]
	loop @check_section_for_cave
	jmp @fail

@cave_found:	
	; return the code cave VA
	mov rax, rsi

@exit:
	_DeleteFrame rbx,rsi,rdi,r11
	ret

@fail:
	xor rax, rax
	jmp @exit
find_code_cave endp

;
; This funcion uses EAT hooking with a trampoline. To be able to call the original function
; the function pointer is stored in the trampoline. To avoid to corrupt the stack the original 
; function address is saved in _NT_TIB.ArbitraryUserPointer. This implies that hook_call_original
; *cannot* be called by a different thread.
;	Args: <lib_name:ptr char> <func_name:ptr char> <hook:ptr HOOK_DEF>
;	Ret: TRUE on success, FALSE otherwise
;
hook_set proc frame	
	hset_hDll EQU LOCALS.Local1
	hset_cave_va EQU Locals.Local2
	hset_protection EQU Locals.Local3
	hset_func_offset EQU Locals.Local4
	hset_STACK_SIZE EQU LOCALS_SIZE + MEMORY_BASIC_INFORMATION_SIZE
	_CreateFrame hset_,hset_STACK_SIZE,0,rbx,rsi,rdi
	_EndProlog
	_AllocHomeArea
	mov qword ptr hset_OffsetHomeRCX[rbp], rcx
	mov qword ptr hset_OffsetHomeRDX[rbp], rdx
	mov qword ptr hset_OffsetHomeR8[rbp], r8

	; resolve the DLL
	call LoadLibraryA
	test rax, rax
	jz @fail
	mov qword ptr hset_hDll[rbp], rax

	mov rcx, rax
	call find_code_cave
	test rax, rax
	jz @fail
	mov qword ptr hset_cave_va[rbp], rax

	; unprotect code
	lea r9, qword ptr hset_protection[rbp]
	mov r8, PAGE_EXECUTE_READWRITE
	mov rdx, 0fh
	mov rcx, rax
	call VirtualProtect
	test rax, rax
	jz @fail

	; write the trampoline to the code cave
	mov rcx, trampoline_code_size
	mov rdi, qword ptr hset_cave_va[rbp]
	mov rsi, offset @trampoline_code_start
	rep movsb

	; write the address of the hook function in the trampoline
	mov r10, qword ptr hset_cave_va[rbp]
	add r10, 2
	add r10, sizeof qword
	add r10, 0bh
	mov r8, qword ptr hset_OffsetHomeR8[rbp]
	mov r8, qword ptr HOOK_DEF.hook_func[r8]
	mov qword ptr [r10], r8 ; write the address of the hook function	

	; resolve the exported function RVA
	mov rdx, qword ptr hset_OffsetHomeRDX[rbp]
	mov rcx, qword ptr hset_hDll[rbp]
	call pe_resolve_exported_function
	test rax, rax
	jz @fail
	mov qword ptr hset_func_offset[rbp], rax

	; set the HOOK_DEF orig_func property
	mov r8, qword ptr hset_OffsetHomeR8[rbp]
	mov eax, dword ptr [rax]
	add rax, qword ptr hset_hDll[rbp]	
	mov HOOK_DEF.orig_func[r8], rax

	; write the address of the original function function
	mov r10, qword ptr hset_cave_va[rbp]
	add r10, 2 
	mov r8, qword ptr hset_OffsetHomeR8[rbp]
	mov r8, qword ptr HOOK_DEF.orig_func[r8]
	mov qword ptr [r10], r8 ; write the address of the hook function	

	; set back protection
	lea r9, qword ptr hset_protection[rbp]
	mov r8, qword ptr hset_protection[rbp]
	mov rdx, 0fh
	mov rcx, qword ptr hset_cave_va[rbp]
	call VirtualProtect
	test rax, rax
	jz @fail

	; set the HOOK_DEF trampoline properties
	mov rax, qword ptr hset_cave_va[rbp]
	mov HOOK_DEF.trampoline[r8], rax
	mov HOOK_DEF.trampoline_size[r8], trampoline_code_size

	; unprotect code
	lea r9, qword ptr hset_protection[rbp]
	mov r8, PAGE_EXECUTE_READWRITE
	mov rdx, 0fh
	mov rcx, qword ptr hset_func_offset[rbp]
	call VirtualProtect
	test rax, rax
	jz @fail

	; compute the new RVA and write the trampoline RVA
	mov rax, qword ptr hset_func_offset[rbp]
	mov r8, qword ptr hset_cave_va[rbp]	
	sub r8, qword ptr hset_hDll[rbp]	
	mov dword ptr [rax], r8d

	; set back protection
	lea r9, qword ptr hset_protection[rbp]
	mov r8, qword ptr hset_protection[rbp]
	mov rdx, 0fh
	mov rcx, qword ptr hset_func_offset[rbp]
	call VirtualProtect
	test rax, rax
	jz @fail

	mov rax, 1

@exit:
	_DeleteFrame rbx,rsi,rdi
	ret

@fail:
	xor rax, rax
	jmp @exit
hook_set endp

;
; Place an hook to the specified function
;	Args: <lib_name:ptr char> <func_name:ptr char> <hook function addr>
;	Ret: ptr HOOK_DEF on success, FALSE otherwise
;
hook_add proc frame
	hadd_hook_def EQU LOCALS.Local1
	_CreateFrame hadd_,LOCALS_SIZE
	_EndProlog
	_AllocHomeArea

	mov qword ptr hadd_OffsetHomeRCX[rbp], rcx
	mov qword ptr hadd_OffsetHomeRDX[rbp], rdx
	mov qword ptr hadd_OffsetHomeR8[rbp], r8

	; allocate HOOK_DEF object
	mov rcx, sizeof HOOK_DEF
	call heap_alloc
	test rax, rax
	jz @fail
	mov qword ptr hadd_hook_def[rbp], rax

	; set hook function address
	mov r10, qword ptr hadd_OffsetHomeR8[rbp]
	mov HOOK_DEF.hook_func[rax], r10

	; set hook lib name
	mov rcx, qword ptr hadd_OffsetHomeRCX[rbp]
	call string_clone
	test rax, rax
	jz @fail
	mov r10, qword ptr hadd_hook_def[rbp]
	mov HOOK_DEF.lib_name[r10], rax

	; set hook func name
	mov rcx, qword ptr hadd_OffsetHomeRDX[rbp]
	call string_clone
	test rax, rax
	jz @fail
	mov r10, qword ptr hadd_hook_def[rbp]
	mov HOOK_DEF.func_name[r10], rax

	; now I can place the hook
	mov r8, qword ptr hadd_hook_def[rbp]
	mov rdx, qword ptr hadd_OffsetHomeRDX[rbp]
	mov rcx, qword ptr hadd_OffsetHomeRCX[rbp]
	call hook_set
	test rax, rax
	jz @fail

	mov rax, qword ptr hadd_hook_def[rbp]

@exit:
	_DeleteFrame
	ret

@fail:
	xor rax, rax
	jmp @exit
hook_add endp

;
; Call the original function
;	Args: <varargs arguments...>
;	Ret: the value of the hooked function
;
hook_call_original proc
	; the address of the original function was saved in gs:[0x28] (ArbitraryUserPointer), just call it
	mov rax, gs:[028h]
	jmp rax
hook_call_original endp