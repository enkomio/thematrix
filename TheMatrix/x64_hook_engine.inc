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

;
; This funcion uses EAT hooking.
; See https://devblogs.microsoft.com/oldnewthing/20110921-00/?p=9583
;	Args: <lib_name:ptr char> <func_name:ptr char> <hook:ptr HOOK_DEF>
;	Ret: TRUE on success, FALSE otherwise
;
hook_set proc frame	
	hset_hDll EQU LOCALS.Local1
	hset_cave_va EQU Locals.Local2
	hset_protection EQU Locals.Local3
	hset_func_offset EQU Locals.Local4
	_CreateFrame hset_,LOCALS_SIZE,0,rbx
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

	; TODO: this method allows just one hook. Implements a generic one.

	; find a code cave in the DLL (in general at the end of a section)
	; RCX = number of section, RBX = current section base
	mov r8d, IMAGE_DOS_HEADER.e_lfanew[rax]
	add r8, rax
	movzx rcx, IMAGE_NT_HEADERS64.FileHeader.NumberOfSections[r8]

	movzx rbx, IMAGE_NT_HEADERS64.FileHeader.SizeOfOptionalHeader[r8]
	add rbx, sizeof IMAGE_FILE_HEADER + sizeof IMAGE_NT_HEADERS64.Signature
	add rbx, r8

@check_section_for_cave:
	; get pointer to section data	
	mov r9d, IMAGE_SECTION_HEADER.VirtualSize[rbx]
	mov r10d, IMAGE_SECTION_HEADER.VirtualAddress[rbx]
	add r10, qword ptr hset_hDll[rbp]
	
	; check if the last bytes are zero
	add r10, r9
	vmovups xmm0, xmmword ptr [r10]
	ptest xmm0, xmm0
	jz @cave_found

	; check the next section
	add rbx, sizeof IMAGE_SECTION_HEADER	
	loop @check_section_for_cave
	jmp @fail
@cave_found:
	mov qword ptr hset_cave_va[rbp], r10

	; unprotect code
	lea r9, qword ptr hset_protection[rbp]
	mov r8, PAGE_EXECUTE_READWRITE
	mov rdx, 0fh
	mov rcx, r10
	call VirtualProtect
	test rax, rax
	jz @fail

	; write the trampoline to the code cave
	mov r10, qword ptr hset_cave_va[rbp]
	mov word ptr [r10], 0b848h
	add r10, 2
	mov r8, qword ptr hset_OffsetHomeR8[rbp]
	mov r8, qword ptr HOOK_DEF.hook_func[r8]
	mov qword ptr [r10], r8
	add r10, sizeof qword
	mov word ptr [r10], 0e0ffh

	; set back protection
	lea r9, qword ptr hset_protection[rbp]
	mov r8, qword ptr hset_protection[rbp]
	mov rdx, 0fh
	mov rcx, qword ptr hset_cave_va[rbp]
	call VirtualProtect
	test rax, rax
	jz @fail

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

	; set the HOOK_DEF trampoline properties
	mov rax, qword ptr hset_cave_va[rbp]
	mov HOOK_DEF.trampoline[r8], rax
	mov HOOK_DEF.trampoline_size[r8], 0fh

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
	_DeleteFrame rbx
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
;	Args: <HOOK_DEF ptr>, <varargs arguments...>
;	Ret: the value of the hooked function
;
hook_call_original proc
	ret
hook_call_original endp