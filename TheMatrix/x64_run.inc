;
; Load the embedded binary
;	Args: None
;	Ret: The binary on success, NULL otherwise
;
load_embedded_binary proc frame
	leb_hMod EQU LOCALS.Local1
	leb_hRes EQU LOCALS.Local2
	leb_hGlobal EQU LOCALS.Local3
	leb_res_buffer EQU LOCALS.Local4

	_CreateFrame leb_,LOCALS_SIZE,0,rsi,rdi,r14,r15
	_EndProlog
	_AllocHomeArea

	call get_module_base
	test rax, rax
	jz @fail
	mov qword ptr leb_hMod[rbp], rax

	; load the binary from the resource
	mov r8, RT_VERSION
	mov rdx, VS_VERSION_INFO
	mov rcx, qword ptr leb_hMod[rbp]
	call FindResourceA
	test rax, rax
	jz @exit
	mov qword ptr leb_hRes[rbp], rax
		
	mov rdx, qword ptr leb_hRes[rbp]
	mov rcx, qword ptr leb_hMod[rbp]
	call LoadResource
	test rax, rax
	jz @fail
	mov qword ptr leb_hGlobal[rbp], rax

	mov rcx, qword ptr leb_hGlobal[rbp]
	call LockResource
	test rax, rax
	jz @fail
	mov qword ptr leb_res_buffer[rbp], rax

	; get resource size
	mov rdx, qword ptr leb_hRes[rbp]
	mov rcx, qword ptr leb_hMod[rbp]
	call SizeofResource
	test rax, rax
	jz @fail

	mov r14, rax ; save value to non-volatile register

	; allocate memory and copy the resource content
	mov r9, PAGE_READWRITE
	mov r8, MEM_COMMIT
	mov rdx, rax
	xor rcx, rcx
	call VirtualAlloc
	test rax, rax
	jz @fail
	mov r15, rax

	; copy the resource content to the newly allocated memory
	mov rcx, r14
	mov rsi, qword ptr leb_res_buffer[rbp]
	mov rdi, r15
	rep movsb

	; free resources
	mov rcx, qword ptr leb_hRes[rbp]
	call FreeResource

	mov rax, r15

@exit:
	_DeleteFrame rsi,rdi,r14,r15
	ret

@fail:
	xor rax, rax
	jmp @exit
load_embedded_binary endp

;
; Run the embedded binary
;	Args: The arguments might vary according to how the binary is invoked (.DLL or .EXE)
;	Ret: The PE base address on success, NULL otherwise
;
run_binary proc frame
	_CreateFrame rb_,LOCALS_SIZE
	_EndProlog
	_AllocHomeArea

	mov qword ptr rb_OffsetHomeRCX[rbp], rcx
	mov qword ptr rb_OffsetHomeRDX[rbp], rdx
	mov qword ptr rb_OffsetHomeR8[rbp], r8
	mov qword ptr rb_OffsetHomeR9[rbp], r9

	; first load the embedded PE binary
	call load_embedded_binary
	test rax, rax
	jz @fail
	mov qword ptr LOCALS.Local1[rbp], rax

	; hook functions. This must be done before the embedded binary is loaded,
	; since in x64 we use EAT hooking. If not done in this way, the resolved
	; functions will have the real values in the IAT and not the hooked ones.
	mov rcx, qword ptr LOCALS.Local2[rbp]
	call hooks_init
	test rax, rax
	jz @fail

	; load the PE in memory
	mov rcx, qword ptr LOCALS.Local1[rbp]
	call pe_load
	test rax, rax
	jz @fail
	mov qword ptr LOCALS.Local2[rbp], rax

	; cleanup
	mov r8, MEM_DECOMMIT
	xor rdx, rdx
	mov rcx, qword ptr LOCALS.Local1[rbp]
	call VirtualFree
	test rax, rax
	jz @fail	

	; flush instructions
	xor r8, r8
	xor rdx, rdx
	mov rcx, -1
	call FlushInstructionCache

	; restore arguments
	mov rcx, qword ptr rb_OffsetHomeRCX[rbp]
	mov rdx, qword ptr rb_OffsetHomeRDX[rbp]
	mov r8, qword ptr rb_OffsetHomeR8[rbp]
	mov r9, qword ptr rb_OffsetHomeR9[rbp]

	; call OEP
	mov r10, qword ptr LOCALS.Local2[rbp]
	mov eax, IMAGE_DOS_HEADER.e_lfanew[r10]
	add rax, r10
	mov eax, IMAGE_NT_HEADERS64.OptionalHeader.AddressOfEntryPoint[rax]	
	add rax, r10
	call rax

	; return base address
	mov rax, qword ptr LOCALS.Local2[rbp]

@exit:
	_DeleteFrame
	ret

@fail:
	xor rax, rax
	jmp @exit
run_binary endp