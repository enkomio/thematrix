;
; Compute the string length
;	Args: <string buffer>
;	Ret: string length
;
string_len proc frame
	_CreateFrame stringlen_,0,0,rdi
	_EndProlog
	mov qword ptr stringlen_OffsetHomeRCX[rbp], rcx

	xor rax, rax
	mov rdi, rcx
	mov rcx, -1
	repnz scasb
	neg rcx
	dec rcx
	mov rax, rcx

	_DeleteFrame rdi
	ret
string_len endp

;
; Clone the given string
;	Args: <string buffer>
;	Ret: cloned string on success, NULL on error
;
string_clone proc frame
	_CreateFrame stringcl_,LOCALS_SIZE,0,rsi,rdi
	_EndProlog
	mov qword ptr stringcl_OffsetHomeRCX[rbp], rcx

	; compute string length for allocation
	call string_len
	inc rax
	mov qword ptr LOCALS.Local1[rbp], rax
	
	; allocate space
	mov rcx, rax
	call heap_alloc
	test rax, rax
	jz @fail
	mov qword ptr LOCALS.Local2[rbp], rax

	; copy the string
	mov rsi, qword ptr stringcl_OffsetHomeRCX[rbp]
	mov rdi, rax
	mov rcx, qword ptr LOCALS.Local1[rbp]
	rep movsb

	mov rax, qword ptr LOCALS.Local2[rbp]

@exit:
	_DeleteFrame rsi,rdi
	ret

@fail:
	xor rax, rax
	jmp @exit
string_clone endp