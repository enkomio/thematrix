;
; Compute the ascii string length
;	Args: <string buffer>
;	Ret: string length
;
ascii_string_len proc frame
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
ascii_string_len endp

;
; Compute the unicode string length (in bytes)
;	Args: <string buffer>
;	Ret: string length
;
unicode_string_len proc frame
	_CreateFrame stringlen_
	_EndProlog
	mov qword ptr stringlen_OffsetHomeRCX[rbp], rcx

	mov rdx, rcx
	xor rcx, rcx
@unicode_string_len_loop:
	mov ax, word ptr [rdx]	
	inc rdx
	inc rcx
	test ax, ax
	jnz @unicode_string_len_loop
	dec rcx
	mov rax, rcx

	_DeleteFrame
	ret
unicode_string_len endp

;
; Clone the given string
;	Args: <string buffer>
;	Ret: cloned string on success, NULL on error
;
string_clone proc frame
	_CreateFrame stringcl_,LOCALS_SIZE,0,rsi,rdi
	_EndProlog
	_AllocHomeArea
	mov qword ptr stringcl_OffsetHomeRCX[rbp], rcx

	; compute string length for allocation
	call ascii_string_len
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

;
; Compare two strings
;	Args: <string A>, <string B>
;	Ret: TRUE if both strings are equal, FALSE otherwise
;
string_equals proc frame
	_CreateFrame stringeq_,LOCALS_SIZE,0,rsi,rdi
	_EndProlog
	_AllocHomeArea
	mov qword ptr stringeq_OffsetHomeRCX[rbp], rcx
	mov qword ptr stringeq_OffsetHomeRDX[rbp], rdx

	; compare the two strings length
	call ascii_string_len
	mov rsi, rax

	mov rcx, rdx
	call ascii_string_len
	cmp rax, rsi
	jne @not_equal

	; the strings have the same length, check content
	mov rcx, rax
	mov rsi, qword ptr stringeq_OffsetHomeRCX[rbp]
	mov rdi, qword ptr stringeq_OffsetHomeRDX[rbp]
	repe cmpsb
	test rcx, rcx
	jnz @not_equal

	mov rax, 1

@exit:
	_DeleteFrame rsi,rdi
	ret

@not_equal:
	xor rax, rax
	jmp @exit
string_equals endp