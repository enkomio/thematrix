;
; Write to console the input buffer
;	Args: <buffer to print>, <buffer size>
;	Ret: TRUE on success, FALSE otherwise
;
print_buffer proc frame
	_CreateFrame pb_,LOCALS_SIZE
	_EndProlog
	_AllocHomeArea

	mov qword ptr pb_OffsetHomeRCX[rbp], rcx
	mov qword ptr pb_OffsetHomeRDX[rbp], rdx

	mov rcx, STD_OUTPUT_HANDLE
	call GetStdHandle
	test rax, rax
	jz @fail

	push 0
	lea r9, LOCALS.Local1[rbp]
	mov r8, qword ptr pb_OffsetHomeRDX[rbp]
	mov rdx, qword ptr pb_OffsetHomeRCX[rbp]
	mov rcx, rax
	_AllocHomeArea
	call WriteConsoleA
	test rax, rax
	jz @fail

	mov rax, 1

@exit:
	_DeleteFrame
	ret

@fail:
	xor rax, rax
	jmp @exit
print_buffer endp

;
; Return the string length
;	Args: <string>
;	Ret: The length of the string, until a max of 0xffff bytes
;
strlen proc frame
	_CreateFrame slen_,0,0,rdi
	_EndProlog

	mov qword ptr slen_OffsetHomeRCX[rbp], rcx

	mov rcx, 0ffffh
	mov rdi, qword ptr slen_OffsetHomeRCX[rbp]
	xor rax, rax
	repnz scasb
	sub rdi, qword ptr slen_OffsetHomeRCX[rbp]
	dec rdi
	mov rax, rdi

	_DeleteFrame rdi
	ret
strlen endp

;
; Write to console the input ASCII string
;	Args: <String to print>
;	Ret: TRUE on success, FALSE otherwise
;
print_line proc frame
	_CreateFrame pl_
	_EndProlog
	_AllocHomeArea

	mov qword ptr pl_OffsetHomeRCX[rbp], rcx	

	call strlen
	mov rdx, rax
	mov rcx, qword ptr pl_OffsetHomeRCX[rbp]	
	call print_buffer

	_DeleteFrame
	ret
print_line endp