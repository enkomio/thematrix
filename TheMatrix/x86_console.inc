; from project https://github.com/enkomio/s4tanic0d3

;
; Write to console the input buffer
;	Args: <buffer to print>, <buffer size>
;	Ret: TRUE on success, FALSE otherwise
;
print_buffer proc
	push ebp
	mov ebp, esp
	sub esp, sizeof dword
	push ebx
	
	; write string
	lea ebx, [ebp+local0]
	push 0
	push ebx
	push [ebp+arg1]
	push dword ptr [ebp+arg0]
	
	push STD_OUTPUT_HANDLE
	call GetStdHandle
	push eax

	call WriteConsoleA

	pop ebx
	mov esp, ebp
	pop ebp
	ret
print_buffer endp

; return the string length in ECX
strlen macro input
	push edi
	push eax
	mov ecx, 0ffffh
	mov edi, input
	xor eax, eax
	repnz scasb 
	sub edi, input
	dec edi
	mov ecx, edi
	pop eax
	pop edi	
endm

;
; Write to console the input ASCII string
;	Args: <String to print>
;	Ret: TRUE on success, FALSE otherwise
;
print_line proc
	push ebp
	mov ebp, esp

	; compute string length
	strlen (dword ptr [ebp+arg0])

	push ecx
	push dword ptr [ebp+arg0]
	call print_buffer

	mov esp, ebp
	pop ebp
	ret
print_line endp