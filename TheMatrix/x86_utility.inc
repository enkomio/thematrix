;
; Compute the string length
;	Args: <string buffer>
;	Ret: string length
;
string_len proc buffer:dword
	push edi ; save value
	xor eax, eax
	mov edi, buffer
	mov ecx, -1
	repnz scasb
	neg ecx
	dec ecx
	mov eax, ecx
	pop edi ; restore value
	ret
string_len endp

;
; Clone the given string
;	Args: <string buffer>
;	Ret: cloned string on success, NULL on error
;
string_clone proc buffer:dword
	local l:dword
	local cloned_string:dword

	invoke string_len, buffer
	inc eax
	mov l, eax

	invoke heap_alloc, l
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

;
; Compare two strings
;	Args: <string A>, <string B>
;	Ret: TRUE if both strings are equal, FALSE otherwise
;
string_equals proc str1:dword, str2:dword	
	local l_esi:dword
	local l_edi:dword

	; save non-volatile registers
	mov l_esi, esi
	mov l_edi, edi

	; compare the two strings length
	invoke string_len, str1
	mov ecx, eax

	invoke string_len, str2
	cmp eax, ecx
	jne @not_equal	

	; the strings have the same length, check content
	mov esi, str1
	mov edi, str2
	repe cmpsb
	test ecx, ecx
	jnz @not_equal

	mov eax, 1

@exit:
	; restore registers
	mov esi, l_esi
	mov edi, l_edi
	ret

@not_equal:
	xor eax, eax
	jmp @exit
string_equals endp