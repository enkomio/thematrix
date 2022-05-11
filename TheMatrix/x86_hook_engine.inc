HOOK_DEF struct
	func_name		dword ?
	lib_name		dword ?
	log_dir			dword ?
	orig_func		dword ?
	hook_func		dword ?
	trampoline		dword ?	
	trampoline_size	dword ?
	hook_counter	dword ?
	saved_reg1		dword ?
	saved_reg2		dword ?
	saved_reg3		dword ?
	saved_reg4		dword ?
HOOK_DEF ends

;
; This funcion uses the MS hot-patching method.
; See https://devblogs.microsoft.com/oldnewthing/20110921-00/?p=9583
;
hook_set proc C lib_name:ptr char, func_name:ptr char, hook:ptr HOOK_DEF
	local old_protection:dword
	local long_jump:dword
	
	invoke LoadLibraryA, lib_name
	invoke GetProcAddress, eax, func_name
	cmp word ptr [eax], 0ff8bh ; check if it is mov edi, edi
	jne @fail

	; set the value
	mov edi, hook
	mov HOOK_DEF.orig_func[edi], eax
	
	; set my hook	
	mov edi, eax
	lea eax, dword ptr [eax-5h]
	mov long_jump, eax
	invoke VirtualProtect, long_jump, 0fh, PAGE_EXECUTE_READWRITE, addr old_protection
	test eax, eax
	jz @fail

	; place hook
	mov eax, long_jump
	mov byte ptr [eax], 0e9h ; set opcode
	inc eax

	mov ebx, hook
	mov ebx, HOOK_DEF.hook_func[ebx]
	sub ebx, eax
	sub ebx, 4h
	mov dword ptr [eax], ebx ; set func address

	mov word ptr [edi], 0f9ebh ; set trampoline

	; set the value
	mov eax, hook
	mov HOOK_DEF.trampoline[eax], edi
	mov HOOK_DEF.trampoline_size[eax], 2h

	; restore protection
	invoke VirtualProtect, long_jump, 0fh, old_protection, addr old_protection
	test eax, eax
	jz @fail

	mov eax, 1
@exit:
	ret

@fail:
	xor eax, eax
	jmp @exit
hook_set endp

;
; add a function hook. return the hook object or null on error
;
hook_add proc C export lib_name:ptr char, func_name:ptr char, hook_func:ptr void
	local hook:ptr HOOK_DEF
	local r_ebx:dword
	local r_esi:dword
	local r_edi:dword

	mov r_ebx, ebx
	mov r_esi, esi
	mov r_edi, edi

	invoke mem_alloc, sizeof HOOK_DEF
	test eax, eax
	jz @fail
	mov hook, eax

	; set hook function
	mov ebx, hook_func
	mov HOOK_DEF.hook_func[eax], ebx

	; set hook lib name
	invoke string_clone, lib_name
	test eax, eax
	jz @fail
	mov ebx, hook
	mov HOOK_DEF.lib_name[ebx], eax

	; set hook func name
	invoke string_clone, func_name
	test eax, eax
	jz @fail
	mov ebx, hook
	mov HOOK_DEF.func_name[ebx], eax

	invoke hook_set, lib_name, func_name, hook
	test eax, eax
	jz @fail

	mov eax, hook
@exit:
	mov ebx, r_ebx
	mov esi, r_esi
	mov edi, r_edi
	ret

@fail:
	xor eax, eax
	jmp @exit
hook_add endp

;
; call the original function. Accept as input the hook
;
hook_call_original proc C export
	lea ecx, dword ptr [esp + 4] ; save the value
	pop edx ; pop the return address to a non-volatile register

	; pop the first argument that is the hook_def structure
	pop eax
	mov HOOK_DEF.saved_reg1[eax], ecx
	mov HOOK_DEF.saved_reg2[eax], edx
	mov HOOK_DEF.saved_reg3[eax], esi
	mov esi, eax ; persist the hook value via non-volatile register
	mov ecx, HOOK_DEF.orig_func[eax]
	add ecx, HOOK_DEF.trampoline_size[eax]

	; call the origin function (the input arguments are the correct one specified by the caller)
	call ecx	

	; restore the correct return address from the non-volatile register
	mov esp, HOOK_DEF.saved_reg1[esi]
	push HOOK_DEF.saved_reg2[esi]
	mov esi, HOOK_DEF.saved_reg3[esi]
	ret
hook_call_original endp

hook_log_data proc C export hook:ptr HOOK_DEF, data_size:dword, data:ptr byte
	local file_name:ptr char
	local log_dir:ptr char
	local hFile:dword
	local nCount:dword
	local pid:dword
	local r_ebx:dword
	local r_esi:dword
	local r_edi:dword

	mov r_ebx, ebx
	mov r_esi, esi
	mov r_edi, edi

	mov eax, hook
	mov eax, HOOK_DEF.log_dir[eax]
	mov log_dir, eax
	test eax, eax
	jz @f

	; create the directory
	invoke CreateDirectoryA, log_dir, 0h
@@:

	invoke GetCurrentProcessId
	mov pid, eax

	mov ebx, hook
	;invoke snprintf, 0h, 0h, offset g_string_format_log, log_dir, pid, HOOK_DEF.lib_name[ebx], HOOK_DEF.func_name[ebx], HOOK_DEF.hook_counter[ebx]
	test eax, eax
	jz @fail

	inc eax
	mov esi, eax
	invoke mem_alloc, eax
	test eax, eax
	jz @fail
	mov file_name, eax

	mov ebx, hook
;	invoke snprintf, file_name, esi, offset g_string_format_log, log_dir, pid, HOOK_DEF.lib_name[ebx], HOOK_DEF.func_name[ebx], HOOK_DEF.hook_counter[ebx]
	test eax, eax
	jz @fail

	inc HOOK_DEF.hook_counter[ebx]

	invoke CreateFileA, file_name, GENERIC_READ_WRITE, 0h, 0h, CREATE_NEW, 0h, 0h
	cmp eax, INVALID_HANDLE_VALUE
	je @fail
	mov hFile, eax

	invoke WriteFile, hFile, data, data_size, addr nCount, 0h
	test eax, eax
	jz @fail

	invoke CloseHandle, hFile

@exit:
	mov ebx, r_ebx
	mov esi, r_esi
	mov edi, r_edi
	ret
@fail:
	xor eax, eax
	jmp @exit
hook_log_data endp

hook_set_log_folder proc C export hook:ptr HOOK_DEF, folder:ptr char
	local r_ebx:dword
	local r_esi:dword
	local r_edi:dword

	mov r_ebx, ebx
	mov r_esi, esi
	mov r_edi, edi

	invoke string_clone, folder
	test eax, eax
	jz @fail

	mov ebx, hook
	test ebx, ebx
	jz @fail

	mov HOOK_DEF.log_dir[ebx], eax

@exit:
	mov ebx, r_ebx
	mov esi, r_esi
	mov edi, r_edi
	ret
@fail:
	xor eax, eax
	jmp @exit
hook_set_log_folder endp