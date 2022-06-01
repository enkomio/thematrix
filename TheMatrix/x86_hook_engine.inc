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

@trampoline_code_start:
	mov eax, 011223344h ; store the address of the origin function
	add eax, 2 ; just the overwritten MOV EDI, EDI instruction
	assume fs:nothing
	mov dword ptr fs:[14h], eax
	assume fs:error
	mov eax, 011223344h ; hook function address
	jmp eax
trampoline_code_size EQU $ - @trampoline_code_start

;
; Try to find a code cave in the mapped pe_resolve_exported_function
;	Args: <PE base address>
;	Ret: code cade VA on success, NULL on error
;
find_code_cave proc base_addr:dword
	local pe_addr:dword
	local num_sections:dword
	local cur_section:dword
	local search_start:dword
	local search_end:dword
	local mem_info:MEMORY_BASIC_INFORMATION

	; go to PE
	mov eax, base_addr
	mov eax, IMAGE_DOS_HEADER.e_lfanew[eax]
	add eax, base_addr
	mov pe_addr, eax

	; got to the first section
	movzx ecx, IMAGE_NT_HEADERS32.FileHeader.SizeOfOptionalHeader[eax]
	add ecx, sizeof IMAGE_FILE_HEADER + sizeof IMAGE_NT_HEADERS32.Signature
	add ecx, pe_addr
	mov cur_section, ecx

	; get num of sections
	movzx ecx, IMAGE_NT_HEADERS32.FileHeader.NumberOfSections[eax]
	mov num_sections, ecx

@check_section_for_cave:
	; update index
	mov num_sections, ecx
	mov ebx, cur_section

	; get pointer to section data		
	mov eax, IMAGE_SECTION_HEADER.VirtualAddress[ebx]
	add eax, base_addr

	; compute start search VA
	mov ecx, IMAGE_SECTION_HEADER.VirtualSize[ebx]
	add ecx, eax
	mov search_start, ecx

	; compute section allocation size
	lea edx, mem_info
	invoke VirtualQuery, eax, edx, sizeof MEMORY_BASIC_INFORMATION
	test eax, eax
	jz @fail

	; compute end search VA
	lea eax, mem_info
	mov ecx, MEMORY_BASIC_INFORMATION.BaseAddress[eax]
	add ecx, MEMORY_BASIC_INFORMATION.RegionSize[eax]
	sub ecx, trampoline_code_size
	mov search_end, ecx

	mov esi, search_start
@search_cave:
	; verify that I haven't reached the section end	
	cmp esi, search_end
	jae @check_next_section

	; check if I have a slack of size trampoline_code_size of zero bytes
	mov ecx, trampoline_code_size
	xor ebx, ebx

@@:	
	movzx eax, byte ptr [esi+ecx]
	add ebx, eax
	loop @b	
	test ebx, ebx
	jz @cave_found
	add esi, trampoline_code_size
	jmp @search_cave

@check_next_section:
	; no cave in this section, check the next one
	add cur_section, sizeof IMAGE_SECTION_HEADER	
	mov ecx, num_sections
	loop @check_section_for_cave
	jmp @fail

@cave_found:	
	; return the code cave VA
	mov eax, esi

@exit:
	ret

@fail:
	xor eax, eax
	jmp @exit
find_code_cave endp

;
; This funcion uses the MS hot-patching method. The general concept is:
;	overwrite "MOV EDI, EDI" with a jump before the function
;	overwrite the space before the function with a jump to the trampoline
;	the trampoline set the function information and call the hooked function
; See https://devblogs.microsoft.com/oldnewthing/20110921-00/?p=9583
;	Args: <lib_name:ptr char> <func_name:ptr char> <hook:ptr HOOK_DEF>
;	Ret: TRUE on success, FALSE otherwise
;
hook_set proc lib_name:ptr char, func_name:ptr char, hook:ptr HOOK_DEF
	local code_cave:dword
	local old_protection:dword
	local hDll:dword
	
	; load library and does sanity check
	invoke LoadLibraryA, lib_name
	mov hDll, eax
	invoke GetProcAddress, eax, func_name
	cmp word ptr [eax], 0ff8bh ; check if it is "MOV EDI, EDI"
	jne @fail

	; set the orig_func value
	mov edi, hook
	mov HOOK_DEF.orig_func[edi], eax

	; find a code cave in the DLL
	invoke find_code_cave, hDll
	test eax, eax
	jz @fail
	mov code_cave, eax

	; unprotect code
	invoke VirtualProtect, code_cave, trampoline_code_size, PAGE_EXECUTE_READWRITE, addr old_protection
	test eax, eax
	jz @fail

	; write the trampoline to the code cave
	mov ecx, trampoline_code_size
	mov edi, code_cave
	mov esi, offset @trampoline_code_start
	rep movsb

	; fix the trampoline address
	mov ecx, hook
	mov edi, code_cave
	add edi, 1
	mov ebx, HOOK_DEF.orig_func[ecx]
	mov dword ptr [edi], ebx ; write the original function address
	add edi, sizeof dword ; skip address
	add edi, 0ah ; skip code that set FS and the jmp opcode
	mov ebx, HOOK_DEF.hook_func[ecx]
	mov dword ptr [edi], ebx ; write function hook address
	
	; restore protection
	invoke VirtualProtect, code_cave, trampoline_code_size, old_protection, addr old_protection
	test eax, eax
	jz @fail

	; set the trampoline information value
	mov edi, code_cave
	mov eax, hook
	mov HOOK_DEF.trampoline[eax], edi
	mov HOOK_DEF.trampoline_size[eax], trampoline_code_size

	; overwrite the MOV EDI, EDI
	mov edi, hook
	mov edi, HOOK_DEF.orig_func[edi]
	sub edi, 5h ; sub the space to write the long jump

	invoke VirtualProtect, edi, 7h, PAGE_EXECUTE_READWRITE, addr old_protection
	test eax, eax
	jz @fail
		
	; start write code
	mov esi, edi
	mov byte ptr [edi], 0e9h ; set opcode 
	inc edi

	; compute trampoline offset
	mov eax, hook
	mov eax, HOOK_DEF.trampoline[eax]
	sub eax, edi
	sub eax, 4h
	
	; write trampoline address	
	mov dword ptr [edi], eax ; set the trampoline address
	add edi, sizeof dword ; move to the MOV EDI, EDI address
	mov word ptr [edi], 0f9ebh ; overwrite MOV EDI, EDI to jump to the long jump

	; restore protection
	invoke VirtualProtect, esi, 7h, old_protection, addr old_protection
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
; Place an hook to the specified function
;	Args: <lib_name:ptr char> <func_name:ptr char> <hook function addr>
;	Ret: ptr HOOK_DEF on success, FALSE otherwise
;
hook_add proc C lib_name:ptr char, func_name:ptr char, hook_func:ptr void
	local hook:ptr HOOK_DEF
	local r_ebx:dword
	local r_esi:dword
	local r_edi:dword

	mov r_ebx, ebx
	mov r_esi, esi
	mov r_edi, edi

	invoke heap_alloc, sizeof HOOK_DEF
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
; Call the original function
;	Args: <varargs arguments...>
;	Ret: the value of the hooked function
;
hook_call_original proc
	; adjust stack
	pop eax

	; the address of the original function was saved in gs:[0x28] (ArbitraryUserPointer), just call it
	assume fs:nothing
	mov eax, dword ptr fs:[14h]
	assume fs:error
	jmp eax
hook_call_original endp

;
; This function pointer is used to call the original hooked function
;
g_hook_call_original dword hook_call_original
public C g_hook_call_original 