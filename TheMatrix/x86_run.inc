load_embedded_resource proc
	local file_content:ptr byte
	local hRes:dword
	local hGlobal:dword
	local res_buffer:ptr byte
	local res_size:dword
	local hMod:dword

	call get_module_base
	test eax, eax
	jz @fail
	mov hMod, eax

	invoke FindResourceA, hMod, VS_VERSION_INFO, RT_VERSION
	test eax, eax
	jz @fail
	mov hRes, eax

	invoke LoadResource, hMod, hRes
	test eax, eax
	jz @fail
	mov hGlobal, eax

	invoke LockResource, hGlobal
	test eax, eax
	jz @fail
	mov res_buffer, eax

	invoke SizeofResource, hMod, hRes
	mov res_size, eax
	invoke VirtualAlloc, 0h, res_size, MEM_COMMIT, PAGE_READWRITE
	test eax, eax
	jz @fail
	mov file_content, eax

	; copy the res content to the allocated buffer
	mov ecx, res_size
	mov esi, res_buffer
	mov edi, file_content
	rep movsb

	invoke FreeResource, hRes
	mov eax, file_content

@exit:
	ret

@fail:
	xor eax, eax
	jmp @exit
load_embedded_resource endp

run_binary proc
	local file_content:ptr byte
	local base_addr:ptr byte
	local pe_addr:ptr byte
		
	invoke load_embedded_resource
	test eax, eax
	jz @fail
	mov file_content, eax

	invoke pe_load, file_content
	test eax, eax
	jz @fail
	mov base_addr, eax

	; go to PE
	mov eax, base_addr
	mov eax, IMAGE_DOS_HEADER.e_lfanew[eax]
	add eax, base_addr
	mov pe_addr, eax	

	; free input buffer
	invoke VirtualFree, file_content, 0h, MEM_DECOMMIT

	; hooks all functions
	call hooks_init
	test eax, eax
	jz @fail

	; flush instructions
	invoke FlushInstructionCache, -1h, 0h, 0h
	
	; set parameters
	mov eax, pe_addr
	movzx eax, word ptr IMAGE_NT_HEADERS32.FileHeader.Characteristics[eax]
	test eax, IMAGE_FILE_DLL
	jz @call_entry_point

	push 0h ; lpReserver	
	push 1 ; fdwReason
	push base_addr ; hModule
	jmp @call_entry_point

@run_as_exe:
	push 0h ; argv
	push 0h ; argc
	
@call_entry_point:
	mov eax, pe_addr
	mov eax, IMAGE_NT_HEADERS32.OptionalHeader.AddressOfEntryPoint[eax]	
	add eax, base_addr
	call eax

	mov eax, base_addr
@exit:
	ret
	
@fail:
	xor eax, eax
	jmp @exit
run_binary endp