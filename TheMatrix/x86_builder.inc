;
; Add the input binary to the resource directory
;	Args: <file to modify>,<file to embed>
;	Ret: TRUE on success, FALSE otherwise
;
add_resource proc file_to_add:ptr char , target_file:ptr char 
	local hRes:dword
	local file_size:dword
	local hFile:dword
	local ncount:dword
	local file_buffer:ptr byte	

	; get file to add size
	invoke CreateFileW, file_to_add, GENERIC_READ, 0h, 0h, OPEN_EXISTING, 0h, 0h
	cmp eax, ERROR_FILE_NOT_FOUND
	je @fail
	mov hFile, eax
	invoke GetFileSize, hFile, 0h
	cmp eax, INVALID_FILE_SIZE
	je @fail
	mov file_size, eax
	
	; load the content	
	invoke heap_alloc, eax
	test eax, eax
	jz @fail
	mov file_buffer, eax

	invoke ReadFile, hfile, file_buffer, file_size, addr ncount, 0h
	test eax, eax
	jz @fail	
	
	invoke CloseHandle, hFile

	; update the file
	invoke BeginUpdateResourceA, target_file, 0h
	test eax, eax
	jz @fail
	mov hRes, eax

	invoke UpdateResourceA, hRes, RT_VERSION, VS_VERSION_INFO, 0h, file_buffer, file_size
	test eax, eax
	jz @fail

	invoke EndUpdateResourceA, hRes, 0h
	test eax, eax
	jz @fail

	invoke heap_free, file_buffer
	mov eax, 1

@exit:
	ret

@fail:
	xor eax, eax
	jmp @exit
add_resource endp

;
; Clone the currently executing file
;	Args: None
;	Ret: The name of the cloned file
;
clone_file proc
	local orig_filename:ptr char
	local build_filename:ptr char

	; get my filename
	invoke heap_alloc, 512h
	test eax, eax
	jz @fail
	mov orig_filename, eax

	push 512h
	push orig_filename
	push 0h
	call GetModuleFileNameA

	cld

	; create the build filename
	invoke heap_alloc, 512h
	test eax, eax
	jz @fail
	mov build_filename, eax

	; compute name length
	mov edi, orig_filename
	mov ecx, 255h
	xor eax, eax
	repnz scasb
	sub edi, orig_filename
	mov ecx, edi
	
	; copy the filename
	mov esi, orig_filename
	mov edi, build_filename
@@:
	lodsb
	stosb
	loop @b

	; set .build.exe extension
	sub edi, 4h	
	mov dword ptr [edi], 'liub'
	mov dword ptr [edi + 4], 'xe.d'
	mov byte ptr [edi + 8], 'e'

	; copy the file
	push 0h
	push build_filename
	push orig_filename
	call CopyFileA
	test eax, eax
	jz @fail

	invoke heap_free, orig_filename	
	mov eax, build_filename

@exit:	
	ret

@fail:
	xor eax, eax
	jmp @exit

clone_file endp

;
; Create the artifact containing the input binary in the embedded resource
;	Args: <file path>
;	Ret: TRUE on success. False otherwise
;
create_artifact proc file_to_add:ptr char
	local cloned_filename:ptr char

	; clone my file 
	invoke clone_file
	test eax, eax
	jz @fail
	mov cloned_filename, eax

	; create the file with the embedded resource
	invoke add_resource, file_to_add, eax
	test eax, eax
	jz @fail

	invoke heap_free, cloned_filename
	mov eax, 1

@exit:
	ret

@fail:
	xor eax, eax
	jmp @exit
create_artifact endp