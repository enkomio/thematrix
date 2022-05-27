;
; Add the input binary to the resource directory
;	Args: <file to modify>,<file to embed>
;	Ret: TRUE on success, FALSE otherwise
;
add_resource proc frame
	ar_hFile EQU LOCALS.Local1
	ar_file_size EQU LOCALS.Local2
	ar_buffer EQU LOCALS.Local3
	ar_hRes EQU LOCALS.Local4

	_CreateFrame ar_,LOCALS_SIZE,0,rdi
	_EndProlog	

	mov qword ptr ar_OffsetHomeRCX[rbp], rcx
	mov qword ptr ar_OffsetHomeRDX[rbp], rdx

	; get the size of the file to embed
	push 0h
	push 0h
	push OPEN_EXISTING
	xor r9, r9
	xor r8, r8
	mov rdx, GENERIC_READ
	mov rcx, qword ptr ar_OffsetHomeRDX[rbp]

	_AllocHomeArea
	call CreateFileW
	test rax, rax
	jz @fail
	mov qword ptr ar_hFile[rbp], rax

	xor rdx, rdx
	mov rcx, qword ptr ar_hFile[rbp]
	call GetFileSize
	cmp rax, INVALID_FILE_SIZE
	je @fail
	mov qword ptr ar_file_size[rbp], rax

	; allocate space for the file content
	call GetProcessHeap
	mov rcx, rax
	mov rdx, HEAP_ZERO_MEMORY
	mov r8, qword ptr ar_file_size[rbp]
	call HeapAlloc
	test rax, rax
	jz @fail
	mov qword ptr ar_buffer[rbp], rax

	; read the file content
	push 0
	lea r9, qword ptr LOCALS.Local4[rbp]
	mov r8, qword ptr ar_file_size[rbp]
	mov rdx, qword ptr ar_buffer[rbp]
	mov rcx, qword ptr ar_hFile[rbp]
	; this is a waste of space since I can recover part of 
	; the memory reserved from the previous call, but it is
	; annoying and error prone.
	_AllocHomeArea
	call ReadFile
	test rax, rax
	jz @fail

	; close handle to file
	mov rcx, qword ptr ar_hFile[rbp]
	call CloseHandle

	; now I can add the binary to the resource
	xor rdx, rdx
	mov rcx, qword ptr ar_OffsetHomeRCX[rbp]
	call BeginUpdateResourceA
	test rax, rax
	jz @fail
	mov qword ptr ar_hRes[rbp], rax

	push qword ptr ar_file_size[rbp]
	push qword ptr ar_buffer[rbp]
	xor r9, r9
	mov r8, VS_VERSION_INFO
	mov rdx, RT_VERSION
	mov rcx, qword ptr ar_hRes[rbp]
	_AllocHomeArea
	call UpdateResourceA
	test rax, rax
	jz @fail

	xor rdx, rdx
	mov rcx, qword ptr ar_hRes[rbp]
	call EndUpdateResourceA
	test rax, rax
	jz @fail

	; free resources
	call GetProcessHeap
	mov r8, qword ptr ar_buffer[rbp]
	xor rdx, rdx
	mov rcx, rax
	call HeapFree

	mov rax, 1

@exit:
	_DeleteFrame rdi
	ret

@fail:
	xor rax, rax
	jmp @exit
add_resource endp

;
; Clone the currently executing file considering the extension of the file to embed
;	Args: <file path>
;	Ret: The name of the cloned file
; 
clone_file proc frame
	_CreateFrame cf_,LOCALS_SIZE,0,rdi,rsi,rbx
	_EndProlog
	_AllocHomeArea

	mov qword ptr cf_OffsetHomeRCX[rbp], rcx
	mov qword ptr cf_OffsetHomeRDX[rbp], rdx
	mov qword ptr cf_OffsetHomeR8[rbp], r8

	; check if the file to embed is a dll
	mov rax, 06c006c0064002e00h
	mov rdi, rcx
	mov rcx, 255h
@@:
	cmp qword ptr [rdi], rax
	je @f
	inc rdi
	loop @b
@@:
	
	test rcx, rcx
	mov edi, 'lld.'
	mov ecx, 'exe.'
	cmovnz ecx, edi
	mov qword ptr LOCALS.Local3[rbp], rcx

	; alloc memory for original file name
	mov rcx, 512h
	call heap_alloc
	test rax, rax
	jz @fail
	mov qword ptr LOCALS.Local1[rbp], rax

	; alloc memory for the clone file name
	mov rcx, 512h
	call heap_alloc
	test rax, rax
	jz @fail
	mov qword ptr LOCALS.Local2[rbp], rax

	; get executable file name (original file name)
	mov r8, 512h
	mov rdx, qword ptr LOCALS.Local1[rbp]
	xor rcx, rcx
	call GetModuleFileNameA
	test rax, rax
	jz @fail

	; get executable file name (cloned file name)
	mov r8, 512h
	mov rdx, qword ptr LOCALS.Local2[rbp]
	xor rcx, rcx
	call GetModuleFileNameA
	test rax, rax
	jz @fail

	; change the extension from '.<EXT>' to '.build.<EXT>' (I suppose it has 3 chars extension).
	cld
	mov rdi, qword ptr LOCALS.Local2[rbp]
	xor rax, rax
	mov rcx, 512h
	repnz scasb
	sub rdi, 4
	mov qword ptr [rdi], 'liub'
	add rdi, 4
	mov byte ptr [rdi], 'd'
	inc rdi
	mov rax, qword ptr LOCALS.Local3[rbp]
	mov dword ptr [rdi], eax

	; now I can copy the file
	xor r8, r8
	mov rdx, qword ptr LOCALS.Local2[rbp]
	mov rcx, qword ptr LOCALS.Local1[rbp]
	call CopyFileA
	test rax, rax
	jz @fail

	; clean-up memory
	mov rcx, qword ptr LOCALS.Local1[rbp]
	call heap_free

	; if the file to embed is a DLL I have to change the File Header Characteristics
	cmp dword ptr LOCALS.Local3[rbp], 'lld.'
	jne @f

	; read the file content
	push 0h
	push 0h
	push OPEN_EXISTING
	xor r9, r9
	xor r8, r8
	mov rdx, GENERIC_READ_WRITE
	mov rcx, qword ptr LOCALS.Local2[rbp]
	_AllocHomeArea
	call CreateFileA
	test rax, rax
	jz @fail
	mov rsi, rax ; save handle

	xor rdx, rdx
	mov rcx, rsi
	call GetFileSize
	cmp rax, INVALID_FILE_SIZE
	je @fail
	mov rbx, rax ; save file size

	; allocate space for the file content
	call GetProcessHeap
	mov rcx, rax
	mov rdx, HEAP_ZERO_MEMORY
	mov r8, rbx
	call HeapAlloc
	test rax, rax
	jz @fail
	mov rdi, rax ; save buffer ptr

	; read the file content
	push 0
	lea r9, qword ptr LOCALS.Local4[rbp]
	mov r8, rbx
	mov rdx, rdi
	mov rcx, rsi
	_AllocHomeArea
	call ReadFile
	test rax, rax
	jz @fail	

	; go to PE
	mov eax, IMAGE_DOS_HEADER.e_lfanew[rdi]
	add rax, rdi

	; update the Characteristics
	mov cx, word ptr IMAGE_NT_HEADERS64.FileHeader.Characteristics[rax]
	or cx, IMAGE_FILE_DLL
	mov word ptr IMAGE_NT_HEADERS64.FileHeader.Characteristics[rax], cx

	; go to the start of the file
	mov rcx, rsi
	xor rdx, rdx
	xor r8, r8
	mov r9, FILE_BEGIN
	call SetFilePointer
	cmp rax, INVALID_SET_FILE_POINTER
	je @fail

	; write back the result
	mov rcx, rsi
	mov rdx, rdi
	mov r8, rbx
	lea r9, qword ptr LOCALS.Local4[rbp]
	push 0h
	_AllocHomeArea
	call WriteFile
	test rax, rax
	jz @fail	

	; close handle to file
	mov rcx, rsi
	call CloseHandle
@@:


	; return the name of the cloned file
	mov rax, qword ptr LOCALS.Local2[rbp]

@exit:
	_DeleteFrame rdi,rsi,rbx
	ret

@fail:
	xor rax, rax
	jmp @exit
clone_file endp

;
; Create the artifact containing the input binary in the embedded resource
;	Args: <file path>
;	Ret: TRUE on success. False otherwise
;
create_artifact proc frame
	_CreateFrame ca_,LOCALS_SIZE
	_EndProlog
	_AllocHomeArea

	mov qword ptr ca_OffsetHomeRCX[rbp], rcx

	; clone the executable to add the embedded file
	call clone_file
	test rax, rax
	jz @fail
	mov qword ptr LOCALS.Local1[rbp], rax

	; add the file to the resource
	mov rdx, qword ptr ca_OffsetHomeRCX[rbp]
	mov rcx, rax
	call add_resource
	test rax, rax
	jz @fail

	; free resources
	call GetProcessHeap
	mov rcx, qword ptr LOCALS.Local1[rbp]
	call heap_free

	mov rax, 1

@exit:
	_DeleteFrame
	ret

@fail:
	;xor eax, eax
	jmp @exit
create_artifact endp