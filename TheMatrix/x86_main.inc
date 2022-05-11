.686
.model flat, stdcall
.stack 4096
.xmm

.data

; 
; this function is called to place all the function hooks
;
extern C hooks_init:proc

.code

include const.inc
include api.inc
include x86_def.inc
include x86_utility.inc
include x86_pe.inc
include x86_builder.inc
include x86_console.inc
include x86_run.inc
include x86_hook_engine.inc

includelib libucrt.lib
includelib legacy_stdio_definitions.lib

;
; parse the command line
;
parse_args proc
	enter 0, 0

	; get the array
	call GetCommandLineW
	push dword ptr [ebp+arg0]
	push eax
	call CommandLineToArgvW	

	leave
	ret
parse_args endp

;
; check if the user specified the -add option. If so return the arg index
;
is_add_command proc
	enter 0,0
	; do we have an "-add" argument
	xor ebx, ebx
	xor eax, eax
	mov edx, dword ptr [ebp+arg0]	
	mov ecx, dword ptr [ebp+arg1]
	movsd xmm1, qword ptr [g_string_add_opt]

@check_arg:		
	lea eax, dword ptr [edx + ebx * sizeof dword]		
	inc ebx	
	mov eax, dword ptr [eax]	
	vmovups xmm0, xmmword ptr [eax]
	pcmpeqd xmm0, xmm1	
	ptest xmm0, xmm0
	jnz @option_set	
	loop @check_arg
	mov eax, 0ffffffffh

@exit:
	leave
	ret

@option_set:
	mov eax, ebx
	jmp @exit
is_add_command endp

DllRegisterServer proc C export
	r_ebx equ local0
	r_esi equ local1
	r_edi equ local2

	push ebp
	mov ebp, esp
	sub esp, sizeof dword * 3

	mov dword ptr [ebp+r_ebx], ebx
	mov dword ptr [ebp+r_esi], esi
	mov dword ptr [ebp+r_edi], edi

	cmp g_base_address, 0h
	jz @fail

	invoke pe_resolve_exported_function, g_base_address
	test eax, eax
	jz @fail

	; call the exported function
	call eax

	mov eax, 1h
@exit:	
	mov ebx, dword ptr [ebp+r_ebx]
	mov esi, dword ptr [ebp+r_esi]
	mov edi, dword ptr [ebp+r_edi]

	leave
	ret

@fail:
	xor eax, eax
	jmp @exit
DllRegisterServer endp

run_as_dll proc fdwReason:dword
	cmp fdwReason, DLL_PROCESS_ATTACH
	jne @exit

	call run_binary	
	test eax, eax
	jz @exit

	; save the value for exported method call
	mov g_base_address, eax
		
@exit:	
	mov eax, 1h
	ret
run_as_dll endp

run_as_executable proc
	argc equ local0
	argv equ local1	

	lea ebx, dword ptr [ebp+argc]
	push ebx
	call parse_args

	; check if we have at least 3 args, otherwise run the embedded binary
	mov ebx, dword ptr [ebp+argc]
	cmp ebx, 3h
	jb @run_resource_binary
	mov dword ptr [ebp+argv], eax

	; it was specified the -add option?
	push dword ptr [ebp+argc]
	push dword ptr [ebp+argv]
	call is_add_command
	mov ecx, eax

	test eax, eax
	jz @run_resource_binary

	mov eax, dword ptr [ebp+argv]
	mov eax, dword ptr [eax + ecx * sizeof dword]
	invoke create_artifact, eax
	test eax, eax
	jz @fail

	push offset g_string_file_create
	call print_line	
	jmp @exit

@run_resource_binary:
	call run_binary	
	test eax, eax
	jnz @exit

	push offset g_string_load_error
	call print_line
	mov eax, 1

@exit:	
	leave
	ret

@fail:
	mov eax, 1
	jmp @exit
run_as_executable endp

main proc	
	r_ebx equ local0
	r_esi equ local1
	r_edi equ local2
	
	push ebp
	mov ebp, esp
	sub esp, sizeof dword * 3

	mov dword ptr [ebp+r_ebx], ebx
	mov dword ptr [ebp+r_esi], esi
	mov dword ptr [ebp+r_edi], edi

	; check if the program is executed as a DLL
	; this is an heuristics and is based on the input parameters
	call get_module_base
	mov esi, eax
	mov eax, dword ptr [ebp+arg0]
	cmp eax, esi ; hModule != module base ~> is an EXE
	jne @run_as_executable

	mov eax, dword ptr [ebp+arg2]
	cmp eax, 0h ; lpReserver == 0
	jne @run_as_executable

	invoke run_as_dll, dword ptr [ebp+arg1]
	jmp @exit

@run_as_executable:
	call run_as_executable

@exit:	
	mov ebx, dword ptr [ebp+r_ebx]
	mov esi, dword ptr [ebp+r_esi]
	mov edi, dword ptr [ebp+r_edi]

	leave	
	ret

@fail:	
	mov eax, 2
	jmp @exit
main endp