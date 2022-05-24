.686
.model flat, stdcall
.stack 4096
.xmm

.data

;
; The mapped PE base address
;
g_base_address dword 0h

.code

; 
; This function is used to place the function hooks
;
extern C hooks_init:proc

include const.inc
include api.inc
include x86_def.inc
include x86_memory.inc
include x86_utility.inc
include x86_pe.inc
include x86_builder.inc
include x86_console.inc
include x86_run.inc
include x86_hook_engine.inc

includelib libucrt.lib
includelib legacy_stdio_definitions.lib

;
; Parse the command line
;	Args: <*argc>
;	Ret: <string array>
;
parse_command_line proc
	enter 0, 0

	; get the array
	call GetCommandLineW
	push dword ptr [ebp+arg0]
	push eax
	call CommandLineToArgvW	

	leave
	ret
parse_command_line endp

;
; Check if the user specified the -add option. If so, it returns the arg index
;	Args: <argc>, <argv>
;	Ret: TRUE on success, -1 otherwise
;
has_add_command proc argc:dword, argv:dword
	; do we have an "-add" argument
	xor ebx, ebx
	mov edx, argv
	mov ecx, argc
	movsd xmm1, qword ptr [g_string_add_opt]

@check_arg:		
	mov eax, dword ptr [edx + ebx * sizeof dword]		
	inc ebx	
	vmovups xmm0, xmmword ptr [eax]
	pcmpeqd xmm0, xmm1	
	ptest xmm0, xmm0
	jnz @option_set	
	loop @check_arg
	mov eax, 0ffffffffh

@exit:
	ret

@option_set:
	mov eax, ebx
	jmp @exit
has_add_command endp

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

	invoke pe_resolve_exported_function, g_base_address, offset g_string_DllRegisterServer
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

;
; Run the embedded binary as a DLL. This is useful when the binary is invoked with 
;	Args: <hinstDLL> <fdwReason> <lpReserved>
;
run_as_dll proc hinstDLL:dword, fdwReason:dword, lpReserved:dword
	cmp fdwReason, DLL_PROCESS_ATTACH
	jne @exit

	; this function will call the DLL entry-point
	push lpReserved
	push fdwReason
	push hinstDLL
	call run_binary	
	test eax, eax
	jz @exit

	; save the value for exported method call
	mov g_base_address, eax
		
@exit:	
	mov eax, 1h
	ret
run_as_dll endp

;
; This function run the binary as an executable. 
;	Args: <argc> <argv>
;
run_as_executable proc i_argc:dword, i_argv:dword
	argc equ local0
	argv equ local1	

	lea ebx, dword ptr [ebp+argc]
	push ebx
	call parse_command_line

	; check if we have at least 3 args, otherwise run the embedded binary
	mov ebx, dword ptr [ebp+argc]
	cmp ebx, 3h
	jb @run_resource_binary
	mov dword ptr [ebp+argv], eax

	; it was specified the -add option?
	invoke has_add_command, dword ptr [ebp+argc], dword ptr [ebp+argv]
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
	invoke run_binary, i_argc, i_argv, 0h
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

	; save non-volatile registers
	mov dword ptr [ebp+r_ebx], ebx
	mov dword ptr [ebp+r_esi], esi
	mov dword ptr [ebp+r_edi], edi

	; check if the program is executed as a DLL
	; this is an heuristics and is based on the input parameters
	call get_module_base
	cmp dword ptr [ebp+arg0], eax ; hModule != module base ~> is an EXE
	jne @run_as_executable

	; second heuristic: lpReserver == 0 ?
	cmp dword ptr [ebp+arg2], 0h
	jne @run_as_executable

	invoke run_as_dll, dword ptr [ebp+arg0], dword ptr [ebp+arg1], dword ptr [ebp+arg2]
	jmp @exit

@run_as_executable:
	invoke run_as_executable, dword ptr [ebp+arg0], dword ptr [ebp+arg1]

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