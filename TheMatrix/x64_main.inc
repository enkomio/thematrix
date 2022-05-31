
.data

;
; The mapped PE base address
;
g_base_address qword 0h

.code

; 
; This function is used to place the function hooks
;
extern hooks_init:proc

include ksamd64.inc
include const.inc
include api.inc
include x64_def.inc
include x64_memory.inc
include x64_utility.inc
include x64_run.inc
include x64_pe.inc
include x64_builder.inc
include x64_hook_engine.inc
include x64_console.inc

;
; Parse the command line
;	Args: <*argc>
;	Ret: <string array>
;
parse_command_line proc frame
	_CreateFrame pcl_
	_EndProlog
	_AllocHomeArea
	mov qword ptr pcl_OffsetHomeRCX[rbp], rcx

	; get the array
	call GetCommandLineW
	mov rdx, qword ptr pcl_OffsetHomeRCX[rbp]
	mov rcx, rax	
	call CommandLineToArgvW	
	
	_DeleteFrame
	ret
parse_command_line endp

;
; Check if the user specified the -add option. If so, it returns the arg index
;	Args: <argc>, <argv>
;	Ret: TRUE on success, -1 otherwise
;
has_add_command proc frame
	_CreateFrame add_,LOCALS_SIZE
	_EndProlog
	mov qword ptr add_OffsetHomeRCX[rbp], rcx
	mov qword ptr add_OffsetHomeRDX[rbp], rdx

	movsd xmm1, qword ptr [g_string_add_opt]
	xor r10, r10

@check_arg:		
	lea rax, qword ptr [rdx + r10 * sizeof qword]
	inc r10	
	mov rax, qword ptr [rax] ; read i-th arg

	; do comparison
	vmovups xmm0, xmmword ptr [rax]
	pcmpeqd xmm0, xmm1	
	ptest xmm0, xmm0
	jnz @option_set	
	loop @check_arg
	xor rax, rax
	dec rax

@exit:
	_DeleteFrame
	ret

@option_set:
	mov rax, r10
	jmp @exit	
has_add_command endp

DllRegisterServer proc export frame
	_CreateFrame dllreg_,LOCALS_SIZE
	_EndProlog
	_AllocHomeArea

	cmp g_base_address, 0h
	jz @fail

	; resolve the function address of the mapped binary
	mov rcx, g_base_address
	mov rdx, offset g_string_DllRegisterServer	
	call pe_resolve_exported_function
	test rax, rax
	jz @fail

	; call the exported function
	mov eax, dword ptr [rax]
	add rax, g_base_address
	call rax

 @exit:
	_DeleteFrame
	ret

@fail:
	xor rax, rax
	jmp @exit
DllRegisterServer endp

;
; Run the embedded binary as a DLL. This is useful when the binary is invoked with 
;	Args: <hinstDLL> <fdwReason> <lpReserved>
;
run_as_dll proc frame
	_CreateFrame rdll_,LOCALS_SIZE
	_EndProlog
	_AllocHomeArea

	cmp rdx, DLL_PROCESS_ATTACH
	jne @exit

	; this function will call the DLL entry-point
	call run_binary	
	test rax, rax
	jz @exit

	; save the value for exported method call
	mov g_base_address, rax

 @exit:
	_DeleteFrame
	mov rax, 1h
	ret
run_as_dll endp

;
; This function run the binary as an executable. 
;	Args: <argc> <argv>
;
run_as_executable proc frame
	_CreateFrame rexe_,LOCALS_SIZE
	_EndProlog
	_AllocHomeArea

	; parse command-line
	mov qword ptr LOCALS.Local1[rbp], 0
	lea rcx, qword ptr LOCALS.Local1[rbp]
	call parse_command_line
	mov qword ptr LOCALS.Local2[rbp], rax

	; check if we have at least 3 args, if not run the embedded binary
	cmp qword ptr LOCALS.Local1[rbp], 3h
	jb @run_resource_binary

	; it was specified the -add option?
	mov rcx, qword ptr LOCALS.Local1[rbp]
	mov rdx, rax
	call has_add_command
	test rax, rax
	jb @run_resource_binary

	; create the artifact to run the embedded binary
	mov rcx, qword ptr LOCALS.Local2[rbp]
	mov rcx, qword ptr [rcx + rax * sizeof qword]
	mov qword ptr LOCALS.Local3[rbp], rcx
	call get_module_base
	mov rdx, DllMain
	sub rdx, rax
	mov rcx, qword ptr LOCALS.Local3[rbp]
	call create_artifact
	test rax, rax
	jz @fail

	; print ok
	mov rcx, offset g_string_file_create
	call print_line	
	jmp @exit
 
 @run_resource_binary:
	call run_binary

 @exit:
	_DeleteFrame
	ret

@fail:
	xor rax, rax
	jmp @exit
run_as_executable endp

main proc frame
	_CreateFrame m_
	_EndProlog
	_AllocHomeArea

	; save args to home area
	mov qword ptr m_OffsetHomeRCX[rbp], rcx
	mov qword ptr m_OffsetHomeRDX[rbp], rdx
	mov qword ptr m_OffsetHomeR8[rbp], r8
	mov qword ptr m_OffsetHomeR9[rbp], r9

	; get the module base to compare it with the input parameter
	call get_module_base

	; if it is called as a DLL the first parameter is the module base
	cmp rax, qword ptr m_OffsetHomeRCX[rbp]
	jne @run_as_executable
		
	cmp qword ptr m_OffsetHomeR8[rbp], 0h ; lpReserver == 0
	jne @run_as_executable
		
	mov rcx, qword ptr m_OffsetHomeRCX[rbp] ; hinstDLL
	mov rdx, qword ptr m_OffsetHomeRDX[rbp] ; fdwReason
	mov r8, qword ptr m_OffsetHomeR8[rbp] ; lpReserved 
	call run_as_dll
	jmp @exit
	 
@run_as_executable:
	; the program is executed as an executable
	mov rcx, qword ptr m_OffsetHomeRCX[rbp] ; argc
	mov rdx, qword ptr m_OffsetHomeRDX[rbp] ; argv
	call run_as_executable

@exit:
	_DeleteFrame
	ret
main endp

DllMain proc frame
	_CreateFrame dllm_
	_EndProlog
	_AllocHomeArea
	call main
	_DeleteFrame
	ret
DllMain endp