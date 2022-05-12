comment !
-=[ The Matrix ]=-

This application provide a mechanism to hook Win32 API for tracing purpose.

2022 (C) Antonio 's4tan' Parata
!

VERSION equ 1.0

IFDEF rax
	end_program textequ <end>

; 
; this function places all the function hooks
;
extern hooks_init:proc

.code

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
; parse the command line
;	Args: <*argc>
;	Ret: <string array>
;
parse_command_line proc frame
	_CreateFrame pcl_
	_EndProlog

	mov qword ptr pcl_OffsetHomeRCX[rbp], rcx

	_AllocHomeArea

	; get the array
	call GetCommandLineW
	mov rdx, qword ptr pcl_OffsetHomeRCX[rbp]
	mov rcx, rax	
	call CommandLineToArgvW	
	
	_DeleteFrame
	ret
parse_command_line endp

;
; check if the user specified the -add option. If so return the arg index
;	Args: <argc>, <argv>
;	Ret: TRUE on success, FALSE otherwise
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


;
; Run the embedded binary
;	Args: The arguments might vary according to how the binary is invoked (.DLL or .EXE)
;	Ret: TRUE on success, FALSE otherwise
;
run_binary proc frame
	_CreateFrame rb_,LOCALS_SIZE
	_EndProlog
	_AllocHomeArea

	mov qword ptr hset_OffsetHomeRCX[rbp], rcx
	mov qword ptr hset_OffsetHomeRDX[rbp], rdx
	mov qword ptr hset_OffsetHomeR8[rbp], r8
	mov qword ptr hset_OffsetHomeR9[rbp], r9

	; first load the embedded PE binary
	call load_embedded_binary
	test rax, rax
	jz @fail
	mov qword ptr LOCALS.Local1[rbp], rax

	; hook functions. This must be done before the embedded binary is loaded,
	; since in x64 we use EAT hooking. If not done in this way, the resolved
	; functions will have the real values in the IAT and not the hooked ones.
	mov rcx, qword ptr LOCALS.Local2[rbp]
	call hooks_init
	test rax, rax
	jz @fail

	; load the PE in memory
	mov rcx, qword ptr LOCALS.Local1[rbp]
	call pe_load
	test rax, rax
	jz @fail
	mov qword ptr LOCALS.Local2[rbp], rax

	; cleanup
	mov r8, MEM_DECOMMIT
	xor rdx, rdx
	mov rcx, qword ptr LOCALS.Local1[rbp]
	call VirtualFree
	test rax, rax
	jz @fail	

	; flush instructions
	xor r8, r8
	xor rdx, rdx
	mov rcx, -1
	call FlushInstructionCache

	; restore arguments
	mov rcx, qword ptr hset_OffsetHomeRCX[rbp]
	mov rdx, qword ptr hset_OffsetHomeRDX[rbp]
	mov r8, qword ptr hset_OffsetHomeR8[rbp]
	mov r9, qword ptr hset_OffsetHomeR9[rbp]

	; call OEP
	mov r10, qword ptr LOCALS.Local2[rbp]
	mov eax, IMAGE_DOS_HEADER.e_lfanew[r10]
	add rax, r10
	mov eax, IMAGE_NT_HEADERS64.OptionalHeader.AddressOfEntryPoint[rax]	
	add rax, r10
	call rax

@exit:
	_DeleteFrame
	ret

@fail:
	xor rax, rax
	jmp @exit
run_binary endp

;
; This function run the binary as an executable. 
;	Args: None
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

	; TODO: support -dll command to create a .build.dll file. The created artifact must be a DLL not just a renaming

	; it was specified the -add option?
	mov rcx, qword ptr LOCALS.Local1[rbp]
	mov rdx, rax
	call has_add_command
	test rax, rax
	jb @run_resource_binary

	; create the artifact to run the embedded binary
	mov rcx, qword ptr LOCALS.Local2[rbp]
	mov rcx, qword ptr [rcx + rax * sizeof qword]
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

	; save args to home area
	mov qword ptr m_OffsetHomeRCX[rbp], rcx
	mov qword ptr m_OffsetHomeRDX[rbp], rdx

	; needed to save input args when another function must be called
	_AllocHomeArea

	; get the module base to compare it with the input parameter
	call get_module_base

	; if it is called as a DLL the first parameter is the module base
	cmp rax, qword ptr m_OffsetHomeRCX[rbp]
	jne @run_as_executable
	 
@run_as_executable:
	; the program is executed as an executable
	mov rcx, qword ptr m_OffsetHomeRCX[rbp] ; argc
	mov rdx, qword ptr m_OffsetHomeRDX[rbp] ; argv
	call run_as_executable

@exit:
	_DeleteFrame
	ret
main endp

ELSE
	end_program textequ <end main>
	include x86_main.inc
ENDIF

end_program