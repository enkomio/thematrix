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
; This funcion uses EAT hooking.
; See https://devblogs.microsoft.com/oldnewthing/20110921-00/?p=9583
;	Args: <lib_name:ptr char> <func_name:ptr char> <hook:ptr HOOK_DEF>
;	Ret: TRUE on success, FALSE otherwise
;
hook_set proc frame	
	hset_pe_va EQU LOCALS.Local1
	_CreateFrame hset_,LOCALS_SIZE
	_EndProlog
	_AllocHomeArea
	mov qword ptr hset_OffsetHomeRCX[rbp], rcx

	; resolve the DLL
	call LoadLibraryA
	test rax, rax
	jz @fail

	; go to PE
	mov ecx, IMAGE_DOS_HEADER.e_lfanew[rax]
	add rax, rcx
	mov qword ptr hset_pe_va[rbp], rax

	; TODO: resolve exported function and place hook

@exit:
	_DeleteFrame
	ret

@fail:
	xor rax, rax
	jmp @exit
hook_set endp

;
; Place an hook to the specified function
;	Args: <lib_name:ptr char> <func_name:ptr char> <hook function addr>
;	Ret: ptr HOOK_DEF on success, FALSE otherwise
;
hook_add proc frame
	hadd_hook_def EQU LOCALS.Local1
	_CreateFrame hadd_,LOCALS_SIZE
	_EndProlog
	_AllocHomeArea

	mov qword ptr hadd_OffsetHomeRCX[rbp], rcx
	mov qword ptr hadd_OffsetHomeRDX[rbp], rdx
	mov qword ptr hadd_OffsetHomeR8[rbp], r8

	; allocate HOOK_DEF object
	mov rcx, sizeof HOOK_DEF
	call heap_alloc
	test rax, rax
	jz @fail
	mov qword ptr hadd_hook_def[rbp], rax

	; set hook function address
	mov r10, qword ptr hadd_OffsetHomeR8[rbp]
	mov HOOK_DEF.hook_func[rax], r10

	; set hook lib name
	mov rcx, qword ptr hadd_OffsetHomeRCX[rbp]
	call string_clone
	test rax, rax
	jz @fail
	mov r10, qword ptr hadd_hook_def[rbp]
	mov HOOK_DEF.lib_name[r10], rax

	; set hook func name
	mov rcx, qword ptr hadd_OffsetHomeRDX[rbp]
	call string_clone
	test rax, rax
	jz @fail
	mov r10, qword ptr hadd_hook_def[rbp]
	mov HOOK_DEF.func_name[r10], rax

	; now I can place the hook
	mov r8, qword ptr hadd_hook_def[rbp]
	mov rdx, qword ptr hadd_OffsetHomeRDX[rbp]
	mov rcx, qword ptr hadd_OffsetHomeRCX[rbp]
	call hook_set

@exit:
	_DeleteFrame
	ret

@fail:
	xor rax, rax
	jmp @exit
hook_add endp



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
;	Args: None
;	Ret: TRUE on success, FALSE otherwise
;
run_binary proc frame
	_CreateFrame rb_,LOCALS_SIZE
	_EndProlog
	_AllocHomeArea

	; first load the embedded PE binary
	call load_embedded_binary
	test rax, rax
	jz @fail
	mov qword ptr LOCALS.Local1[rbp], rax

	; load the PE in memory
	mov rcx, rax
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

	; hook functions
	mov rcx, qword ptr LOCALS.Local2[rbp]
	call hooks_init
	test rax, rax
	jz @fail

	; flush instructions
	xor r8, r8
	xor rdx, rdx
	mov rcx, -1
	call FlushInstructionCache


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