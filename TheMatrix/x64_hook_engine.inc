HOOK_DEF struct
	func_name		qword ?
	lib_name		qword ?
	log_dir			qword ?
	orig_func		qword ?
	hook_func		qword ?
	trampoline		qword ?	
	trampoline_size	qword ?
	hook_counter	qword ?
	saved_reg1		qword ?
	saved_reg2		qword ?
	saved_reg3		qword ?
	saved_reg4		qword ?
HOOK_DEF ends

;
; This funcion uses the MS hot-patching method.
; See https://devblogs.microsoft.com/oldnewthing/20110921-00/?p=9583
;	Args: <lib_name:ptr char> <func_name:ptr char> <hook:ptr HOOK_DEF>
;	Ret: TRUE on success, FALSE otherwise
;
hook_set proc frame
	_CreateFrame pb_,LOCALS_SIZE
	_EndProlog

	mov qword ptr pb_OffsetHomeRCX[rbp], rcx

@exit:
	_DeleteFrame
	ret

@fail:
	xor rax, rax
	jmp @exit
hook_set endp

hook_call_original proc
	ret
hook_call_original endp

hook_add proc
	ret
hook_add endp

hook_set_log_folder proc
	ret
hook_set_log_folder endp

hook_log_data proc
	ret
hook_log_data endp