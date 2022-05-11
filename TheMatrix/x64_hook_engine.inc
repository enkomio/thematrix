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

hook_call_original proc
	ret
hook_call_original endp

