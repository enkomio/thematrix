comment !
-=[ The Matrix - A Process Tracer With Win32 APIs Interception ]=-

This application provide a mechanism to hook Win32 API for tracing purpose.

2022 (C) Antonio 's4tan' Parata

TODO: 
* When modifing PEB.Ldr, change the FullDllName and BaseDllName accordintg to the name of the .edata
!

VERSION equ 1.0

IFDEF rax
	end_program textequ <end>
	include x64_main.inc
ELSE
	end_program textequ <end main>
	include x86_main.inc
ENDIF

end_program