;
; For MSVC 2010:
;
; Emulate DecodePointer and EncodePointer functions, get rid of their imports
; and make program work on any OS including Windows 2000 and Windows XP without
; service packs.
;
; see https://stackoverflow.com/questions/2484511/can-i-use-visual-studio-2010s-c-compiler-with-visual-studio-2008s-c-runtim
;

	.model flat

	.code

dummy	proc
	mov	eax, [esp+4]
	ret	4
dummy	endp

	.data

__imp__EncodePointer@4	dd	dummy
__imp__DecodePointer@4	dd	dummy

	EXTERNDEF __imp__EncodePointer@4:DWORD
	EXTERNDEF __imp__DecodePointer@4:DWORD

	end
