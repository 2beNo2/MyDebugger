.386
.model flat, stdcall  ;32 bit memory model
option casemap :none  ;case sensitive

include MyDebug.inc
include msvcrt.inc
includelib msvcrt.lib

Decode2AsmOpcode       proto stdcall :dword, :dword, :dword, :dword, :dword

AddBreakPointNode        proto stdcall :dword, :dword, :dword
DelBreakPointNode         proto stdcall :dword, :dword
FindBreakPointNode        proto stdcall :dword, :dword
ShowBreakPointNode      proto stdcall :dword
GetAddressOfBreakPoint  proto stdcall :dword, :dword
GetCodeOfBreakPoint      proto stdcall :dword, :dword

AddHardWareBpNode        proto stdcall :dword, :dword
DelHardWareBpNode         proto stdcall :dword, :dword
ShowHardWareBpNode      proto stdcall :dword
GetAddressOfHardWareBp proto stdcall :dword, :dword

AddMemoryBpNode           proto stdcall :dword, :dword, :dword, :dword, :dword
DelMemoryBpNode            proto stdcall :dword, :dword
ShowMemoryBpNode         proto stdcall :dword
GetAddressOfMemoryBp     proto stdcall :dword, :dword
GetSizeOfMemoryBp           proto stdcall :dword, :dword
GetOldTypeOfMemoryBp    proto stdcall :dword, :dword
CheckMemoryBp                proto stdcall :dword, :dword
IsTheSamePage                  proto stdcall :dword, :dword
GetTypeOfMemoryBp         proto stdcall :dword, :dword



tagBPNODE struct
	AddressOfBreakPoint    LPVOID  ?
	CodeOfBreakPoint        DWORD ?
	SerialNumber               DWORD  ?
	LpNextNode                 LPVOID  ?
tagBPNODE ends

tagBHNODE struct
	AddressOfBreakPoint    LPVOID  ?
	SerialNumber               DWORD  ?
	LpNextNode                 LPVOID  ?
tagBHNODE ends

tagBMNODE struct
	SerialNumber                DWORD  ?
	AddressOfBreakPoint    LPVOID  ?	
	SizeOfMemory              DWORD  ?
	TypeOfBreakPoint         DWORD  ?
	OldTypeOfMemory       DWORD  ?
	LpNextNode                  LPVOID  ?
tagBMNODE ends

.data
	g_btExceptionInt3     db 0cch
		
	g_lpContext LPVOID   ?
	g_hProcess  HANDLE  NULL
	g_hThread   HANDLE  NULL
	g_lpPreMemoryAddr  LPVOID  NULL
	g_lpPreCodeAddr       LPVOID  NULL
	
	;入口断点
	g_lpEntryPoint           LPVOID ?
	g_btEntryPointCode  db ?
		
	;单步
	g_isDebugSingleStep    dd  FALSE
	g_isDebugSingleStep_P dd  FALSE
	g_isDebugSingleStep_T dd  FALSE
	g_isStepOverCall           dd  FALSE	
	g_lpStepOverCall          LPVOID  ?
	g_btStepOverCallCode  db ?
	
	;g命令
	g_isDebugGo             dd  FALSE
	g_lpGoBreakPoint      LPVOID  ?
	g_btGoCode               db ?
	
	;一般断点
	g_isDebugBreakPoint        dd  FALSE	
	g_isDebugBreakPointEX    dd  FALSE	
	g_lpDebugBreakPoint        LPVOID  ?
	g_BreakPointListHeaderNode  tagBPNODE <?, ?, ?, ?>
	
	;硬件断点
	g_isHardWareSingleStep        dd  FALSE	
	g_dwHardWareBpCount        dd 0
	g_HardWareBpListHeaderNode  tagBHNODE <?, ?, ?>
	g_dwDR7 dd 0
	g_lpDR0  LPVOID  NULL
	g_lpDR1  LPVOID  NULL
	g_lpDR2  LPVOID  NULL
	g_lpDR3  LPVOID  NULL
	
	;内存断点
	g_MemoryBpListHeaderNode  tagBMNODE <?, ?, ?, ?, ?>
	g_isMemorySingleStep            dd  FALSE	
	g_isMemorySingleStepEX        dd  FALSE	
	g_lpMemoryBpAddress           LPVOID  NULL
	
.const
	g_szFilePath db 'winmine.exe',0
	
	g_szErrorInputFormat db 'error input', 0dh, 0ah, 0
	g_szNewLine db 0dh, 0ah, 0
	g_szSpace db '     ', 0
.code


ShowMemory proc uses ecx ebx esi edi hProcess:HANDLE, pCodeAddr:LPVOID, lpContext:LPVOID
	LOCAL @szCodeBuff[128]:byte
	LOCAL @pCodeAddr:LPVOID
	LOCAL @szTmp[50]:byte
	LOCAL @szASCII[17]:byte
	LOCAL @btASCII:dword
	LOCAL @btCode:dword
		
	jmp NEXT
	g_szAddressFormat db '%p    ', 0
	g_szASCIIFormat db '%c ', 0
	g_szMemoryFormat db '%02x ', 0
		
NEXT:
	invoke RtlZeroMemory, addr @szCodeBuff, sizeof @szCodeBuff
	invoke RtlZeroMemory, addr @szTmp, sizeof @szTmp
	invoke RtlZeroMemory, addr @szASCII, sizeof @szASCII
		
	mov eax, pCodeAddr
	.if pCodeAddr == NULL
	
		.if	g_lpPreMemoryAddr == NULL
			mov esi, lpContext
			assume esi : ptr CONTEXT
			mov eax, [esi].regEip	
			mov g_lpPreMemoryAddr, eax
		.elseif
			mov ebx, g_lpPreMemoryAddr
			add ebx, 128
			mov eax, ebx
			mov g_lpPreMemoryAddr, ebx
		.endif
	.elseif
		mov g_lpPreMemoryAddr, eax
	.endif
	mov @pCodeAddr, eax
	
	invoke ReadProcessMemory, hProcess,  @pCodeAddr, addr @szCodeBuff, sizeof @szCodeBuff, NULL
	.if eax == FALSE
		jmp EXIT_PROC
	.endif
	
	lea esi, @szCodeBuff
	
	mov ecx, 8
	.while ecx > 0
		push ecx

		invoke wsprintf, addr @szTmp,  offset g_szAddressFormat, @pCodeAddr
		invoke crt_printf, addr @szTmp
		
		invoke crt_memcpy, addr @szASCII, esi, 16
		
		mov ecx, 16
		.while ecx > 0
			push ecx
			
			lea edi,  @szASCII
			add edi, 16
			sub edi, ecx
			
			movzx ebx, byte ptr [edi]
			mov @btCode, ebx
			invoke crt_printf, offset g_szMemoryFormat, @btCode
			
			pop ecx
			dec ecx
		.endw
		
		invoke crt_printf, offset g_szSpace
		
		mov ecx, 16
		.while ecx > 0
			push ecx
			
			lea edi,  @szASCII
			add edi, 16
			sub edi, ecx
			
			movzx ebx, byte ptr [edi]
			mov @btASCII, ebx
			invoke crt_printf, offset g_szASCIIFormat, @btASCII
			
			pop ecx
			dec ecx
		.endw
		
		mov eax,  @pCodeAddr
		add eax, 16
		mov @pCodeAddr, eax
		
		invoke crt_printf, offset g_szNewLine
		
		pop ecx
		dec ecx
		add esi, 16
	.endw
	
EXIT_PROC:
	
	ret
ShowMemory endp

ShowReg proc uses esi
	LOCAL @szTmp[500]:byte
	LOCAL @nCF:dword
	LOCAL @nPF:dword
	LOCAL @nAF:dword
	LOCAL @nZF:dword
	LOCAL @nSF:dword
	LOCAL @nTF:dword
	LOCAL @nIF:dword
	LOCAL @nDF:dword
	LOCAL @nOF:dword
	
	jmp NEXT
	g_szRegFormat db 'EAX=%08p  ECX=%08p  EDX=%08p  EBX=%08p', 0dh, 0ah, 
								'ESI=%08p  EDI=%08p  ESP=%08p  EBP=%08p', 0dh, 0ah, 
								'FS =%08p  CS =%08p  DS =%08p  ES =%08p  SS =%08p  EIP =%08p', 0dh, 0ah, 0
	g_szFlagRegFormat db 'CF =%d  PF =%d  AF =%d  ZF =%d  SF =%d  TF =%d  IF =%d  DF =%d   OF =%d', 0ah, 0dh, 0						
NEXT:	
	mov esi, g_lpContext
	assume esi : ptr CONTEXT
	
	mov eax, [esi].regFlag
	and eax, 1h
	mov @nCF, eax

	mov eax, [esi].regFlag
	and eax, 4h
	shr eax, 2
	mov @nPF, eax	 
	 
	mov eax, [esi].regFlag
	and eax, 10h
	shr eax, 4
	mov @nAF, eax
	
	mov eax, [esi].regFlag
	and eax, 40h
	shr eax, 6
	mov @nZF, eax
	
	mov eax, [esi].regFlag
	and eax, 80h
	shr eax, 7
	mov @nSF, eax
	
	mov eax, [esi].regFlag
	and eax, 100h
	shr eax, 8
	mov @nTF, eax
	
	mov eax, [esi].regFlag
	and eax, 200h
	shr eax, 9
	mov @nIF, eax
	
	mov eax, [esi].regFlag
	and eax, 400h
	shr eax, 10
	mov @nDF, eax
	
	mov eax, [esi].regFlag
	and eax, 800h
	shr eax, 11
	mov @nOF, eax	
	
	invoke wsprintf, addr @szTmp, offset g_szRegFormat, [esi].regEax, [esi].regEcx, [esi].regEdx, [esi].regEbx,
																					   [esi].regEsi, [esi].regEdi, [esi].regEsp, [esi].regEbp,
																					   [esi].regFs, [esi].regCs, [esi].regDs, [esi].regEs,[esi].regSs, [esi].regEip
	invoke crt_printf, addr @szTmp
	
	invoke wsprintf, addr @szTmp, offset g_szFlagRegFormat, @nCF, @nPF, @nAF, @nZF, @nSF, @nTF, @nIF, @nDF, @nOF													
	invoke crt_printf, addr @szTmp
	ret
ShowReg endp

ShowASM proc uses ecx ebx esi hProcess:HANDLE, pCodeAddr:LPVOID, dwAsmCodeLines:DWORD, lpContext:LPVOID
	LOCAL @szCodeBuff[50]:byte
	LOCAL @szAsmCode[200]:byte
	LOCAL @szOpcode[50]:byte
	LOCAL @nCodeSize:UINT
	LOCAL @szTmp[500]:byte
	LOCAL @pCodeAddr:LPVOID
	
	jmp NEXT
	g_szASMFormat db '%p   %-16s%s', 0dh, 0ah, 0
NEXT:
	mov ecx, dwAsmCodeLines
	
	.if pCodeAddr == NULL
		mov esi, lpContext
		assume esi : ptr CONTEXT
		mov eax, [esi].regEip
		mov @pCodeAddr, eax
	.elseif
		push pCodeAddr
		pop @pCodeAddr
	.endif

	.while ecx > 0
		push ecx
		invoke ReadProcessMemory, hProcess, @pCodeAddr, addr @szCodeBuff, sizeof @szCodeBuff, NULL
		.if eax == FALSE
			jmp EXIT_PROC
		.endif
		
		invoke Decode2AsmOpcode, addr @szCodeBuff, addr @szAsmCode, addr @szOpcode, addr @nCodeSize, @pCodeAddr
		invoke wsprintf, addr @szTmp, offset g_szASMFormat, @pCodeAddr, addr @szOpcode, addr @szAsmCode
		invoke crt_printf, addr @szTmp
		
		mov ebx, @pCodeAddr
		add ebx, @nCodeSize
		mov @pCodeAddr, ebx
		
		pop ecx
		dec ecx
	.endw
EXIT_PROC:
	ret
ShowASM endp

SetStepOverCallBP proc uses esi edi hProcess:HANDLE, pCodeAddr:LPVOID,  lpContext:LPVOID
	LOCAL @szCodeBuff[50]:byte
	LOCAL @szAsmCode[200]:byte
	LOCAL @szOpcode[50]:byte
	LOCAL @nCodeSize:UINT
	LOCAL @szTmp[5]:byte
	
	jmp NEXT
	g_szCall db 'call', 0
NEXT:

	invoke ReadProcessMemory, hProcess, pCodeAddr, addr @szCodeBuff, sizeof @szCodeBuff, NULL
	.if eax == FALSE
		jmp EXIT_PROC
	.endif
	
	invoke Decode2AsmOpcode, addr @szCodeBuff, addr @szAsmCode, addr @szOpcode, addr @nCodeSize, pCodeAddr
	
	invoke crt_memcpy, addr @szTmp, addr @szAsmCode, 4
	invoke crt_strcmp, addr @szTmp, offset g_szCall
	
	.if eax == 0
		mov esi, lpContext
		assume esi : ptr CONTEXT
		mov eax, pCodeAddr
		add eax, @nCodeSize	
		mov g_lpPreCodeAddr, eax
		
		;在Call指令的下一条下断点
		mov g_lpStepOverCall, eax
		invoke ReadProcessMemory, hProcess, g_lpStepOverCall, offset g_btStepOverCallCode, 1, NULL
		.if	eax == 0
			jmp EXIT_PROC
		.endif
		
		invoke WriteProcessMemory, hProcess, g_lpStepOverCall, offset g_btExceptionInt3, 1, NULL
		.if	eax == 0
			jmp EXIT_PROC
		.endif
		
		mov eax, 1
		ret
	.endif

EXIT_PROC:	
	mov eax, 0
	ret
SetStepOverCallBP endp

SetGoBP proc uses esi edi hProcess:HANDLE
	
	;在G的目标地址设置断点
	invoke ReadProcessMemory, hProcess, g_lpGoBreakPoint, offset g_btGoCode, 1, NULL
	.if	eax == 0
		jmp EXIT_PROC
	.endif
		
	invoke WriteProcessMemory, hProcess, g_lpGoBreakPoint, offset g_btExceptionInt3, 1, NULL
	.if	eax == 0
		jmp EXIT_PROC
	.endif
	
EXIT_PROC:
	ret
SetGoBP endp

SetUserBreakPoint proc uses esi edi hProcess:HANDLE, pCodeAddr:LPVOID,  lpContext:LPVOID
	LOCAL @szCodeBuff[2]:byte
	LOCAL @btCode:byte
	;读取目标地址数据
	invoke ReadProcessMemory, hProcess, pCodeAddr, addr @btCode, 1, NULL
	.if eax == FALSE
		jmp EXIT_PROC
	.endif
	
	invoke WriteProcessMemory, hProcess, pCodeAddr, offset g_btExceptionInt3, 1, NULL
	.if	eax == 0
		jmp EXIT_PROC
	.endif
	
	movzx eax, @btCode
	mov esi, eax
	
	invoke AddBreakPointNode,  offset g_BreakPointListHeaderNode,  pCodeAddr, esi
EXIT_PROC:	
	ret
SetUserBreakPoint endp

DelUserBreakPoint proc uses esi edi hProcess:HANDLE,  NumberOfBp:DWORD
	LOCAL @pCodeAddr:LPVOID
	LOCAL @dwCode:DWORD
	
	invoke GetAddressOfBreakPoint, offset g_BreakPointListHeaderNode, NumberOfBp
	.if eax == 0
		jmp EXIT_PROC
	.endif
	mov @pCodeAddr, eax
	
	invoke GetCodeOfBreakPoint, offset g_BreakPointListHeaderNode, NumberOfBp
	.if eax == 0
		jmp EXIT_PROC
	.endif
	mov @dwCode, eax
	
	invoke WriteProcessMemory, hProcess, @pCodeAddr, addr @dwCode, 1, NULL
	.if	eax == 0
		jmp EXIT_PROC
	.endif
	
	invoke DelBreakPointNode, offset g_BreakPointListHeaderNode, NumberOfBp
	.if	eax == 0
		jmp EXIT_PROC
	.endif
	
EXIT_PROC:		
	ret
DelUserBreakPoint endp

SetHardWareBreakPoint proc uses esi edi hProcess:HANDLE, pCodeAddr:LPVOID, szCommand:LPVOID, lpContext:LPVOID
	LOCAL dwBhLength:DWORD
	
	mov edi, lpContext
	assume edi : ptr CONTEXT	
	
	mov esi, szCommand
	add esi, 12
	movzx eax, byte ptr [esi]
	
	.if (ax == 'e') || (ax == 'E')
		;执行断点
		.if g_lpDR0 == NULL
			mov eax,  pCodeAddr
			mov [edi].iDr0, eax
			mov g_lpDR0, eax
			;0000 0000 0000 0011 00 0 001 11 00 00 00 01b
			or [edi].iDr7, 00000000000000000000011100000001b
			
		.elseif g_lpDR1 == NULL
			mov eax,  pCodeAddr
			mov [edi].iDr1, eax
			mov g_lpDR1, eax
			or [edi].iDr7, 00000000000000000000011100000100b
			
		.elseif g_lpDR2 == NULL
			mov eax,  pCodeAddr
			mov [edi].iDr2, eax
			mov g_lpDR2, eax
			or [edi].iDr7, 00000000000000000000011100010000b
			
		.elseif g_lpDR3 == NULL
			mov eax,  pCodeAddr
			mov [edi].iDr3, eax
			mov g_lpDR3, eax
			or [edi].iDr7, 00000000000000000000011101000000b
		.endif
		
	.elseif  (ax == 'a') || (ax == 'A')
		;访问断点
		movzx eax, byte ptr [esi + 2]
		.if ax == 31h
			.if g_lpDR0 == NULL
				mov eax,  pCodeAddr
				mov [edi].iDr0, eax
				mov g_lpDR0, eax
				;0000 0000 0000 0011 00 0 001 11 00 00 00 01b
				or [edi].iDr7, 00000000000000110000011100000001b
			.elseif g_lpDR1 == NULL
				mov eax,  pCodeAddr
				mov [edi].iDr1, eax
				mov g_lpDR1, eax
				or [edi].iDr7, 00000000001100000000011100000100b
			.elseif g_lpDR2 == NULL
				mov eax,  pCodeAddr
				mov [edi].iDr2, eax
				mov g_lpDR2, eax
				or [edi].iDr7, 00000011000000000000011100010000b
			.elseif g_lpDR3 == NULL
				mov eax,  pCodeAddr
				mov [edi].iDr3, eax
				mov g_lpDR3, eax
				or [edi].iDr7, 00110000000000000000011101000000b
			.endif
			
		.elseif  ax == 32h
			.if g_lpDR0 == NULL
				mov eax,  pCodeAddr
				mov [edi].iDr0, eax
				mov g_lpDR0, eax
				;0000 0000 0000 0011 00 0 001 11 00 00 00 01b
				or [edi].iDr7, 00000000000001110000011100000001b
			.elseif g_lpDR1 == NULL
				mov eax,  pCodeAddr
				mov [edi].iDr1, eax
				mov g_lpDR1, eax
				or [edi].iDr7, 00000000011100000000011100000100b
			.elseif g_lpDR2 == NULL
				mov eax,  pCodeAddr
				mov [edi].iDr2, eax
				mov g_lpDR2, eax
				or [edi].iDr7, 00000111000000000000011100010000b
			.elseif g_lpDR3 == NULL
				mov eax,  pCodeAddr
				mov [edi].iDr3, eax
				mov g_lpDR3, eax
				or [edi].iDr7, 01110000000000000000011101000000b
			.endif
			
		.elseif  ax == 34h
			.if g_lpDR0 == NULL
				mov eax,  pCodeAddr
				mov [edi].iDr0, eax
				mov g_lpDR0, eax
				;0000 0000 0000 0011 00 0 001 11 00 00 00 01b
				or [edi].iDr7, 00000000000011110000011100000001b
			.elseif g_lpDR1 == NULL
				mov eax,  pCodeAddr
				mov [edi].iDr1, eax
				mov g_lpDR1, eax
				or [edi].iDr7, 00000000111100000000011100000100b
			.elseif g_lpDR2 == NULL
				mov eax,  pCodeAddr
				mov [edi].iDr2, eax
				mov g_lpDR2, eax
				or [edi].iDr7, 00001111000000000000011100010000b
			.elseif g_lpDR3 == NULL
				mov eax,  pCodeAddr
				mov [edi].iDr3, eax
				mov g_lpDR3, eax
				or [edi].iDr7, 11110000000000000000011101000000b
			.endif
			
		.else
			jmp EXIT_PROC
		.endif
		
	.elseif  (ax == 'w') || (ax == 'W')
		;写入断点
		movzx eax, byte ptr [esi + 2]
		.if ax == 31h
			.if g_lpDR0 == NULL
				mov eax,  pCodeAddr
				mov [edi].iDr0, eax
				mov g_lpDR0, eax
				;0000 0000 0000 0011 00 0 001 11 00 00 00 01b
				or [edi].iDr7, 00000000000000010000011100000001b
			.elseif g_lpDR1 == NULL
				mov eax,  pCodeAddr
				mov [edi].iDr1, eax
				mov g_lpDR1, eax
				or [edi].iDr7, 00000000000100000000011100000100b
			.elseif g_lpDR2 == NULL
				mov eax,  pCodeAddr
				mov [edi].iDr2, eax
				mov g_lpDR2, eax
				or [edi].iDr7, 00000001000000000000011100010000b
			.elseif g_lpDR3 == NULL
				mov eax,  pCodeAddr
				mov [edi].iDr3, eax
				mov g_lpDR3, eax
				or [edi].iDr7, 00010000000000000000011101000000b
			.endif
			
		.elseif  ax == 32h
			.if g_lpDR0 == NULL
				mov eax,  pCodeAddr
				mov [edi].iDr0, eax
				mov g_lpDR0, eax
				;0000 0000 0000 0011 00 0 001 11 00 00 00 01b
				or [edi].iDr7, 00000000000001010000011100000001b
			.elseif g_lpDR1 == NULL
				mov eax,  pCodeAddr
				mov [edi].iDr1, eax
				mov g_lpDR1, eax
				or [edi].iDr7, 00000000010100000000011100000100b
			.elseif g_lpDR2 == NULL
				mov eax,  pCodeAddr
				mov [edi].iDr2, eax
				mov g_lpDR2, eax
				or [edi].iDr7, 00000101000000000000011100010000b
			.elseif g_lpDR3 == NULL
				mov eax,  pCodeAddr
				mov [edi].iDr3, eax
				mov g_lpDR3, eax
				or [edi].iDr7, 01010000000000000000011101000000b
			.endif
			
		.elseif  ax == 34h
			.if g_lpDR0 == NULL
				mov eax,  pCodeAddr
				mov [edi].iDr0, eax
				mov g_lpDR0, eax
				;0000 0000 0000 0011 00 0 001 11 00 00 00 01b
				or [edi].iDr7, 00000000000011010000011100000001b
			.elseif g_lpDR1 == NULL
				mov eax,  pCodeAddr
				mov [edi].iDr1, eax
				mov g_lpDR1, eax
				or [edi].iDr7, 00000000110100000000011100000100b
			.elseif g_lpDR2 == NULL
				mov eax,  pCodeAddr
				mov [edi].iDr2, eax
				mov g_lpDR2, eax
				or [edi].iDr7, 00001101000000000000011100010000b
			.elseif g_lpDR3 == NULL
				mov eax,  pCodeAddr
				mov [edi].iDr3, eax
				mov g_lpDR3, eax
				or [edi].iDr7, 11010000000000000000011101000000b
			.endif
			
		.else
			jmp EXIT_PROC
		.endif
	.endif
	
	invoke AddHardWareBpNode, offset g_HardWareBpListHeaderNode , pCodeAddr
	
	mov eax, g_dwHardWareBpCount
	inc eax
	mov g_dwHardWareBpCount, eax
	mov eax, TRUE
	ret
EXIT_PROC:
	mov eax, FALSE
	ret

SetHardWareBreakPoint endp

DelHardWareBreakPoint proc uses esi edi hProcess:HANDLE,  NumberOfBp:DWORD, lpContext:LPVOID
	LOCAL @pCodeAddr:LPVOID
	
	mov edi, lpContext
	assume edi : ptr CONTEXT	
	
	;删除硬件断点
	invoke GetAddressOfHardWareBp, offset g_HardWareBpListHeaderNode, NumberOfBp
	.if eax == 0
		jmp EXIT_PROC
	.endif
	mov @pCodeAddr, eax
	
	mov eax, @pCodeAddr
	.if eax == g_lpDR0
		and [edi].iDr7, 11111111111100001111111111111100b
		mov g_lpDR0, NULL
	.elseif eax == g_lpDR1
		and [edi].iDr7, 11111111000011111111111111110011b
		mov g_lpDR1, NULL
	.elseif eax == g_lpDR2
		and [edi].iDr7, 11110000111111111111111111001111b
		mov g_lpDR2, NULL
	.elseif eax == g_lpDR3
		and [edi].iDr7, 00001111111111111111111100111111b
		mov g_lpDR3, NULL
	.endif
	
	invoke DelHardWareBpNode, offset g_HardWareBpListHeaderNode, NumberOfBp
	
EXIT_PROC:		
	ret
DelHardWareBreakPoint endp

SetMemoryBreakPoint proc uses esi edi hProcess:HANDLE, pCodeAddr:LPVOID, szCommand:LPVOID, lpContext:LPVOID
	LOCAL @dwMemorySize:DWORD
	LOCAL @lpMemoryBuff:LPVOID
	LOCAL @szTmp[12]:byte
	LOCAL @dwLength:DWORD
	LOCAL @dwOldProtect:DWORD
	
	invoke RtlZeroMemory, addr @szTmp, sizeof @szTmp
	mov edi, lpContext
	assume edi : ptr CONTEXT	
	
	mov esi, szCommand
	add esi, 12   ;长度  类型
	
	mov @lpMemoryBuff, esi
	invoke crt_strlen, @lpMemoryBuff
	dec eax
	mov @dwLength, eax
	
	invoke crt_memcpy,  addr @szTmp,  @lpMemoryBuff,  @dwLength
	invoke crt_atoi, addr @szTmp
	.if	eax == 0
		jmp EXIT_PROC
	.endif
	mov @dwMemorySize, eax
	
	mov eax, pCodeAddr
	and eax, 0fffh
	add eax, @dwMemorySize
	.if eax > 1000h
		jmp EXIT_PROC
	.endif
	
	add esi, @dwLength
	movzx eax, byte ptr [esi]
	
	.if (ax == 'r') || (ax == 'R')    ;访问断点	
		invoke VirtualProtectEx, hProcess, pCodeAddr, @dwMemorySize,PAGE_NOACCESS, addr @dwOldProtect
		invoke AddMemoryBpNode, offset g_MemoryBpListHeaderNode, pCodeAddr, @dwMemorySize, PAGE_NOACCESS, @dwOldProtect
	.elseif (ax == 'w') || (ax == 'W')    ;写
		invoke VirtualProtectEx, hProcess, pCodeAddr, @dwMemorySize,PAGE_EXECUTE_READ, addr @dwOldProtect	
		invoke AddMemoryBpNode, offset g_MemoryBpListHeaderNode, pCodeAddr, @dwMemorySize, PAGE_EXECUTE_READ, @dwOldProtect
	.else		
		jmp EXIT_PROC
	.endif
	
	mov eax, TRUE
	ret
	
EXIT_PROC:
	mov eax, FALSE
	ret
SetMemoryBreakPoint endp

DelMemoryBreakPoint proc uses esi edi hProcess:HANDLE,  NumberOfBp:DWORD, lpContext:LPVOID
	LOCAL @dwOldType:DWORD
	LOCAL @dwOldSize:DWORD
	LOCAL @pCodeAddr:LPVOID
	LOCAL @dwTmp:DWORD
	
	;删除内存断点
	;将对应内存的属性设置回去
	invoke GetOldTypeOfMemoryBp, offset g_MemoryBpListHeaderNode, NumberOfBp
	.if eax == 0
		jmp EXIT_PROC
	.endif
	mov @dwOldType, eax
	
	invoke GetSizeOfMemoryBp, offset g_MemoryBpListHeaderNode, NumberOfBp
	.if eax == 0
		jmp EXIT_PROC
	.endif
	mov @dwOldSize, eax
	
	invoke GetAddressOfMemoryBp, offset g_MemoryBpListHeaderNode, NumberOfBp
	.if eax == 0
		jmp EXIT_PROC
	.endif
	mov @pCodeAddr, eax	
	
	invoke VirtualProtectEx, hProcess, @pCodeAddr, @dwOldSize,@dwOldType, addr @dwTmp	
	
	invoke DelMemoryBpNode, offset g_MemoryBpListHeaderNode, NumberOfBp
	
EXIT_PROC:	
	ret
DelMemoryBreakPoint endp

OnAccess proc uses ecx ebx esi edi hProcess:HANDLE, hThread:HANDLE, lpDebugEvent:LPVOID, lpContext:LPVOID
	LOCAL @dwContinueStatus:DWORD
	LOCAL @pExpCodeAddr:LPVOID
	LOCAL @pBpCodeAddr:LPVOID
	LOCAL @dwOldType:DWORD
	LOCAL @dwOldSize:DWORD
	LOCAL @dwNumOfBp:DWORD
	LOCAL @dwTmp:DWORD
	
	mov @dwContinueStatus, DBG_EXCEPTION_NOT_HANDLED
	
	mov esi, lpDebugEvent
	assume esi : ptr DEBUG_EVENT
	lea esi, [esi].u
	assume esi : ptr EXCEPTION_DEBUG_INFO 
	
	mov edi, lpContext
	assume edi : ptr CONTEXT	
	
	;判断发生异常的位置是否落在内存断点的范围
	mov eax, [esi].pExceptionRecord.ExceptionInformation[4]
	mov @pExpCodeAddr,  eax
	mov g_lpMemoryBpAddress, eax
	
	invoke IsTheSamePage, offset g_MemoryBpListHeaderNode, @pExpCodeAddr
	.if eax != -1
		;在同一个分页
		mov @dwNumOfBp, eax
		invoke GetOldTypeOfMemoryBp, offset g_MemoryBpListHeaderNode, @dwNumOfBp
		.if eax == 0
			jmp EXIT_PROC
		.endif
		mov @dwOldType, eax
		
		invoke GetSizeOfMemoryBp, offset g_MemoryBpListHeaderNode, @dwNumOfBp
		.if eax == 0
			jmp EXIT_PROC
		.endif
		mov @dwOldSize, eax
		
		invoke GetAddressOfMemoryBp, offset g_MemoryBpListHeaderNode, @dwNumOfBp
		.if eax == 0
			jmp EXIT_PROC
		.endif
		mov @pBpCodeAddr, eax	
		
		mov eax, [esi].pExceptionRecord.ExceptionInformation[0]
		.if (eax != 1) && (eax != 0) 
			;断点类型不一致
			jmp EXIT_PROC
		.endif
		
		invoke CheckMemoryBp, offset g_MemoryBpListHeaderNode, @pExpCodeAddr
		.if eax != 0
			invoke ShowReg
			invoke ShowASM, hProcess, NULL, 1, lpContext
			mov g_isMemorySingleStepEX, TRUE
		.endif
		
		invoke VirtualProtectEx, hProcess, @pBpCodeAddr, @dwOldSize, @dwOldType, addr @dwTmp
		
		or  [edi].regFlag, 100h	
		mov @dwContinueStatus, DBG_CONTINUE
		mov g_isMemorySingleStep, TRUE
	.endif

EXIT_PROC:
	mov eax,@dwContinueStatus
	ret
OnAccess endp

OnBreakPoint proc uses ecx ebx esi edi hProcess:HANDLE, hThread:HANDLE, lpDebugEvent:LPVOID, lpContext:LPVOID
	LOCAL @dwContinueStatus:DWORD
	LOCAL @dwCodeOfBreakPoint:DWORD
	mov @dwContinueStatus, DBG_EXCEPTION_NOT_HANDLED
	
	mov esi, lpDebugEvent
	assume esi : ptr DEBUG_EVENT
	lea esi, [esi].u
	assume esi : ptr EXCEPTION_DEBUG_INFO 
	
	mov edi, lpContext
	assume edi : ptr CONTEXT	
	
	mov eax, [esi].pExceptionRecord.ExceptionAddress
	.if  eax == g_lpEntryPoint
		;程序入口断点的临时断点
		invoke WriteProcessMemory, hProcess, g_lpEntryPoint, offset g_btEntryPointCode, 1, NULL
		invoke ShowASM, hProcess, g_lpEntryPoint, 8, lpContext
				
		dec  [edi].regEip
		mov @dwContinueStatus, DBG_CONTINUE
		invoke SuspendThread, g_hThread 
		
		.if g_isDebugSingleStep_P == TRUE 
			or  [edi].regFlag, 100h		
			mov g_isDebugSingleStep, TRUE
			mov g_isDebugSingleStep_P, FALSE
		.endif
		
		.if g_isDebugSingleStep_T == TRUE 
			or  [edi].regFlag, 100h
			mov g_isDebugSingleStep, TRUE
			mov g_isDebugSingleStep_T, FALSE
		.endif	
		
	.elseif 	eax == g_lpStepOverCall
		;call指令的下一条地址的临时断点
		invoke WriteProcessMemory, hProcess, g_lpStepOverCall, offset g_btStepOverCallCode, 1, NULL		
		dec  [edi].regEip
		invoke ShowReg
		invoke ShowASM, hProcess, g_lpStepOverCall, 1, lpContext
		
		mov @dwContinueStatus, DBG_CONTINUE
		invoke SuspendThread, g_hThread 
		
		.if g_isDebugSingleStep_P == TRUE 
			or  [edi].regFlag, 100h		
			mov g_isDebugSingleStep, TRUE
			mov g_isDebugSingleStep_P, FALSE
		.endif
		
		.if g_isDebugSingleStep_T == TRUE 
			or  [edi].regFlag, 100h
			mov g_isDebugSingleStep, TRUE
			mov g_isDebugSingleStep_T, FALSE
		.endif	
		
	.elseif 	eax == g_lpGoBreakPoint
		;g指令目标地址的临时断点
		invoke WriteProcessMemory, hProcess, g_lpGoBreakPoint, offset g_btGoCode, 1, NULL				
		dec  [edi].regEip
		invoke ShowReg
		invoke ShowASM, hProcess, g_lpGoBreakPoint, 1, lpContext	
		push [edi].regEip
		pop g_lpPreCodeAddr
		
		mov @dwContinueStatus, DBG_CONTINUE
		invoke SuspendThread, g_hThread 
		
		.if g_isDebugSingleStep_P == TRUE 
			or  [edi].regFlag, 100h		
			mov g_isDebugSingleStep, TRUE
			mov g_isDebugSingleStep_P, FALSE
		.endif
		
		.if g_isDebugSingleStep_T == TRUE 
			or  [edi].regFlag, 100h
			mov g_isDebugSingleStep, TRUE
			mov g_isDebugSingleStep_T, FALSE
		.endif	
		
	.endif
	
	;非临时断点进行查表
	mov ebx, [esi].pExceptionRecord.ExceptionAddress
	invoke FindBreakPointNode, offset g_BreakPointListHeaderNode, ebx
	.if	eax == 0
		jmp HARDWARE_BP
	.elseif
		;是一般断点
		mov @dwCodeOfBreakPoint, eax
		invoke WriteProcessMemory, hProcess, [esi].pExceptionRecord.ExceptionAddress, addr @dwCodeOfBreakPoint, 1, NULL				
		dec  [edi].regEip
		
		push [edi].regEip
		pop g_lpPreCodeAddr
		mov g_isDebugBreakPoint, TRUE
		mov @dwContinueStatus, DBG_CONTINUE
		push [esi].pExceptionRecord.ExceptionAddress
		pop g_lpDebugBreakPoint
				
		.if g_isDebugSingleStep_P == TRUE 
			or  [edi].regFlag, 100h		
			mov g_isDebugSingleStep, TRUE		
			mov g_isDebugSingleStep_P, FALSE
		.endif
		
		.if g_isDebugSingleStep_T == TRUE 
			or  [edi].regFlag, 100h
			mov g_isDebugSingleStep, TRUE
			mov g_isDebugSingleStep_T, FALSE
		.endif	
		
		.if g_isDebugGo == TRUE
			invoke ShowReg
			invoke ShowASM, hProcess, [esi].pExceptionRecord.ExceptionAddress, 1, lpContext

			mov g_isDebugSingleStep_P, FALSE
			mov g_isDebugSingleStep_T, FALSE		
			or  [edi].regFlag, 100h
			mov g_isDebugSingleStep, TRUE
	
		.endif
		
	.endif
	jmp EXIT_PROC
	
	
HARDWARE_BP:
	;查找是否是硬件断点
	
	
	
EXIT_PROC:
	mov eax,@dwContinueStatus
	ret
OnBreakPoint endp

OnSingleStep proc uses ecx ebx esi edi hProcess:HANDLE, hThread:HANDLE, lpDebugEvent:LPVOID, lpContext:LPVOID
	LOCAL @dwContinueStatus:DWORD
	
	LOCAL @pExpCodeAddr:LPVOID
	LOCAL @pBpCodeAddr:LPVOID
	LOCAL @dwType:DWORD
	LOCAL @dwOldSize:DWORD
	LOCAL @dwNumOfBp:DWORD
	LOCAL @dwTmp:DWORD
	
	mov @dwContinueStatus, DBG_EXCEPTION_NOT_HANDLED

	mov esi, lpDebugEvent
	assume esi : ptr DEBUG_EVENT
	lea esi, [esi].u
	assume esi : ptr EXCEPTION_DEBUG_INFO 
	
	mov edi, lpContext
	assume edi : ptr CONTEXT	
	
	.if g_isHardWareSingleStep == TRUE
		mov g_isHardWareSingleStep, FALSE
		mov eax, g_dwDR7
		mov [edi].iDr7, eax	
		mov @dwContinueStatus, DBG_CONTINUE
		invoke SuspendThread, g_hThread 
	.endif
	
	.if g_isMemorySingleStep == TRUE
		mov g_isMemorySingleStep, FALSE
		mov @dwContinueStatus, DBG_CONTINUE
		;将内存属性置回去

		invoke IsTheSamePage, offset g_MemoryBpListHeaderNode, g_lpMemoryBpAddress	
		mov @dwNumOfBp, eax
		invoke GetTypeOfMemoryBp, offset g_MemoryBpListHeaderNode, @dwNumOfBp
		mov @dwType, eax
		invoke GetSizeOfMemoryBp, offset g_MemoryBpListHeaderNode, @dwNumOfBp
		mov @dwOldSize, eax	
		invoke GetAddressOfMemoryBp, offset g_MemoryBpListHeaderNode, @dwNumOfBp
		mov @pBpCodeAddr, eax	
				
		invoke VirtualProtectEx, hProcess, @pBpCodeAddr, @dwOldSize,@dwType,  addr @dwTmp
		.if g_isMemorySingleStepEX == TRUE
			mov g_isMemorySingleStepEX, FALSE
			invoke SuspendThread, g_hThread 
		.endif
		
	.endif
	
	.if g_isDebugSingleStep == TRUE
		mov g_isDebugSingleStep, FALSE
		mov g_isDebugSingleStep_P, FALSE
		mov @dwContinueStatus, DBG_CONTINUE
		
		.if g_isStepOverCall == TRUE			
			mov g_isStepOverCall, FALSE
			
			.if g_lpPreCodeAddr == NULL
				invoke ShowReg
				invoke ShowASM, hProcess, NULL, 1, lpContext													
			.elseif		
				invoke SetStepOverCallBP, hProcess, g_lpPreCodeAddr, lpContext
				.if	eax == 1
					mov g_isDebugSingleStep, FALSE
					jmp EXIT_PROC
				.endif							
				invoke ShowReg
				invoke ShowASM, hProcess, [edi].regEip, 1, lpContext								
			.endif						
			push [edi].regEip
			pop  g_lpPreCodeAddr	
			invoke SuspendThread, g_hThread 
			
		.elseif g_isDebugGo == TRUE
			invoke SuspendThread, g_hThread 
			
		.else
			invoke ShowReg
			invoke ShowASM, hProcess, [esi].pExceptionRecord.ExceptionAddress, 1, lpContext
			push [edi].regEip
			pop  g_lpPreCodeAddr	
			invoke SuspendThread, g_hThread 
		.endif
		
		
	
		.if g_isDebugBreakPoint == TRUE     ;一般性断点	,需将断点写回
			mov g_isDebugBreakPoint, FALSE
			invoke WriteProcessMemory, hProcess, g_lpDebugBreakPoint, offset g_btExceptionInt3, 1, NULL		
		.endif
		
;		
;		.if g_isDebugGo == TRUE
;			mov g_isDebugSingleStep, FALSE
;			mov g_isDebugSingleStep_P, FALSE
;			mov g_isDebugSingleStep_T, FALSE
;		.endif
					
		.if g_isDebugSingleStep_P == TRUE 
			or  [edi].regFlag, 100h		
			mov g_isDebugSingleStep, TRUE
			mov g_isDebugSingleStep_P, FALSE
		.endif
			
		.if g_isDebugSingleStep_T == TRUE 
			or  [edi].regFlag, 100h
			mov g_isDebugSingleStep, TRUE
			mov g_isDebugSingleStep_T, FALSE
		.endif
	.endif
	
	mov eax, [edi].iDr6
	;判断是否是访问断点，需要重新写回
	.if eax & 1	
		invoke ShowReg
		invoke ShowASM, hProcess, [esi].pExceptionRecord.ExceptionAddress, 1, lpContext
		;0000 0000 0000 0011 00 0 001 11 00 00 00 01b
		mov eax, [edi].iDr7
		mov g_dwDR7, eax
		and eax, 00000000000000110000000000000000b
		shr eax, 16
		.if eax == 0
			and [edi].iDr7, 11111111111111001111111111111100b
		.endif
		or  [edi].regFlag, 100h		
		mov g_isHardWareSingleStep, TRUE
		mov @dwContinueStatus, DBG_CONTINUE
		jmp EXIT_PROC
		
	.elseif eax & 10b
		invoke ShowReg
		invoke ShowASM, hProcess, [esi].pExceptionRecord.ExceptionAddress, 1, lpContext
		;0000 0000 0000 0011 00 0 001 11 00 00 00 01b
		mov eax, [edi].iDr7
		mov g_dwDR7, eax
		and eax, 00000000001100000000000000000000b
		shr eax, 20
		.if eax == 0
			and [edi].iDr7, 11111111110011111111111111110011b
		.endif
		or  [edi].regFlag, 100h		
		mov g_isHardWareSingleStep, TRUE
		mov @dwContinueStatus, DBG_CONTINUE
		jmp EXIT_PROC
		
	.elseif eax & 100b
		invoke ShowReg
		invoke ShowASM, hProcess, [esi].pExceptionRecord.ExceptionAddress, 1, lpContext
		;0000 0000 0000 0011 00 0 001 11 00 00 00 01b
		mov eax, [edi].iDr7
		mov g_dwDR7, eax
		and eax, 00000011000000000000000000000000b
		shr eax, 24
		.if eax == 0
			and [edi].iDr7, 11111100111111111111111111001111b
		.endif
		or  [edi].regFlag, 100h		
		mov g_isHardWareSingleStep, TRUE
		mov @dwContinueStatus, DBG_CONTINUE
		jmp EXIT_PROC		
		
	.elseif eax & 1000b	
		invoke ShowReg
		invoke ShowASM, hProcess, [esi].pExceptionRecord.ExceptionAddress, 1, lpContext
		;0000 0000 0000 0011 00 0 001 11 00 00 00 01b
		mov eax, [edi].iDr7
		mov g_dwDR7, eax
		and eax, 00110000000000000000000000000000b
		shr eax, 28
		.if eax == 0
			and [edi].iDr7, 11001111111111111111111100111111b
		.endif
		or  [edi].regFlag, 100h		
		mov g_isHardWareSingleStep, TRUE
		mov @dwContinueStatus, DBG_CONTINUE
		jmp EXIT_PROC		
		
	.endif


EXIT_PROC:		
	mov eax,@dwContinueStatus
	ret
OnSingleStep endp

OnCreateThread proc uses ecx ebx esi edi hProcess:HANDLE, hThread:HANDLE, lpDebugEvent:LPVOID, lpContext:LPVOID
	LOCAL @dwContinueStatus:DWORD
	mov @dwContinueStatus, DBG_CONTINUE
	
	mov esi, lpDebugEvent
	assume esi : ptr DEBUG_EVENT
	lea esi, [esi].u
	assume esi : ptr EXCEPTION_DEBUG_INFO 
	
	mov edi, lpContext
	assume edi : ptr CONTEXT	
	
	mov eax,@dwContinueStatus
	ret
OnCreateThread endp

OnCreateProcess proc uses ecx ebx esi edi hProcess:HANDLE, hThread:HANDLE, lpDebugEvent:LPVOID, lpContext:LPVOID
	LOCAL @dwContinueStatus:DWORD

	mov @dwContinueStatus, DBG_CONTINUE
	
	mov esi, lpDebugEvent
	assume esi : ptr DEBUG_EVENT
	lea esi, [esi].u
	assume esi : ptr CREATE_PROCESS_DEBUG_INFO 
	
	mov edi, lpContext
	assume edi : ptr CONTEXT
	
	mov eax, [esi].lpStartAddress
	mov g_lpEntryPoint, eax
	
	invoke ReadProcessMemory, hProcess, g_lpEntryPoint, offset g_btEntryPointCode, 1, NULL
	.if	eax == 0
		jmp EXIT_PROC
	.endif
	
	invoke WriteProcessMemory, hProcess, g_lpEntryPoint, offset g_btExceptionInt3, 1, NULL
	.if	eax == 0
		jmp EXIT_PROC
	.endif	

EXIT_PROC:	
	mov eax,@dwContinueStatus
	ret
OnCreateProcess endp

OnExitThread proc uses ecx ebx esi edi hProcess:HANDLE, hThread:HANDLE, lpDebugEvent:LPVOID, lpContext:LPVOID
	LOCAL @dwContinueStatus:DWORD
	mov @dwContinueStatus, DBG_CONTINUE
	
	mov esi, lpDebugEvent
	assume esi : ptr DEBUG_EVENT
	lea esi, [esi].u
	assume esi : ptr EXCEPTION_DEBUG_INFO 
	
	mov edi, lpContext
	assume edi : ptr CONTEXT	
	
	mov eax,@dwContinueStatus
	ret
OnExitThread endp

OnLoadDLL proc uses ecx ebx esi edi hProcess:HANDLE, hThread:HANDLE, lpDebugEvent:LPVOID, lpContext:LPVOID
	LOCAL @dwContinueStatus:DWORD
	mov @dwContinueStatus, DBG_CONTINUE
	;读目标进程中的地址。或者DLL路径，相当于OD中的记录
	
	mov esi, lpDebugEvent
	assume esi : ptr DEBUG_EVENT
	lea esi, [esi].u
	assume esi : ptr EXCEPTION_DEBUG_INFO 
	
	mov edi, lpContext
	assume edi : ptr CONTEXT	
	
	mov eax,@dwContinueStatus
	ret
OnLoadDLL endp

OnUnloadDLL proc uses ecx ebx esi edi hProcess:HANDLE, hThread:HANDLE, lpDebugEvent:LPVOID, lpContext:LPVOID
	LOCAL @dwContinueStatus:DWORD
	mov @dwContinueStatus, DBG_CONTINUE
	
	mov esi, lpDebugEvent
	assume esi : ptr DEBUG_EVENT
	lea esi, [esi].u
	assume esi : ptr EXCEPTION_DEBUG_INFO 
	
	mov edi, lpContext
	assume edi : ptr CONTEXT	
	
	mov eax,@dwContinueStatus
	ret
OnUnloadDLL endp

OnDebugString proc uses ecx ebx esi edi hProcess:HANDLE, hThread:HANDLE, lpDebugEvent:LPVOID, lpContext:LPVOID
	LOCAL @dwContinueStatus:DWORD
	mov @dwContinueStatus, DBG_CONTINUE
	
	mov esi, lpDebugEvent
	assume esi : ptr DEBUG_EVENT
	lea esi, [esi].u
	assume esi : ptr EXCEPTION_DEBUG_INFO 
	
	mov edi, lpContext
	assume edi : ptr CONTEXT	
	
	mov eax,@dwContinueStatus
	ret
OnDebugString endp

DebugProc proc uses ecx ebx esi edi hProcess:HANDLE, hThread:HANDLE, lpDebugEvent:LPVOID, lpContext:LPVOID
	LOCAL @dwContinueStatus:DWORD
	mov @dwContinueStatus, DBG_EXCEPTION_NOT_HANDLED
	
	mov esi, lpDebugEvent
	assume esi: ptr DEBUG_EVENT
	lea edi, [esi].u
	
	.if	[esi].dwDebugEventCode == EXCEPTION_DEBUG_EVENT
		assume edi :ptr EXCEPTION_DEBUG_INFO 
		.if	[edi].pExceptionRecord.ExceptionCode == EXCEPTION_ACCESS_VIOLATION
			invoke OnAccess, hProcess, hThread, lpDebugEvent, lpContext
			mov @dwContinueStatus,eax
			
		.elseif [edi].pExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT
			invoke OnBreakPoint, hProcess, hThread, lpDebugEvent, lpContext
			mov @dwContinueStatus,eax
			
		.elseif [edi].pExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP
			invoke OnSingleStep, hProcess, hThread, lpDebugEvent, lpContext
			mov @dwContinueStatus,eax
			
		.endif
		
	.elseif [esi].dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT
		assume edi :ptr CREATE_THREAD_DEBUG_INFO 
		invoke OnCreateThread, hProcess, hThread, lpDebugEvent, lpContext
		mov @dwContinueStatus,eax
			
	.elseif [esi].dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT
		assume edi :ptr CREATE_PROCESS_DEBUG_INFO  
		invoke OnCreateProcess, hProcess, hThread, lpDebugEvent, lpContext
		mov @dwContinueStatus,eax
			
	.elseif [esi].dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT
		assume edi :ptr  EXIT_THREAD_DEBUG_INFO  
		invoke OnExitThread, hProcess, hThread, lpDebugEvent, lpContext
		mov @dwContinueStatus,eax
			
	.elseif [esi].dwDebugEventCode == LOAD_DLL_DEBUG_EVENT
		assume edi :ptr LOAD_DLL_DEBUG_INFO  
		invoke OnLoadDLL, hProcess, hThread, lpDebugEvent, lpContext
		mov @dwContinueStatus,eax
			
	.elseif [esi].dwDebugEventCode == UNLOAD_DLL_DEBUG_EVENT
		assume edi :ptr UNLOAD_DLL_DEBUG_INFO  
		invoke OnUnloadDLL, hProcess, hThread, lpDebugEvent, lpContext
		mov @dwContinueStatus,eax
			
	.elseif [esi].dwDebugEventCode == OUTPUT_DEBUG_STRING_EVENT
		assume edi :ptr OUTPUT_DEBUG_STRING_INFO  
		invoke OnDebugString, hProcess, hThread, lpDebugEvent, lpContext
		mov @dwContinueStatus,eax
			
	.endif
	
	mov eax,@dwContinueStatus
	ret
DebugProc endp

ThreadFunc proc uses ecx ebx esi edi
	LOCAL @si:STARTUPINFO
	LOCAL @pi:PROCESS_INFORMATION
	LOCAL @DebugEvent:DEBUG_EVENT
	LOCAL @hProcess:HANDLE
	LOCAL @hThread:HANDLE
	LOCAL @Context:CONTEXT
	LOCAL @dwContinueStatus:DWORD
	
	invoke RtlZeroMemory, addr @si, sizeof STARTUPINFO
	invoke RtlZeroMemory, addr @pi, sizeof PROCESS_INFORMATION
	mov @si.cb, sizeof @si
	xor eax,eax
	mov @hProcess, eax
	mov @hThread, eax
	mov @dwContinueStatus, DBG_EXCEPTION_NOT_HANDLED
	
	invoke CreateProcess, NULL, offset g_szFilePath, NULL, NULL, FALSE, 
						DEBUG_ONLY_THIS_PROCESS, NULL, NULL, addr @si, addr @pi
	.if	eax == 0
		jmp EXIT_PROC
	.endif
	
	.while 1
		invoke WaitForDebugEvent, addr @DebugEvent, INFINITE
		.if	eax == 0
			jmp EXIT_PROC
		.endif
		
		.if @DebugEvent.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT
			.break
		.endif
		
		.if	@hProcess == NULL
			invoke OpenProcess, PROCESS_ALL_ACCESS, FALSE, @DebugEvent.dwProcessId
			.if	eax == NULL
				jmp EXIT_PROC
			.endif
			mov @hProcess,eax
			mov g_hProcess, eax
					
			invoke OpenThread, THREAD_ALL_ACCESS, FALSE, @DebugEvent.dwThreadId
			.if	eax == NULL
				jmp EXIT_PROC
			.endif
			mov @hThread,eax		
		.endif
			
		mov @Context.ContextFlags, CONTEXT_ALL
		invoke GetThreadContext, @hThread, addr @Context
		.if	eax == 0
			jmp EXIT_PROC
		.endif
		
		lea eax, @Context
		push eax
		pop  g_lpContext
		
		invoke DebugProc, @hProcess, @hThread, addr @DebugEvent, addr @Context
		mov @dwContinueStatus, eax
		
		invoke SetThreadContext, @hThread, addr @Context
		.if	eax == 0
			jmp EXIT_PROC
		.endif
				
		invoke ContinueDebugEvent, @DebugEvent.dwProcessId, @DebugEvent.dwThreadId,@dwContinueStatus
	.endw

EXIT_PROC:
	.if @hThread
		invoke CloseHandle, @hThread
	.endif
		
	.if @hProcess
		invoke CloseHandle, @hProcess
	.endif
	ret
ThreadFunc endp

main proc C
	
	ret
main endp

GetInputCommand proc uses ecx ebx esi edi szCommand:LPVOID
	LOCAL @szAddress[50]:byte
	LOCAL @dwAddress:DWORD
	LOCAL @dwNumber:DWORD
	
	xor eax,eax
	mov @dwAddress,eax
	mov @dwNumber,eax
	invoke RtlZeroMemory, addr @szAddress, sizeof @szAddress
	
	mov eax, szCommand
	movzx eax, byte ptr [eax]
	
	.if (ax == 'r') || (ax == 'R')   ;查看寄存器
		invoke crt_strlen, szCommand
		.if eax > 1
			jmp ERROR_INPUT
		.endif	
		invoke ShowReg
		jmp EXIT_PROC
	.endif
	
	.if (ax == 'u') || (ax == 'U')  ;查看反汇编
		invoke crt_strlen, szCommand
		.if	eax == 1
			invoke ShowASM, g_hProcess, NULL, 8, g_lpContext
			jmp EXIT_PROC
			
		.elseif
			mov eax, szCommand
			movzx eax, byte ptr [eax + 1]
			.if	ax != 20h
				jmp ERROR_INPUT
			.endif
			
			mov esi, szCommand
			add esi, 2
			invoke crt_memcpy,  addr @szAddress, esi, 8
			invoke crt_strtol, addr @szAddress, NULL, 16
			.if	eax == 0
				jmp ERROR_INPUT
			.endif
			mov @dwAddress, eax
			
			;判断输入的地址是否有效
			.if (@dwAddress < 10000h) || (@dwAddress > 7FFE1000H)
				jmp ERROR_INPUT
			.endif
			invoke ShowASM, g_hProcess, @dwAddress, 8, g_lpContext
			jmp EXIT_PROC
			
		.endif			
	.endif
	
	.if (ax == 'p') || (ax == 'P')    ;单步步过	
		invoke crt_strlen, szCommand
		.if eax > 1
			jmp ERROR_INPUT
		.endif
		mov g_isDebugSingleStep_P, TRUE
		mov g_isStepOverCall, TRUE
		invoke ResumeThread,  g_hThread
		jmp EXIT_PROC
	.endif
	
	.if (ax == 't') || (ax == 'T')    ;单步步入	
		invoke crt_strlen, szCommand
		.if eax > 1
			jmp ERROR_INPUT
		.endif
		mov g_isDebugSingleStep_T, TRUE
		invoke ResumeThread,  g_hThread			
		jmp EXIT_PROC
	.endif
	
	.if (ax == 'g') || (ax == 'G')    ;运行	
		invoke crt_strlen, szCommand
		.if eax == 1
			mov g_isDebugGo, TRUE
			invoke ResumeThread,  g_hThread	
			jmp EXIT_PROC			
		.elseif
			mov eax, szCommand
			movzx eax, byte ptr [eax + 1]
			.if	ax != 20h
				jmp ERROR_INPUT
			.endif
			
			mov esi, szCommand
			add esi, 2
			invoke crt_memcpy,  addr @szAddress, esi, 8
			invoke crt_strtol, addr @szAddress, NULL, 16
			.if	eax == 0
				jmp ERROR_INPUT
			.endif
			mov @dwAddress, eax
			
			;判断输入的地址是否有效
			.if (@dwAddress < 10000h) || (@dwAddress > 7FFE1000H)
				jmp ERROR_INPUT
			.endif
			
			push @dwAddress
			pop  g_lpGoBreakPoint
			
			invoke SetGoBP, g_hProcess    ;设置断点
			invoke ResumeThread,  g_hThread
			jmp EXIT_PROC
		.endif
	.endif
	
	mov eax, szCommand
	movzx eax, word ptr [eax]
	
	.if (ax == 6464h) || (ax == 4444h)   ;dd命令,查看内存
		invoke crt_strlen, szCommand
		.if	eax == 2
			invoke ShowMemory, g_hProcess, NULL, g_lpContext
			jmp EXIT_PROC
			
		.elseif
			mov eax, szCommand
			movzx eax, byte ptr [eax + 2]
			.if	ax != 20h
				jmp ERROR_INPUT
			.endif
			
			mov esi, szCommand
			add esi, 3
			invoke crt_memcpy,  addr @szAddress, esi, 8
			invoke crt_strtol, addr @szAddress, NULL, 16
			.if	eax == 0
				jmp ERROR_INPUT
			.endif
			mov @dwAddress, eax
			
			;判断输入的地址是否有效
			.if (@dwAddress < 10000h) || (@dwAddress > 7FFE1000H)
				jmp ERROR_INPUT
			.endif
			invoke ShowMemory, g_hProcess, @dwAddress, g_lpContext
			jmp EXIT_PROC
		.endif	
	.endif
	
	.if (ax == 7062h) || (ax == 5042h)   ;bp一般断点命令
		invoke crt_strlen, szCommand
		.if	eax == 2
			jmp ERROR_INPUT
		.endif
		
		mov eax, szCommand
		movzx eax, byte ptr [eax + 2]
		
		.if	(ax == 'l') || (ax == 'L')
			;bpl
			invoke ShowBreakPointNode, offset g_BreakPointListHeaderNode
			jmp EXIT_PROC
			
		.elseif (ax == 'c') || (ax == 'C')
			;bpc 序号
			mov eax, szCommand
			movzx eax, byte ptr [eax + 3]
			.if	ax != 20h
				jmp ERROR_INPUT
			.endif
			
			mov esi, szCommand
			add esi, 4
			invoke crt_memcpy,  addr @szAddress, esi, 8
			invoke crt_atoi, addr @szAddress
			mov @dwNumber, eax		
			invoke DelUserBreakPoint, g_hProcess, @dwNumber
			jmp EXIT_PROC
			
		.elseif  ax == 20h
			;bp addr 设置一般断点
			mov eax, szCommand
			movzx eax, byte ptr [eax + 2]
			.if	ax != 20h
				jmp ERROR_INPUT
			.endif
			
			mov esi, szCommand
			add esi, 3
			invoke crt_memcpy,  addr @szAddress, esi, 8
			invoke crt_strtol, addr @szAddress, NULL, 16
			.if	eax == 0
				jmp ERROR_INPUT
			.endif
			mov @dwAddress, eax
			
			;判断输入的地址是否有效
			.if (@dwAddress < 10000h) || (@dwAddress > 7FFE1000H)
				jmp ERROR_INPUT
			.endif
			
			invoke SetUserBreakPoint, g_hProcess, @dwAddress, g_lpContext
			jmp EXIT_PROC
			
		.endif
		
	.endif
	
	.if (ax == 6862h) || (ax == 4842h)   ;bh硬件断点命令
		invoke crt_strlen, szCommand
		.if	eax == 2
			jmp ERROR_INPUT
		.endif
		
		mov eax, szCommand
		movzx eax, byte ptr [eax + 2]
		
		.if	(ax == 'l') || (ax == 'L')
			;bhl
			invoke ShowHardWareBpNode, offset g_HardWareBpListHeaderNode
			jmp EXIT_PROC
			
		.elseif (ax == 'c') || (ax == 'C')
			;bhc 序号
			mov eax, szCommand
			movzx eax, byte ptr [eax + 3]
			.if	ax != 20h
				jmp ERROR_INPUT
			.endif
			
			mov esi, szCommand
			add esi, 4
			invoke crt_memcpy,  addr @szAddress, esi, 8
			invoke crt_atoi, addr @szAddress
			mov @dwNumber, eax		
			invoke DelHardWareBreakPoint, g_hProcess, @dwNumber, g_lpContext
			jmp EXIT_PROC
			
		.elseif  ax == 20h
			;bh addr 设置硬件断点
			.if g_dwHardWareBpCount == 4
				jmp EXIT_PROC
			.endif
			mov eax, szCommand
			movzx eax, byte ptr [eax + 2]
			.if	ax != 20h
				jmp ERROR_INPUT
			.endif
			
			mov esi, szCommand
			add esi, 3
			invoke crt_memcpy,  addr @szAddress, esi, 8
			invoke crt_strtol, addr @szAddress, NULL, 16
			.if	eax == 0
				jmp ERROR_INPUT
			.endif
			mov @dwAddress, eax
			
			;判断输入的地址是否有效
			.if (@dwAddress < 10000h) || (@dwAddress > 7FFE1000H)
				jmp ERROR_INPUT
			.endif
						
			invoke SetHardWareBreakPoint, g_hProcess, @dwAddress, szCommand, g_lpContext
			.if eax == FALSE
				jmp ERROR_INPUT
			.endif
			jmp EXIT_PROC
			
		.endif
		
	.endif
	
	.if (ax == 6D62h) || (ax == 4D42h)   ;bm内存断点命令
		invoke crt_strlen, szCommand
		.if	eax == 2
			jmp ERROR_INPUT
		.endif
		
		mov eax, szCommand
		movzx eax, byte ptr [eax + 2]
		
		.if	(ax == 'l') || (ax == 'L')
			;bml
			invoke ShowMemoryBpNode, offset g_MemoryBpListHeaderNode
			jmp EXIT_PROC
			
		.elseif (ax == 'c') || (ax == 'C')
			;bmc 序号
			mov eax, szCommand
			movzx eax, byte ptr [eax + 3]
			.if	ax != 20h
				jmp ERROR_INPUT
			.endif
			
			mov esi, szCommand
			add esi, 4
			invoke crt_memcpy,  addr @szAddress, esi, 8
			invoke crt_atoi, addr @szAddress
			mov @dwNumber, eax		
			invoke DelMemoryBreakPoint, g_hProcess, @dwNumber, g_lpContext
			jmp EXIT_PROC
			
		.elseif  ax == 20h
			;bm addr 长度 类型 设置内存断点
			mov eax, szCommand
			movzx eax, byte ptr [eax + 2]
			.if	ax != 20h
				jmp ERROR_INPUT
			.endif
			
			mov esi, szCommand
			add esi, 3
			invoke crt_memcpy,  addr @szAddress, esi, 8
			invoke crt_strtol, addr @szAddress, NULL, 16
			.if	eax == 0
				jmp ERROR_INPUT
			.endif
			mov @dwAddress, eax
			
			;判断输入的地址是否有效
			.if (@dwAddress < 10000h) || (@dwAddress > 7FFE1000H)
				jmp ERROR_INPUT
			.endif
						
			invoke SetMemoryBreakPoint, g_hProcess, @dwAddress, szCommand, g_lpContext
			.if eax == FALSE
				jmp ERROR_INPUT
			.endif
			jmp EXIT_PROC
			
		.endif
		
	.endif
	
ERROR_INPUT:
	invoke crt_printf, offset g_szErrorInputFormat
	ret
EXIT_PROC:
	ret
GetInputCommand endp


start proc 
	LOCAL @hThread:HANDLE
	LOCAL @szCommand[50]:byte
	xor eax,eax
	mov @hThread, eax
	
	invoke CreateThread, NULL, 0, ThreadFunc, NULL, 0, NULL
	.if eax == NULL
		jmp EXIT_PROC
	.endif
	mov @hThread, eax
	mov g_hThread, eax
	
	;get user Input
	.while 1
		invoke crt_gets, addr @szCommand
		invoke GetInputCommand, addr @szCommand
	.endw
	
EXIT_PROC:
	invoke ExitProcess,0
start endp
end start







