
/Users/taogoldi/Projects/Malware/Mirai/input/d40cf9c95dcedf4f19e4a5f5bb744c8e98af87eb5703c850e6fda3b613668c28.elf:	file format elf64-x86-64

Disassembly of section .text:

00000000004001c0 <verify_server_ip>:
  4001c0: 55                           	push	rbp
  4001c1: 53                           	push	rbx
  4001c2: 48 83 ec 38                  	sub	rsp, 0x38
  4001c6: 48 8d 6c 24 10               	lea	rbp, [rsp + 0x10]
  4001cb: 48 8d 54 24 2c               	lea	rdx, [rsp + 0x2c]
  4001d0: c7 44 24 2c 10 00 00 00      	mov	dword ptr [rsp + 0x2c], 0x10
  4001d8: 48 89 ee                     	mov	rsi, rbp
  4001db: e8 58 a5 00 00               	call	0x40a738 <getpeername>
  4001e0: 85 c0                        	test	eax, eax
  4001e2: 78 5d                        	js	0x400241 <verify_server_ip+0x81>
  4001e4: 48 8d 75 04                  	lea	rsi, [rbp + 0x4]
  4001e8: b9 10 00 00 00               	mov	ecx, 0x10
  4001ed: 48 89 e2                     	mov	rdx, rsp
  4001f0: bf 02 00 00 00               	mov	edi, 0x2
  4001f5: e8 ba a2 00 00               	call	0x40a4b4 <inet_ntop>
  4001fa: fc                           	cld
  4001fb: b9 10 00 00 00               	mov	ecx, 0x10
  400200: bf 8a 49 41 00               	mov	edi, 0x41498a
  400205: 48 89 e6                     	mov	rsi, rsp
  400208: f3 a6                        	rep		cmpsb	byte ptr [rsi], byte ptr es:[rdi]
  40020a: b9 01 00 00 00               	mov	ecx, 0x1
  40020f: 0f 97 c2                     	seta	dl
  400212: 0f 92 c0                     	setb	al
  400215: 38 c2                        	cmp	dl, al
  400217: 75 09                        	jne	0x400222 <verify_server_ip+0x62>
  400219: 48 83 c4 38                  	add	rsp, 0x38
  40021d: 89 c8                        	mov	eax, ecx
  40021f: 5b                           	pop	rbx
  400220: 5d                           	pop	rbp
  400221: c3                           	ret
  400222: 48 89 e6                     	mov	rsi, rsp
  400225: ba 8a 49 41 00               	mov	edx, 0x41498a
  40022a: bf 20 48 41 00               	mov	edi, 0x414820
  40022f: 31 c0                        	xor	eax, eax
  400231: e8 9a 7c 00 00               	call	0x407ed0 <printf>
  400236: 48 83 c4 38                  	add	rsp, 0x38
  40023a: 31 c9                        	xor	ecx, ecx
  40023c: 5b                           	pop	rbx
  40023d: 5d                           	pop	rbp
  40023e: 89 c8                        	mov	eax, ecx
  400240: c3                           	ret
  400241: bf 00 48 41 00               	mov	edi, 0x414800
  400246: e8 01 7c 00 00               	call	0x407e4c <puts>
  40024b: 48 83 c4 38                  	add	rsp, 0x38
  40024f: 31 c9                        	xor	ecx, ecx
  400251: 5b                           	pop	rbx
  400252: 5d                           	pop	rbp
  400253: 89 c8                        	mov	eax, ecx
  400255: c3                           	ret
  400256: 66 66 66 90                  	nop
  40025a: 66 66 90                     	nop
  40025d: 66 66 90                     	nop
