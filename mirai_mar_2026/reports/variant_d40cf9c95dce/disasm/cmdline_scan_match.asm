
/Users/taogoldi/Projects/Malware/Mirai/input/d40cf9c95dcedf4f19e4a5f5bb744c8e98af87eb5703c850e6fda3b613668c28.elf:	file format elf64-x86-64

Disassembly of section .text:

0000000000400b10 <cmdline_scan_match>:
  400b10: 41 54                        	push	r12
  400b12: 48 89 f9                     	mov	rcx, rdi
  400b15: ba c3 4b 41 00               	mov	edx, 0x414bc3
  400b1a: be 00 10 00 00               	mov	esi, 0x1000
  400b1f: 31 c0                        	xor	eax, eax
  400b21: 55                           	push	rbp
  400b22: 53                           	push	rbx
  400b23: 48 81 ec 00 20 00 00         	sub	rsp, 0x2000
  400b2a: 48 8d 9c 24 00 10 00 00      	lea	rbx, [rsp + 0x1000]
  400b32: 48 89 df                     	mov	rdi, rbx
  400b35: e8 c6 74 00 00               	call	0x408000 <snprintf>
  400b3a: 48 89 df                     	mov	rdi, rbx
  400b3d: be fd 4b 41 00               	mov	esi, 0x414bfd
  400b42: e8 c9 72 00 00               	call	0x407e10 <fopen>
  400b47: 48 85 c0                     	test	rax, rax
  400b4a: 48 89 c3                     	mov	rbx, rax
  400b4d: 74 4f                        	je	0x400b9e <cmdline_scan_match+0x8e>
  400b4f: 48 89 c1                     	mov	rcx, rax
  400b52: ba ff 0f 00 00               	mov	edx, 0xfff
  400b57: be 01 00 00 00               	mov	esi, 0x1
  400b5c: 48 89 e7                     	mov	rdi, rsp
  400b5f: e8 88 89 00 00               	call	0x4094ec <fread>
  400b64: 48 89 df                     	mov	rdi, rbx
  400b67: 48 89 c5                     	mov	rbp, rax
  400b6a: e8 9d 71 00 00               	call	0x407d0c <fclose>
  400b6f: 48 85 ed                     	test	rbp, rbp
  400b72: 74 2a                        	je	0x400b9e <cmdline_scan_match+0x8e>
  400b74: c6 04 2c 00                  	mov	byte ptr [rsp + rbp], 0x0
  400b78: 31 db                        	xor	ebx, ebx
  400b7a: 66 66 90                     	nop
  400b7d: 66 66 90                     	nop
  400b80: 48 8b 34 dd a0 76 51 00      	mov	rsi, qword ptr [8*rbx + 0x5176a0]
  400b88: 48 89 e7                     	mov	rdi, rsp
  400b8b: e8 28 93 00 00               	call	0x409eb8 <strstr>
  400b90: 48 85 c0                     	test	rax, rax
  400b93: 75 17                        	jne	0x400bac <cmdline_scan_match+0x9c>
  400b95: 48 ff c3                     	inc	rbx
  400b98: 48 83 fb 12                  	cmp	rbx, 0x12
  400b9c: 75 e2                        	jne	0x400b80 <cmdline_scan_match+0x70>
  400b9e: 48 81 c4 00 20 00 00         	add	rsp, 0x2000
  400ba5: 31 c0                        	xor	eax, eax
  400ba7: 5b                           	pop	rbx
  400ba8: 5d                           	pop	rbp
  400ba9: 41 5c                        	pop	r12
  400bab: c3                           	ret
  400bac: 48 81 c4 00 20 00 00         	add	rsp, 0x2000
  400bb3: b8 01 00 00 00               	mov	eax, 0x1
  400bb8: 5b                           	pop	rbx
  400bb9: 5d                           	pop	rbp
  400bba: 41 5c                        	pop	r12
  400bbc: c3                           	ret
  400bbd: 66 66 90                     	nop
