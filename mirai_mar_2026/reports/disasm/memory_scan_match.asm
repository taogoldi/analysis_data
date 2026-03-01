
/Users/taogoldi/Projects/malware/Mirai/input/d40cf9c95dcedf4f19e4a5f5bb744c8e98af87eb5703c850e6fda3b613668c28.elf:	file format elf64-x86-64

Disassembly of section .text:

0000000000400bc0 <memory_scan_match>:
  400bc0: 55                           	push	rbp
  400bc1: 48 89 fd                     	mov	rbp, rdi
  400bc4: 53                           	push	rbx
  400bc5: 31 db                        	xor	ebx, ebx
  400bc7: 48 83 ec 08                  	sub	rsp, 0x8
  400bcb: 66 66 90                     	nop
  400bce: 66 90                        	nop
  400bd0: 48 8b 34 dd 20 76 51 00      	mov	rsi, qword ptr [8*rbx + 0x517620]
  400bd8: 48 89 ef                     	mov	rdi, rbp
  400bdb: e8 d8 92 00 00               	call	0x409eb8 <strstr>
  400be0: 48 85 c0                     	test	rax, rax
  400be3: 75 12                        	jne	0x400bf7 <memory_scan_match+0x37>
  400be5: 48 ff c3                     	inc	rbx
  400be8: 48 83 fb 10                  	cmp	rbx, 0x10
  400bec: 75 e2                        	jne	0x400bd0 <memory_scan_match+0x10>
  400bee: 48 83 c4 08                  	add	rsp, 0x8
  400bf2: 31 c0                        	xor	eax, eax
  400bf4: 5b                           	pop	rbx
  400bf5: 5d                           	pop	rbp
  400bf6: c3                           	ret
  400bf7: 48 83 c4 08                  	add	rsp, 0x8
  400bfb: b8 01 00 00 00               	mov	eax, 0x1
  400c00: 5b                           	pop	rbx
  400c01: 5d                           	pop	rbp
  400c02: c3                           	ret
  400c03: 66 66 66 90                  	nop
  400c07: 66 66 90                     	nop
  400c0a: 66 66 90                     	nop
  400c0d: 66 66 90                     	nop
