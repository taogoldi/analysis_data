
/Users/taogoldi/Projects/malware/Mirai/input/d40cf9c95dcedf4f19e4a5f5bb744c8e98af87eb5703c850e6fda3b613668c28.elf:	file format elf64-x86-64

Disassembly of section .text:

0000000000400260 <force_sigkill>:
  400260: 48 83 ec 08                  	sub	rsp, 0x8
  400264: bf 68 48 41 00               	mov	edi, 0x414868
  400269: e8 de 7b 00 00               	call	0x407e4c <puts>
  40026e: bf 98 48 41 00               	mov	edi, 0x414898
  400273: e8 d4 7b 00 00               	call	0x407e4c <puts>
  400278: 48 8b 3d e9 fd 11 00         	mov	rdi, qword ptr [rip + 0x11fde9] # 0x520068 <stdout>
  40027f: e8 84 91 00 00               	call	0x409408 <fflush>
  400284: bf 09 00 00 00               	mov	edi, 0x9
  400289: e8 8b 40 00 00               	call	0x404319 <raise>
  40028e: bf 89 00 00 00               	mov	edi, 0x89
  400293: e8 e8 6c 00 00               	call	0x406f80 <_exit>
  400298: 66 66 66 90                  	nop
  40029c: 66 66 66 90                  	nop
