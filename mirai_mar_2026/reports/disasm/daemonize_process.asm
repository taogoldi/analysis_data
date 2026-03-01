
/Users/taogoldi/Projects/malware/Mirai/input/d40cf9c95dcedf4f19e4a5f5bb744c8e98af87eb5703c850e6fda3b613668c28.elf:	file format elf64-x86-64

Disassembly of section .text:

0000000000400940 <daemonize_process>:
  400940: 53                           	push	rbx
  400941: e8 22 2f 00 00               	call	0x403868 <fork>
  400946: 83 f8 00                     	cmp	eax, 0x0
  400949: 0f 8c a7 00 00 00            	jl	0x4009f6 <daemonize_process+0xb6>
  40094f: 0f 85 ab 00 00 00            	jne	0x400a00 <daemonize_process+0xc0>
  400955: e8 7a 6e 00 00               	call	0x4077d4 <setsid>
  40095a: 85 c0                        	test	eax, eax
  40095c: 66 66 66 90                  	nop
  400960: 0f 88 90 00 00 00            	js	0x4009f6 <daemonize_process+0xb6>
  400966: e8 fd 2e 00 00               	call	0x403868 <fork>
  40096b: 83 f8 00                     	cmp	eax, 0x0
  40096e: 66 90                        	nop
  400970: 0f 8c 80 00 00 00            	jl	0x4009f6 <daemonize_process+0xb6>
  400976: 0f 85 84 00 00 00            	jne	0x400a00 <daemonize_process+0xc0>
  40097c: 31 ff                        	xor	edi, edi
  40097e: 66 90                        	nop
  400980: e8 73 6f 00 00               	call	0x4078f8 <umask>
  400985: bf 90 4a 41 00               	mov	edi, 0x414a90
  40098a: e8 49 66 00 00               	call	0x406fd8 <chdir>
  40098f: bf 04 00 00 00               	mov	edi, 0x4
  400994: e8 0b bc 00 00               	call	0x40c5a4 <sysconf>
  400999: 85 c0                        	test	eax, eax
  40099b: 89 c3                        	mov	ebx, eax
  40099d: 78 0f                        	js	0x4009ae <daemonize_process+0x6e>
  40099f: 90                           	nop
  4009a0: 89 df                        	mov	edi, ebx
  4009a2: ff cb                        	dec	ebx
  4009a4: e8 95 49 00 00               	call	0x40533e <close>
  4009a9: 83 fb ff                     	cmp	ebx, -0x1
  4009ac: 75 f2                        	jne	0x4009a0 <daemonize_process+0x60>
  4009ae: 31 c0                        	xor	eax, eax
  4009b0: be 02 00 00 00               	mov	esi, 0x2
  4009b5: bf 92 4a 41 00               	mov	edi, 0x414a92
  4009ba: e8 62 47 00 00               	call	0x405121 <open>
  4009bf: 83 f8 ff                     	cmp	eax, -0x1
  4009c2: 89 c3                        	mov	ebx, eax
  4009c4: 74 26                        	je	0x4009ec <daemonize_process+0xac>
  4009c6: 31 f6                        	xor	esi, esi
  4009c8: 89 c7                        	mov	edi, eax
  4009ca: e8 85 66 00 00               	call	0x407054 <dup2>
  4009cf: be 01 00 00 00               	mov	esi, 0x1
  4009d4: 89 df                        	mov	edi, ebx
  4009d6: e8 79 66 00 00               	call	0x407054 <dup2>
  4009db: be 02 00 00 00               	mov	esi, 0x2
  4009e0: 89 df                        	mov	edi, ebx
  4009e2: e8 6d 66 00 00               	call	0x407054 <dup2>
  4009e7: 83 fb 02                     	cmp	ebx, 0x2
  4009ea: 7f 02                        	jg	0x4009ee <daemonize_process+0xae>
  4009ec: 5b                           	pop	rbx
  4009ed: c3                           	ret
  4009ee: 89 df                        	mov	edi, ebx
  4009f0: 5b                           	pop	rbx
  4009f1: e9 48 49 00 00               	jmp	0x40533e <close>
  4009f6: bf 01 00 00 00               	mov	edi, 0x1
  4009fb: e8 58 b8 00 00               	call	0x40c258 <exit>
  400a00: 31 ff                        	xor	edi, edi
  400a02: e8 51 b8 00 00               	call	0x40c258 <exit>
  400a07: 90                           	nop
  400a08: 90                           	nop
  400a09: 90                           	nop
  400a0a: 90                           	nop
  400a0b: 90                           	nop
  400a0c: 90                           	nop
  400a0d: 90                           	nop
  400a0e: 90                           	nop
  400a0f: 90                           	nop
