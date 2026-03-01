
/Users/taogoldi/Projects/malware/Mirai/input/d40cf9c95dcedf4f19e4a5f5bb744c8e98af87eb5703c850e6fda3b613668c28.elf:	file format elf64-x86-64

Disassembly of section .text:

00000000004025f0 <get_local_ip>:
  4025f0: 55                           	push	rbp
  4025f1: 31 d2                        	xor	edx, edx
  4025f3: be 02 00 00 00               	mov	esi, 0x2
  4025f8: bf 02 00 00 00               	mov	edi, 0x2
  4025fd: 53                           	push	rbx
  4025fe: 48 83 ec 38                  	sub	rsp, 0x38
  402602: e8 6d 82 00 00               	call	0x40a874 <socket>
  402607: 89 c3                        	mov	ebx, eax
  402609: 31 c0                        	xor	eax, eax
  40260b: 85 db                        	test	ebx, ebx
  40260d: 78 4c                        	js	0x40265b <get_local_ip+0x6b>
  40260f: 48 89 e2                     	mov	rdx, rsp
  402612: be 15 89 00 00               	mov	esi, 0x8915
  402617: 89 df                        	mov	edi, ebx
  402619: 48 c7 44 24 10 00 00 00 00   	mov	qword ptr [rsp + 0x10], 0x0
  402622: 48 c7 44 24 18 00 00 00 00   	mov	qword ptr [rsp + 0x18], 0x0
  40262b: 48 89 e5                     	mov	rbp, rsp
  40262e: 48 c7 44 24 20 00 00 00 00   	mov	qword ptr [rsp + 0x20], 0x0
  402637: 48 c7 04 24 65 74 68 30      	mov	qword ptr [rsp], 0x30687465
  40263f: 48 c7 44 24 08 00 00 00 00   	mov	qword ptr [rsp + 0x8], 0x0
  402648: e8 63 4b 00 00               	call	0x4071b0 <ioctl>
  40264d: 85 c0                        	test	eax, eax
  40264f: 78 11                        	js	0x402662 <get_local_ip+0x72>
  402651: 89 df                        	mov	edi, ebx
  402653: e8 e6 2c 00 00               	call	0x40533e <close>
  402658: 8b 45 14                     	mov	eax, dword ptr [rbp + 0x14]
  40265b: 48 83 c4 38                  	add	rsp, 0x38
  40265f: 5b                           	pop	rbx
  402660: 5d                           	pop	rbp
  402661: c3                           	ret
  402662: 48 bf 77 6c 61 6e 30 00 00 00	movabs	rdi, 0x306e616c77
  40266c: 31 c0                        	xor	eax, eax
  40266e: 48 89 e2                     	mov	rdx, rsp
  402671: 48 89 3c 24                  	mov	qword ptr [rsp], rdi
  402675: be 15 89 00 00               	mov	esi, 0x8915
  40267a: 89 df                        	mov	edi, ebx
  40267c: 48 c7 44 24 08 00 00 00 00   	mov	qword ptr [rsp + 0x8], 0x0
  402685: e8 26 4b 00 00               	call	0x4071b0 <ioctl>
  40268a: 85 c0                        	test	eax, eax
  40268c: 79 c3                        	jns	0x402651 <get_local_ip+0x61>
  40268e: 48 be 65 6e 73 33 33 00 00 00	movabs	rsi, 0x3333736e65
  402698: 31 c0                        	xor	eax, eax
  40269a: 48 89 e2                     	mov	rdx, rsp
  40269d: 48 89 34 24                  	mov	qword ptr [rsp], rsi
  4026a1: 89 df                        	mov	edi, ebx
  4026a3: be 15 89 00 00               	mov	esi, 0x8915
  4026a8: 48 c7 44 24 08 00 00 00 00   	mov	qword ptr [rsp + 0x8], 0x0
  4026b1: e8 fa 4a 00 00               	call	0x4071b0 <ioctl>
  4026b6: 85 c0                        	test	eax, eax
  4026b8: 79 97                        	jns	0x402651 <get_local_ip+0x61>
  4026ba: 89 df                        	mov	edi, ebx
  4026bc: e8 7d 2c 00 00               	call	0x40533e <close>
  4026c1: bf b0 50 41 00               	mov	edi, 0x4150b0
  4026c6: e8 f9 7f 00 00               	call	0x40a6c4 <inet_addr>
  4026cb: eb 8e                        	jmp	0x40265b <get_local_ip+0x6b>
  4026cd: 66 66 90                     	nop
