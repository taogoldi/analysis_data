
/Users/taogoldi/Projects/Malware/Mirai/input/d40cf9c95dcedf4f19e4a5f5bb744c8e98af87eb5703c850e6fda3b613668c28.elf:	file format elf64-x86-64

Disassembly of section .text:

0000000000400730 <killer_thread_func>:
  400730: 48 83 ec 08                  	sub	rsp, 0x8
  400734: bf 3f 4a 41 00               	mov	edi, 0x414a3f
  400739: e8 0e 77 00 00               	call	0x407e4c <puts>
  40073e: 66 90                        	nop
  400740: e8 cb 02 00 00               	call	0x400a10 <disable_infection_tools>
  400745: e8 16 06 00 00               	call	0x400d60 <scan_and_kill>
  40074a: bf 90 d0 03 00               	mov	edi, 0x3d090
  40074f: e8 b0 bf 00 00               	call	0x40c704 <usleep>
  400754: eb ea                        	jmp	0x400740 <killer_thread_func+0x10>
  400756: 90                           	nop
  400757: 90                           	nop
  400758: 90                           	nop
  400759: 90                           	nop
  40075a: 90                           	nop
  40075b: 90                           	nop
  40075c: 90                           	nop
  40075d: 90                           	nop
  40075e: 90                           	nop
  40075f: 90                           	nop
