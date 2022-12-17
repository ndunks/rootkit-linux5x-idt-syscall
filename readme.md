# Getting `sys_call_table` on hardened Kernel

    Get linux syscall table from Interupt Descriptor Table (IDT) on Kernel Linux 5.6.3 x86_64

Referrences: 

- https://github.com/linsec/hook-syscall
- https://filippo.io/linux-sysca// 252	i386	exit_group		sys_exit_group			__ia32_sys_exit_groupll-table/
- https://infosecwriteups.com/linux-kernel-module-rootkit-syscall-table-hijacking-8f1bc0bd099c
- https://foxtrot-sq.medium.com/linux-rootkits-multiple-ways-to-hook-syscall-s-7001cc02a1e6



## Kernel 5.6 Vanilla

This kernel is have debuging symbols
IDT address fffffe0000000000  4095
Syscall Gates ffffffff81a01630
entry_INT80_compat -> ffffffff81a01630

0xffffffff81e001e0 <sys_call_table>

in GDB:
- `set $rax = 39` (syscall_getPID)
- `j entry_INT80_compat` (https://elixir.bootlin.com/linux/v5.6.3/source/arch/x86/entry/entry_64_compat.S#L342)
- si ...

### Call function
```
<entry_INT80_compat+125>
    0xffffffff81a016ad <+125>:   e8 fe 04 60 ff  call   0xffffffff81001bb0 <do_int80_syscall_32>
    0xffffffff81a016b2 <+130>:   e9 78 f3 ff ff  jmp    0xffffffff81a00a2f <common_interrupt+47>
```
[Call](https://www.felixcloutier.com/x86/call) Relative Address of $RIP:

|    e8   | fe 04 60 ff  |
|---------|--------------|
| OP:CALL |    REL32     |

Target address is relative from 0xffffffff:81a016b2 (add 32 bit):
    81a016b2 + 0xff6004fe = 0x81001bb0  or 0xffffffff81001bb0


### Syscall table array access
```
<do_int80_syscall_32+57>
    0xffffffff81001be6 <+54>:    48 89 ef        mov    %rbp,%rdi
    0xffffffff81001be9 <+57>:    48 8b 04 c5 a0 11 e0 81 mov    -0x7e1fee60(,%rax,8),%rax
    0xffffffff81001bf1 <+65>:    e8 5a f2 bf 00  call   0xffffffff81c00e50 <__x86_indirect_thunk_rax>
```

```
48 8b 04 c5 a0 11 e0 81: 
AT&T : mov    -0x7e1fee60(,%rax,8),%rax  # QWORD PTR
INTEL: mov     rax,     QWORD PTR [rax*8-0x7e1fee60]


|  48  |   8B   |    04: 00000100      |    c5: 11000101      | a0 11 e0 81 |
|------|--------|----------------------|----------------------|-------------|
|PREFIX| OP:MOV |     MOD-R/M          |      MOD-R/M         |   ADDR32    |
|------|--------|----------------------|----------------------|-------------|
|               |  00 |    000   | 100 |  11 |    000   | 101 |             |
|               | MOD | REG: RAX | R/M | MOD | REG: RAX | R/M |             |
```

- https://wiki.osdev.org/X86-64_Instruction_Encoding#REX_prefix

``` asm


488B04C5A011E081 # mov    rax,QWORD PTR [rax*8-0x7e1fee60]
488B0CC5A011E081 # mov    rcx,QWORD PTR [rax*8-0x7e1fee60]
488B14C5A011E081 # mov    rdx,QWORD PTR [rax*8-0x7e1fee60]

488B04C5A011E081 # mov    rax,QWORD PTR [rax*8-0x7e1fee60]
488B04CDA011E081 # mov    rax,QWORD PTR [rcx*8-0x7e1fee60]

\x48\x8b\x04\xc5\xa0\x11\xe0\x81
488b04c5a011e081
81e011a0c5048b48

```

```
=> 0xffffffff81a01630 <+0>:     66 66 90        data16 xchg %ax,%ax
   0xffffffff81a01633 <+3>:     0f 01 f8        swapgs 
   0xffffffff81a01636 <+6>:     89 c0   mov    %eax,%eax
   0xffffffff81a01638 <+8>:     50      push   %rax
   0xffffffff81a01639 <+9>:     57      push   %rdi
   0xffffffff81a0163a <+10>:    eb 12   jmp    0xffffffff81a0164e <entry_INT80_compat+30>
   0xffffffff81a0163c <+12>:    0f 20 df        mov    %cr3,%rdi
   0xffffffff81a0163f <+15>:    66 66 90        data16 xchg %ax,%ax
   0xffffffff81a01642 <+18>:    66 90   xchg   %ax,%ax
   0xffffffff81a01644 <+20>:    48 81 e7 ff e7 ff ff    and    $0xffffffffffffe7ff,%rdi
   0xffffffff81a0164b <+27>:    0f 22 df        mov    %rdi,%cr3
   0xffffffff81a0164e <+30>:    48 89 e7        mov    %rsp,%rdi
   0xffffffff81a01651 <+33>:    90      nop
   0xffffffff81a01652 <+34>:    90      nop
   0xffffffff81a01653 <+35>:    65 48 8b 24 25 0c 60 00 00      mov    %gs:0x600c,%rsp
   0xffffffff81a0165c <+44>:    ff 77 30        push   0x30(%rdi)
   0xffffffff81a0165f <+47>:    ff 77 28        push   0x28(%rdi)
   0xffffffff81a01662 <+50>:    ff 77 20        push   0x20(%rdi)
   0xffffffff81a01665 <+53>:    ff 77 18        push   0x18(%rdi)
   0xffffffff81a01668 <+56>:    ff 77 10        push   0x10(%rdi)
   0xffffffff81a0166b <+59>:    ff 77 08        push   0x8(%rdi)
   0xffffffff81a0166e <+62>:    ff 37   push   (%rdi)
   0xffffffff81a01670 <+64>:    56      push   %rsi
   0xffffffff81a01671 <+65>:    31 f6   xor    %esi,%esi
   0xffffffff81a01673 <+67>:    52      push   %rdx
   0xffffffff81a01674 <+68>:    31 d2   xor    %edx,%edx
   0xffffffff81a01676 <+70>:    51      push   %rcx
   0xffffffff81a01677 <+71>:    31 c9   xor    %ecx,%ecx
   0xffffffff81a01679 <+73>:    6a da   push   $0xffffffffffffffda
   0xffffffff81a0167b <+75>:    41 50   push   %r8
   0xffffffff81a0167d <+77>:    45 31 c0        xor    %r8d,%r8d
   0xffffffff81a01680 <+80>:    41 51   push   %r9
   0xffffffff81a01682 <+82>:    45 31 c9        xor    %r9d,%r9d
   0xffffffff81a01685 <+85>:    41 52   push   %r10
   0xffffffff81a01687 <+87>:    45 31 d2        xor    %r10d,%r10d
   0xffffffff81a0168a <+90>:    41 53   push   %r11
   0xffffffff81a0168c <+92>:    45 31 db        xor    %r11d,%r11d
   0xffffffff81a0168f <+95>:    53      push   %rbx
   0xffffffff81a01690 <+96>:    31 db   xor    %ebx,%ebx
   0xffffffff81a01692 <+98>:    55      push   %rbp
   0xffffffff81a01693 <+99>:    31 ed   xor    %ebp,%ebp
   0xffffffff81a01695 <+101>:   41 54   push   %r12
   0xffffffff81a01697 <+103>:   45 31 e4        xor    %r12d,%r12d
   0xffffffff81a0169a <+106>:   41 55   push   %r13
   0xffffffff81a0169c <+108>:   45 31 ed        xor    %r13d,%r13d
   0xffffffff81a0169f <+111>:   41 56   push   %r14
   0xffffffff81a016a1 <+113>:   45 31 f6        xor    %r14d,%r14d
   0xffffffff81a016a4 <+116>:   41 57   push   %r15
   0xffffffff81a016a6 <+118>:   45 31 ff        xor    %r15d,%r15d
   0xffffffff81a016a9 <+121>:   fc      cld    
   0xffffffff81a016aa <+122>:   48 89 e7        mov    %rsp,%rdi
   0xffffffff81a016ad <+125>:   e8 fe 04 60 ff  call   0xffffffff81001bb0 <do_int80_syscall_32>
   0xffffffff81a016b2 <+130>:   e9 78 f3 ff ff  jmp    0xffffffff81a00a2f <common_interrupt+47>


Dump of assembler code for function do_int80_syscall_32:
   0xffffffff81001bb0 <+0>:     55      push   %rbp
   0xffffffff81001bb1 <+1>:     48 89 fd        mov    %rdi,%rbp
   0xffffffff81001bb4 <+4>:     fb      sti    
   0xffffffff81001bb5 <+5>:     65 48 8b 14 25 c0 7c 01 00      mov    %gs:0x17cc0,%rdx
   0xffffffff81001bbe <+14>:    48 8b 47 78     mov    0x78(%rdi),%rax
   0xffffffff81001bc2 <+18>:    83 4a 08 02     orl    $0x2,0x8(%rdx)
   0xffffffff81001bc6 <+22>:    48 8b 12        mov    (%rdx),%rdx
   0xffffffff81001bc9 <+25>:    f7 c2 c1 01 08 10       test   $0x100801c1,%edx
   0xffffffff81001bcf <+31>:    75 47   jne    0xffffffff81001c18 <do_int80_syscall_32+104>
   0xffffffff81001bd1 <+33>:    3d b6 01 00 00  cmp    $0x1b6,%eax
   0xffffffff81001bd6 <+38>:    77 22   ja     0xffffffff81001bfa <do_int80_syscall_32+74>
   0xffffffff81001bd8 <+40>:    89 c2   mov    %eax,%edx
   0xffffffff81001bda <+42>:    48 81 fa b7 01 00 00    cmp    $0x1b7,%rdx
   0xffffffff81001be1 <+49>:    48 19 d2        sbb    %rdx,%rdx
   0xffffffff81001be4 <+52>:    21 d0   and    %edx,%eax
   0xffffffff81001be6 <+54>:    48 89 ef        mov    %rbp,%rdi
   0xffffffff81001be9 <+57>:    48 8b 04 c5 a0 11 e0 81 mov    -0x7e1fee60(,%rax,8),%rax
   0xffffffff81001bf1 <+65>:    e8 5a f2 bf 00  call   0xffffffff81c00e50 <__x86_indirect_thunk_rax>
   0xffffffff81001bf6 <+70>:    48 89 45 50     mov    %rax,0x50(%rbp)
   0xffffffff81001bfa <+74>:    65 48 8b 04 25 c0 7c 01 00      mov    %gs:0x17cc0,%rax
   0xffffffff81001c03 <+83>:    48 8b 30        mov    (%rax),%rsi
   0xffffffff81001c06 <+86>:    f7 c6 91 00 00 10       test   $0x10000091,%esi
   0xffffffff81001c0c <+92>:    75 11   jne    0xffffffff81001c1f <do_int80_syscall_32+111>
   0xffffffff81001c0e <+94>:    fa      cli    
   0xffffffff81001c0f <+95>:    48 89 ef        mov    %rbp,%rdi
   0xffffffff81001c12 <+98>:    5d      pop    %rbp
   0xffffffff81001c13 <+99>:    e9 98 fd ff ff  jmp    0xffffffff810019b0 <prepare_exit_to_usermode>
   0xffffffff81001c18 <+104>:   e8 83 fa ff ff  call   0xffffffff810016a0 <syscall_trace_enter>
   0xffffffff81001c1d <+109>:   eb b2   jmp    0xffffffff81001bd1 <do_int80_syscall_32+33>
   0xffffffff81001c1f <+111>:   48 89 ef        mov    %rbp,%rdi
   0xffffffff81001c22 <+114>:   e8 b9 fc ff ff  call   0xffffffff810018e0 <syscall_slow_exit_work>
   0xffffffff81001c27 <+119>:   eb e5   jmp    0xffffffff81001c0e <do_int80_syscall_32+94>
End of assembler dump.

```