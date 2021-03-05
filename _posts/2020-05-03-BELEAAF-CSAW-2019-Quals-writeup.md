---
layout: single
title:  "BELEAAF (CSAW-2019-Quals) writeup" 
date:   2020-05-03 16:06:50 +0100
categories: CTF
toc: true
toc_sticky: true
toc_icon: "cog"
---
# Introduction
_Unicorn is a lightweight multi-platform, multi-architecture CPU emulator framework._ 

## Unicorn Framework
_Unicorn framework_ is a CPU emulator: it allows to emulate native code for 
various architectures (like _arm, arm64, M68K,  mips, sparc, x86, x86_64_) "watching" the 
status of the emulation for each instruction (like registers, memory, etc). 

The [official site](https://www.unicorn-engine.org/docs/) contains all the instructions for the installation.

# Challenge BELEAAF - CSAW-2019-Quals
I think that it's easier to understand a new framework using it instead of only reading about it,
so I will explain how I used Unicorn to solve the CSAW-2019-Quals CTF ([download here](https://github.com/osirislab/CSAW-CTF-2019-Quals/tree/master/rev/beleaf))

## Preliminary analysis
This challenge is the usual _reverse_ CTF, we can start in the usual way.

```bash
$ file beleaf
beleaf: ELF 64-bit LSB pie executable, x86-64, 
    version 1 (SYSV), dynamically linked,
    interpreter /lib64/ld-linux-x86-64.so.2,
    for GNU/Linux 3.2.0, 
    BuildID[sha1]=6d305eed7c9bebbaa60b67403a6c6f2b36de3ca4,
    stripped
$ ./beleaf
Enter the flag
>>> aaaa
Incorrect!
```
As we can see, we need to enter a password. We will solve the ctf with _unicorn_ but we need to 
understand _what_ emulate.

We can open this binary with a generic disassembler.

{% include figure image_path="/assets/images/beleaaf/main_function.png" caption="`main` function" %}

We can split the `main` function into three different "sections":
- reading the password from `stdin` (yellow);
- calculate the password length (gray);
- comparing the length with 32 (red). 

If our input is shorter (or equals) to 32, the binary will exit. Otherwise, there is a `jump` inside
the following loop.

{% include figure image_path="/assets/images/beleaaf/loop.png" caption="`main`: checking loop" %}

We can easily detect the basic blocks of the loop. In the beginning, `0` is assigned to a variable
(I called it _counter_), then we have the length check. It follows the body of the loop and the increments of the _counter_.

The _CFG_ highlights another piece of information. This loop has two exit points:
- when _counter_ is greater than our string;
- at the end of body loop.

{% include figure image_path="/assets/images/beleaaf/exit.png" caption="`main`: loop termination" %}

Zooming the second way of exit, it is easy to notice that there is a checking between the _quadword_ stored in `var_a0_1` (`rbp-0x98`) against `rax`: 
if they are different, the binary will print _"Incorrect!"_ and exit.
## Body loop
To solve the challenge, we need that `rax` is equal to the stored value. So we need to understand what 
data are in that memory (and register). 
{% include figure image_path="/assets/images/beleaaf/body_loop.png" caption="`main`: body loop" %}

This is the _body loop_ (I already renamed some variables and the function name). This code is 
easy to reverse: we take the byte of the inserted string and it is passed as an argument to the 
function _transfrom\_input_. 

The returned value is stored in `var_a0_1`. Then, a _load_ operation takes a value from the memory (_encrypt\_data_) and moves it to `rax`. At the end, we can see the _compare_ instruction.

{% include figure image_path="/assets/images/beleaaf/body_head.png" caption="`main`: body head" %}
{% include figure image_path="/assets/images/beleaaf/body_end.png" caption="`main`: body increment" %}

Now that we have disassembled the loop, we can _rewrite_ it in this pseudo-code:
```c
  int counter;
  char a;
  for(counter=0;counter<strlen(input_data);counter++){
    a=input_data[counter];
    if(encrypt_data[counter] != (long) transform_input(a)){
        puts("Incorrect!");
        exit(1);
        }
    }
```
In other words, the challenge takes every char, transform it, and compares it with a stored value.
This is why we can't simply read the _encrypt\_data_ area.

## Traditional way
So we need to reverse this function.
{% include figure image_path="/assets/images/beleaaf/transform_function.png" caption="`transform_input`" %}

# Unicorn

Although the function is not much complex, I wanted to try a different technique. 
Also, the CTF has a vulnerability (I don't know if that was intended or not) that allows to solve it
using brute-force.

As we already see, the password should be longer than 33 chars but perform a brute-force attack against
so many characters is unfeasible. 

But this challenge has a vulnerability that allows us to “check” one character at a time instead of 33 altogether. In this case, the brute-force is very quickly.

## GEF

_GEF_ is a _"is a kick-ass set of commands for X86, ARM, MIPS, PowerPC and SPARC to make GDB cool again for exploit dev"_
and I think that is great because it is single python script that allows us to avoid complex installation.

We need a debugger in order to check the result of the _transfromt_input_ function: we can set a breakpoint
at 0x00000950.

```bash
$ gdb beleaf
gef➤ pie breakpoint *0x00000950
gef➤ pie run
```
(Note: these commands allows us to insert a _pie_ breakpoint so we can insert directly the address
from the disassembler and _GEF_ will relocate the breakpoint using the _real address_).

```bash
Enter the flag
>>> aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

Breakpoint 1, 0x0000555555554950 in ?? ()
[+] base address 0x555555554000
────────────────────────registers ────
$rax   : 0x61
$rbx   : 0x00005555555549e0  →   push r15
$rcx   : 0x10
$rdx   : 0x00007fffffffe0b0  →  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
$rsp   : 0x00007fffffffe080  →  0x00007fffffffe238  →  0x00007fffffffe5ed  →  "/home/andrea/Documents/CTF/CTF/CSAW-CTF-2019-Quals[...]"
$rbp   : 0x00007fffffffe140  →  0x0000000000000000
$rsi   : 0xa
$rdi   : 0x61
$rip   : 0x0000555555554950  →   call 0x5555555547fa
$r8    : 0xffffffffffffff80
$r9    : 0x40
$r10   : 0x22
$r11   : 0x246
$r12   : 0x00005555555546f0  →   xor ebp, ebp
$r13   : 0x00007fffffffe230  →  0x0000000000000001
$r14   : 0x0
$r15   : 0x0
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000

────────────────────────stack ────
0x00007fffffffe080│+0x0000: 0x00007fffffffe238  →  0x00007fffffffe5ed  →  "/home/andrea/Documents/CTF/CTF/CSAW-CTF-2019-Quals[...]"      ← $rsp
0x00007fffffffe088│+0x0008: 0x0000000100000100
0x00007fffffffe090│+0x0010: 0x0000000000000000
0x00007fffffffe098│+0x0018: 0x0000000000000000
0x00007fffffffe0a0│+0x0020: 0x0000000000000022 ("""?)
0x00007fffffffe0a8│+0x0028: 0x0000000000000000
0x00007fffffffe0b0│+0x0030: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"         ← $rdx
0x00007fffffffe0b8│+0x0038: "aaaaaaaaaaaaaaaaaaaaaaaaaa"
────────────────────────code:x86:64 ────
   0x555555554948                  movzx  eax, BYTE PTR [rax]
   0x55555555494b                  movsx  eax, al
   0x55555555494e                  mov    edi, eax
 → 0x555555554950                  call   0x5555555547fa
   ↳  0x5555555547fa                  push   rbp
      0x5555555547fb                  mov    rbp, rsp
      0x5555555547fe                  mov    eax, edi
      0x555555554800                  mov    BYTE PTR [rbp-0x14], al
      0x555555554803                  mov    QWORD PTR [rbp-0x8], 0x0
      0x55555555480b                  jmp    0x555555554890
────────────────────────arguments (guessed) ────
0x5555555547fa (
   $rdi = 0x0000000000000061,
   $rsi = 0x000000000000000a,
   $rdx = 0x00007fffffffe0b0 → "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)
────────────────────────threads ────
[#0] Id 1, Name: "beleaf", stopped 0x555555554950 in ?? (), reason: BREAKPOINT
────────────────────────trace ────
[#0] 0x555555554950 → call 0x5555555547fa
[#1] 0x7ffff7df6023 → __libc_start_main()
[#2] 0x55555555471a → hlt
────────────────────────────────
gef➤
```
Now, we have various possibility:
- use GDB in order to see the result of the function and check if that is correct;
- use some _DBI_ (e.g. Frida) and perform and instrumentation
- emulate the function
- etc

We will use _unicorn_ in order to emulate the _transfrom_input_ function and retrieve the flag.

To emulate the function, it is necessary to create all the memory areas (and this can be boring) but _GEF_ creates for us the “environment” for emulating the function.

```bash
gef➤ emulate -n 1
emulated code................
.....
.........
================ Final registers ======
$cs     = 0x000033  $ds     = 0x000000
$eflags = 0x000246  $es     = 0x000000
$fs     = 0x000000  $gs     = 0x000000
$r10    = 0x000022  $r11    = 0x000246
$r12    = 0x5555555546f0      $r13    = 0x7fffffffe230
$r14    = 0x000000            $r15    = 0x000000
$r8     = 0xffffffffffffff80  $r9     = 0x000040
$rax    = 0x000011   $rbp    = 0x7fffffffe140 
$rbx    = 0x5555555549e0 $rcx    = 0x000044
$rdi    = 0x000061  $rdx    = 0x000061
$rip    = 0x555555554955 $rsi    = 0x00000a
$rsp    = 0x7fffffffe080  $ss     = 0x00002b
```
We have emulated the function and we can see that the returned value (`$rax` register) is 0x11 (for _a_).

Now, we can create a script that performs the brute-force and retrieve the flag.

We can emulate so much code as we want, so we can reach the _compare_ instruction. At that point, we have 
in memory the computed value and the expected value in order to check the equality.

## Unicorn script
We can use agains _GEF_ in order to create an executable script.

```bash
gef➤  emulate -n 6 -s -o /tmp/csaw.py
[+] Unicorn script generated as '/tmp/csaw.py'
gef➤
```
The options are:
 - -`n 6` : execute 6 instruction (reaching the _CMP_)
 - `-s` do not execute the script
 - `-o <path>` write the script

We have a script that can be used to emulate the code without using _gdb_. 

```python
uc = reset()
emulate(uc, 0x555555554950, 0x55555555497d)
```

So, the script calls only the `reset` and `emulate` function.

```python
def emulate(emu, start_addr, end_addr):
    print("========================= Initial registers =========================")
    print_regs(emu, registers)
    try:
        print("========================= Starting emulation =========================")
        emu.emu_start(start_addr, end_addr)
    except Exception as e:
        emu.emu_stop()
        print("========================= Emulation failed =========================")
        print("[!] Error: {}".format(e))
    print("========================= Final registers =========================")
    print_regs(emu, registers)
    return
```
`emulate` starts the emulation. `reset` instead is interesting.

```python
def reset():
    emu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64 + unicorn.UC_MODE_LITTLE_ENDIAN)
    emu.mem_map(SEGMENT_FS_ADDR-0x1000, 0x3000)
    set_fs(emu, SEGMENT_FS_ADDR)
    set_gs(emu, SEGMENT_GS_ADDR)
    emu.reg_write(unicorn.x86_const.UC_X86_REG_RAX, 0x61)
    emu.reg_write(unicorn.x86_const.UC_X86_REG_RBX, 0x5555555549e0)
    emu.reg_write(unicorn.x86_const.UC_X86_REG_RCX, 0x10)
    emu.reg_write(unicorn.x86_const.UC_X86_REG_RDX, 0x7fffffffe0b0)
    emu.reg_write(unicorn.x86_const.UC_X86_REG_RSP, 0x7fffffffe080)
    emu.reg_write(unicorn.x86_const.UC_X86_REG_RBP, 0x7fffffffe140)
    emu.reg_write(unicorn.x86_const.UC_X86_REG_RSI, 0xa)
    emu.reg_write(unicorn.x86_const.UC_X86_REG_RDI, 0x61)
    emu.reg_write(unicorn.x86_const.UC_X86_REG_RIP, 0x555555554950)
    emu.reg_write(unicorn.x86_const.UC_X86_REG_R8, 0xffffffffffffff80)
    emu.reg_write(unicorn.x86_const.UC_X86_REG_R9, 0x40)
    emu.reg_write(unicorn.x86_const.UC_X86_REG_R10, 0x22)
    emu.reg_write(unicorn.x86_const.UC_X86_REG_R11, 0x246)
    emu.reg_write(unicorn.x86_const.UC_X86_REG_R12, 0x5555555546f0)
    emu.reg_write(unicorn.x86_const.UC_X86_REG_R13, 0x7fffffffe230)
    emu.reg_write(unicorn.x86_const.UC_X86_REG_R14, 0x0)
    emu.reg_write(unicorn.x86_const.UC_X86_REG_R15, 0x0)
    emu.reg_write(unicorn.x86_const.UC_X86_REG_EFLAGS, 0x202)
    emu.reg_write(unicorn.x86_const.UC_X86_REG_CS, 0x33)
    emu.reg_write(unicorn.x86_const.UC_X86_REG_SS, 0x2b)
    emu.reg_write(unicorn.x86_const.UC_X86_REG_DS, 0x0)
    emu.reg_write(unicorn.x86_const.UC_X86_REG_ES, 0x0)
    emu.reg_write(unicorn.x86_const.UC_X86_REG_FS, 0x0)
    emu.reg_write(unicorn.x86_const.UC_X86_REG_GS, 0x0)
    #Mapping /home/andrea/Documents/CTF/CTF/CSAW-CTF-2019-Quals/beleaf: 0x555555554000-0x555555555000
    emu.mem_map(0x555555554000, 0x1000, 0o5)emu.mem_write(0x555555554000, open('/tmp/gef-beleaf-0x555555554000.raw', 'rb').read())
    #Mapping /home/andrea/Documents/CTF/CTF/CSAW-CTF-2019-Quals/beleaf: 0x555555754000-0x555555755000
    emu.mem_map(0x555555754000, 0x1000, 0o1)emu.mem_write(0x555555754000, open('/tmp/gef-beleaf-0x555555754000.raw', 'rb').read())
    #Mapping /home/andrea/Documents/CTF/CTF/CSAW-CTF-2019-Quals/beleaf: 0x555555755000-0x555555756000
    emu.mem_map(0x555555755000, 0x1000, 0o3)emu.mem_write(0x555555755000, open('/tmp/gef-beleaf-0x555555755000.raw', 'rb').read())
    #Mapping [heap]: 0x555555756000-0x555555777000
    emu.mem_map(0x555555756000, 0x21000, 0o3)emu.mem_write(0x555555756000, open('/tmp/gef-beleaf-0x555555756000.raw', 'rb').read())
```
This function creates the environment for the execution, we can modify it to brute-force the password.

We need that the `rdi` register (the argument of the function `transform_input`) is a parameter and
not hardcoded.

```python
def reset(char):
......
    emu.reg_write(unicorn.x86_const.UC_X86_REG_RDI, char)
......
......
#Main:
char = 0x20
while char < 0x7f:
    uc = reset(char)
    if(emulate(uc, 0x555555554950, 0x55555555497d)):
        print("Char "+chr(char)+" is correct!")
        break
    char += 1
```
I already prepared the _main_ for checking the values. So, in order to compare the value we can 
check `eflags` or directly the memory.

```python
def emulate(emu, start_addr, end_addr):
    try:
        emu.emu_start(start_addr, end_addr)
    except Exception as e:
        emu.emu_stop()
        return False
    address = emu.reg_read(registers['$rbp']) - 0x98;
    to_find = emu.reg_read(registers["$rax"])
    computed = struct.unpack('<q',emu.mem_read(address, 8))[0]
    #print(hex(computed) + ' == '+hex(to_find)+' ?')
    if computed == to_find:
        return True
    return False
```
Now, we need to emulate the _counter_ of the loop (now we are only checking for the first char).

We need to add another paramenter to `reset` (the counter).

```python
def reset(char, counter):
    .......
    emu.reg_write(unicorn.x86_const.UC_X86_REG_RDI, char)
    .......
    # $RBP -0xa8
    emu.mem_write(0x7fffffffe110-0xa8, counter)
    return emu
.......
pos  = 0
char = 0x20
while char < 0x7f:
    uc = reset(char, struct.pack('<I',pos))
    # Ovviamente voi avrete altri indirizzi
    if(emulate(uc, 0x555555554950, 0x55555555497d)):
        print("Char "+chr(char)+" is correct!")
        char = 0x20
        pos += 1
    char += 1
.......
```
Now we can simply execute the script and the flag will be crack!

[Here](https://github.com/c3r34lk1ll3r/CTF/tree/master/CSAW-CTF-2019-Quals/beleaf) you may find  the exploit code.

