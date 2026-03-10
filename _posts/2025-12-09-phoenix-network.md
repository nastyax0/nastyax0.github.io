---
layout: phoenix
title: "Welcome to Jekyll!"
date: 2025-04-06 12:26:40 +0530
categories: jekyll update
---

---

# Phoenix:

**Phoenix** is the first part of the binary exploitation learning series by [Exploit Education](https://exploit.education/).

---

## Getting Started

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

# Net-Zero

**Challenge**: [Phoenix/Net-Zero](https://exploit.education/phoenix/net-zero/)

**Goal**: Send back a server-generated 32-bit integer in **little-endian binary form**.

---

## Starting the Challenge

```c
user@phoenix-amd64:/opt/phoenix/amd64$ nc 127.0.0.1 64000
Welcome to phoenix/net-zero, brought to you by https://exploit.education
Please send '1575617602' as a little endian, 32bit integer.
hello
Close - you sent 1819043176 instead
```

The server clearly tells us what it expects, but the important part is **how** it expects the data — not as ASCII, but as raw binary.

Typing `hello` sends ASCII bytes, which are then interpreted as a 32-bit integer, resulting in a completely different value.

---

## Source Code Analysis

```c
uint32_t i, j;

getrandom((void *)&i, sizeof(i), 0);
printf("Please send '%u' as a little endian, 32bit integer.\n", i);

read(0, (void *)&j, sizeof(j));

if (i == j) {
    printf("You have successfully passed this level, well done!\n");
}
```

Key points:

* `i` is a **random uint32_t**
* the value of `i` is printed **only for our convenience**
* input is read using:

  ```c
  read(0, (void *)&j, sizeof(j))
  ```

* this means:

  * exactly **4 bytes** are read
  * those bytes are interpreted directly as a `uint32_t`
  * **no string parsing is involved**

---

## Network Context

Although a local binary exists, the intended solution is to solve this over the network.

To verify the service:

```bash
ss -ltnp | grep 64000
```

Connection:

```bash
nc 127.0.0.1 64000
```

This confirms we are interacting with a raw TCP service, not a line-based protocol.

---

## Strategy

1. Connect to the service
2. Read the banner
3. Read the line containing the integer
4. Extract the number
5. Pack it as a **little-endian uint32**
6. Send exactly **4 bytes**
7. Done

---

## Exploit

```python
import socket
import time
import struct


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("127.0.0.1", 64000))


print(s.recv(100).decode())
time.sleep(0.3)
num_msg = s.recv(100).decode()
print(num_msg)


num = int(msg.split("'")[1])
print(num)


bytes = struct.pack("<I", num)
s.sendall(bytes)


response = s.recv(1024)
print(response.decode(errors="ignore"))
```

---

## Result

![passed](/assets/phoenix-heap/net-zero.png)

---
<div class="image-row">
  <img src="/assets/phoenix/section.png" class="my-special-class" alt="Elongated Image">
  <img src="/assets/phoenix/section.png" class="my-special-class" alt="Elongated Image">
  <img src="/assets/phoenix/section.png" class="my-special-class" alt="Elongated Image">
</div>

---

# Net-One

**Challenge**: [Phoenix/Net-One](https://exploit.education/phoenix/net-one/)

**Goal**: Send back the correct unsigned decimal value of a server-generated 32-bit integer.

---

## Starting the Challenge

```c
user@phoenix-amd64:/opt/phoenix/amd64$ ./net-one
Welcome to phoenix/net-one, brought to you by https://exploit.education
D���okay lol
Close, you sent "okay lol", and we wanted "3637375812"
user@phoenix-amd64:/opt/phoenix/amd64$
```

At first glance this looks weird: random garbage printed before the prompt.
That’s not memory corruption or UB. It’s intentional.

The program is writing **raw binary bytes** directly to stdout. Terminal is just trying (and failing) to render them as ASCII.

---

## Code Walkthrough

The important part is here:

```c
uint32_t i;

getrandom((void *)&i, sizeof(i), 0);
write(1, &i, sizeof(i));
```

* `i` is a **32-bit unsigned integer**
* generated using `getrandom()`
* written directly using `write()`
* **no formatting**, no conversion, just 4 raw bytes

Later, the comparison logic:

```c
sprintf(fub, "%u", i);
if (strcmp(fub, buf) == 0)
```

This tells us exactly what the program expects:

* convert `i` → unsigned decimal string
* compare it against our input

So the task is **not exploitation**, but **correctly parsing a binary protocol**.

---

## What’s Actually Going On

* The server sends:

  * a banner (ASCII)
  * followed by **4 bytes of binary data**
* Those 4 bytes represent a `uint32_t` in **little-endian**
* We must:

  1. read exactly 4 bytes
  2. interpret them correctly
  3. send back the decimal ASCII representation

Trying to treat the received bytes as text or splitting strings will break sooner or later.

---

## Logic

1. Connect to the service
2. Read and ignore the banner
3. `recv(4)` nothing more, nothing less
4. `struct.unpack("<I", data)`
5. Send back `str(num) + "\\n"`

```python
import socket
import time
import struct

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("127.0.0.1", 64000))

print(s.recv(100).decode())
time.sleep(0.3)
num_msg = s.recv(100).decode()
print(num_msg)

num_m = int(num_msg.split("'")[1])
num = int(num_m)
#print(num)

bytes = struct.pack("<I", num)
s.sendall(bytes)

response = s.recv(1024)
print(response.decode(errors="ignore"))
```

### Why this works

* `recv(4)` matches `write(1, &i, sizeof(i))`
* `<I` = little-endian unsigned 32-bit integer
* server compares **strings**, not raw bytes

---

## Result

![win](/assets/phoenix-heap/net-one.png)

---
<div class="image-row">
  <img src="/assets/phoenix/section.png" class="my-special-class" alt="Elongated Image">
  <img src="/assets/phoenix/section.png" class="my-special-class" alt="Elongated Image">
  <img src="/assets/phoenix/section.png" class="my-special-class" alt="Elongated Image">
</div>

---

# Net-Two

**Challenge**: [Phoenix/Net-Two](https://exploit.education/phoenix/net-two/)

**Goal**: Correctly reconstruct and send back a computed `unsigned long` value based on binary data received from the server.

---

## Starting the Challenge

Run the binary:

![initial](/assets/phoenix-heap/net-three.png)

The program immediately hints at an architecture-specific detail:

> `For this level, sizeof(long) == 8, keep that in mind :)`

On amd64, `sizeof(long) == 8`, which is critical for understanding both the loop and the network protocol.

---

## Source Code Analysis

```c
unsigned long quad[sizeof(long)], result, wanted;
```

Since `sizeof(long) == 8`, this becomes:

```c
unsigned long quad[8];
```

So:

* `quad` contains **8 elements**
* each element is an `unsigned long` (8 bytes)
* total random data size = **64 bytes**

### Random Generation

```c
getrandom((void *)&quad, sizeof(quad), 0);
```

This fills all 8 `unsigned long` values with random data.

---

### Server Output Logic

```c
result = 0;
for (i = 0; i < sizeof(long); i++) {
  result += quad[i];
  write(1, (void *)&quad[i], sizeof(long));
}
```

Important observations:

* The loop runs **8 times**
* Each iteration:

  * adds `quad[i]` to `result`
  * sends **8 raw bytes** (`quad[i]`) to the client

* Total data sent:

  * **8 × 8 = 64 bytes**

---

### Input Expectation

```c
read(0, (void *)&wanted, sizeof(long));
```

* Server reads **exactly 8 bytes**
* Interprets them as an `unsigned long`

So our task is:

> **Sum all received `unsigned long` values and send the result back as a raw 8-byte value.**

---

## Strategy

1. Connect to the service
2. Read and ignore the banner
3. Receive **8 chunks of 8 bytes**
4. Interpret each chunk as `uint64_t`
5. Sum all values
6. Apply 64-bit wraparound (unsigned overflow)
7. Send the result as a **little-endian unsigned long**

---

## Logic

```python
import socket
import time
import struct


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("127.0.0.1", 64002))

print(s.recv(512).decode())

time.sleep(0.3)

print(s.recv(24))

data = b''
i = 0
num_msg = 0
while i < 8:
        #print(len(data))
        data += s.recv(8)
        i = i+1

num_msg = struct.unpack('<8Q', data)

i = 0
result = 0
for v in num_msg:
    result = (result + v) & 0xFFFFFFFFFFFFFFFF

print(result)

#result = sum(num_msg)

s.sendall(struct.pack('<Q', result))

print(s.recv(400))
```

---

## Result

![](/assets/phoenix-heap/net.png)

<div class="image-row">
  <img src="/assets/phoenix/section.png" class="my-special-class" alt="Elongated Image">
  <img src="/assets/phoenix/section.png" class="my-special-class" alt="Elongated Image">
  <img src="/assets/phoenix/section.png" class="my-special-class" alt="Elongated Image">
</div>