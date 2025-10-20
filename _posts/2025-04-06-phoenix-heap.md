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