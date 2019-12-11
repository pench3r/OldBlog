---
layout: post
title: "[reverse] 看雪2016ctf-第一题-solution"
categories: "ReverseEngineering"
---

### 0x00 题目分析 ###

该程序是使用MFC编写的，通过运行程序观察到输入password，点击OK会进行验证。因此是常规的破解题目，首先需要找到winproc这是破解的核心，如何找winproc，有如下思路：

- 在`DispatchMessage`处下条件断点(这里在最后输入完毕后，再切换到od下断点，然后TAB切换程序点击OK)，条件为调用参数的+4位置处是否为`0x202(WM_LBUTTONUP)`，然后跟进
- 在`od`中的`window`中找对应的按键，这里为`ok`，下消息断点，然后跟进
- 通过该模块中引用的`字符表`找出可能获取用户输入的API下断，这里为`GetWindowTextW`
- 关键字搜索，通过unicode中查看有成功信息的引用然后回溯，但是这个方法有点累

我这里使用的为第一种，直接通过`DispatchMessage`下断

### 0x01 寻找核心的算法 ###

这里在DispatchMessage断下后，f7步入函数后，然后配合text内存断点，F9断到`0x402120`,通过堆栈观察message ID是否为我们关心的事件

![ctf]({{ '/images/201808/kanxue2016_ctf_1_1.png' | prepend: site.baseurl }})

`0x111`对应`WM_COMMAND`表示有快捷键按下，这里对应我们的OK键

接着F8单步往后跟，就发现了createthread调用，观察参数，找到对应的`threadfunction`

![ctf]({{ '/images/201808/kanxue2016_ctf_1_2.png' | prepend: site.baseurl }})

接着我们在`0x4020e0`地址下断，然后这里直接F9运行(这里是猜测该地址可能为核心算法，因此通过这种方式直接进行尝试)发现直接断到了该地址，这里很大几率就为核心算法

![ctf]({{ '/images/201808/kanxue2016_ctf_1_3.png' | prepend: site.baseurl }})

这里有2个函数调用，对2个函数简单进行代码查看，得出结论第一个函数为我们最关心的核心算法，而第二个只是最后做了一下垃圾回收。

接下来我们开始分析关键算法`0x401cb0`

通过其他人的wp学习到获取算法的思路：

- 通过字符串查找成功的信息，查找相关的引用
- 判断对应的消息参数，再配合sendmessage和postmessage来查找相关引用的参数是否为对应的消息参数
- 再配合GetWindowTextW直接找到获取用户输入的地方

可以看出思路并非为单一的从头至尾的分析思路，是比较开放的逆向什么效率高就使用什么样的手段，该思路可以放到所有的mfc程序的逆向中

### 0x02 核心算法分析 ###

在`0x401cb0`中会先通过`0x401c00`获取我们输入的password，并判断该输入中是否有'b'，如果存在函数返回1，返回0的话程序直接验证错误

	.text:00401C38                 call    ds:GetWindowTextW ; 获取输入
	.text:00401C3E                 mov     cx, [ebp+user_input]
	.text:00401C45                 lea     eax, [ebp+user_input]
	.text:00401C4B                 pop     esi
	.text:00401C4C                 test    cx, cx
	.text:00401C4F                 jz      short loc_401C5B
	.text:00401C51                 cmp     word ptr [eax+2], 0 ; 简单的判断输入是否为空，没有意义
	.text:00401C56                 lea     eax, [eax+2]
	.text:00401C59                 jnz     short loc_401C51
	.text:00401C5B                 xor     eax, eax
	.text:00401C5D                 test    cx, cx
	.text:00401C60                 jz      short fail_jmp
	.text:00401C62                 movzx   ecx, cx
	.text:00401C65                 mov     edx, 62h
	.text:00401C6A                 nop     word ptr [eax+eax+00h]
	.text:00401C70                 cmp     dx, cx          ; 循环判断输入中是否有b
	.text:00401C73                 jz      short success_jmp
	.text:00401C75                 movzx   ecx, [ebp+eax*2+var_CA]
	.text:00401C7D                 inc     eax
	.text:00401C7E                 test    cx, cx
	.text:00401C81                 jnz     short loc_401C70
	.text:00401C83 fail_jmp:                               ; CODE XREF: sub_401C00+60j
	.text:00401C83                 xor     eax, eax
	.text:00401C85                 mov     ecx, [ebp+var_4]
	.text:00401C88                 xor     ecx, ebp
	.text:00401C8A                 call    sub_402CC5
	.text:00401C8F                 mov     esp, ebp
	.text:00401C91                 pop     ebp
	.text:00401C92                 retn
	.text:00401C93 success_jmp:                            ; CODE XREF: sub_401C00+73j
	.text:00401C93                 mov     ecx, [ebp+var_4]
	.text:00401C96                 mov     eax, 1
	.text:00401C9B                 xor     ecx, ebp
	.text:00401C9D                 call    sub_402CC5
	.text:00401CA2                 mov     esp, ebp
	.text:00401CA4                 pop     ebp
	.text:00401CA5                 retn
	
接着会通过`0x4039d0`(目前不了解该函数功能)，还有`0x402a50`,该函数与上个函数功能大致相同，不过是判断输入的字符串中是否存在字母'p'.

接着会重新调用`0x401cb0`，不过在调用前将`edx`设置为`1`,跟入后发现程序跳转到`0x401d57`

	.text:00401CCE                 test    edx, edx
	.text:00401CD0                 jnz     loc_401D57

在`0x401d57`中,先通过esi保存输入字符串的长度

	.text:00401DA0                 lea     eax, [eax+2]
	.text:00401DA3                 inc     esi
	.text:00401DA4                 cmp     word ptr [eax], 0
	.text:00401DA8                 jnz     short loc_401DA0

接着有个有趣的函数是`0x4048de`,主要调用`PerformanceCounter`来做一个计时器，这个函数会在之前调用一次并保存起来，然后在这次调用后比较差值是否大于2，如果大于2则直接失败。

	.text:00401DC9                 call    sub_4048DE
	.text:00401DCE                 sub     eax, [ebp-0D0h]
	.text:00401DD4                 cmp     eax, 2
	.text:00401DD7                 jg      short loc_401E3E

后续调用`0x402870`,主要功能是将输入的字符串进行保存到另外一个地址空间，并且返回值为：输入的长度与0x5的异或

接着会判断之前保存输入长度esi的值是否等于7

	.text:00401DE6                 cmp     esi, 7
	.text:00401DE9                 jnb     short loc_401DF6
	....
	.text:00401DF6 loc_401DF6:                             ; CODE XREF: .text:00401DE9j
	.text:00401DF6                 jbe     short loc_401E24

最后一个call：`0x401a60`这里应该是最终验证我们的输入是否合格的函数。

跟入后在`0x401bab`处，对输入进行异或并保存(后续还会还原)

	.text:00401BA8                 cmp     eax, 2
	.text:00401BAB                 jnb     short loc_401BB4
	.text:00401BAD                 xor     word ptr [esi+eax*2], 0Fh
	.text:00401BB2                 jmp     short loc_401BC5
	.text:00401BB4                 cmp     eax, 4
	.text:00401BB7                 jnb     short loc_401BC0
	.text:00401BB9                 xor     word ptr [esi+eax*2], 50h
	.text:00401BBE                 jmp     short loc_401BC5
	.text:00401BC0                 xor     word ptr [esi+eax*2], 42h
	.text:00401BC5                 inc     eax
	.text:00401BC6                 cmp     eax, ecx
	.text:00401BC8                 jb      short loc_401BA8

继续跟，跟到`0x401870`,并且参数为异或后的输入，以及一个地址空间。接着就是我们一直要知道的如何判别我们的输入

`0x4018a2`: 填充临时地址内容为0-9

	.text:004018A2                 mov     [ecx], ax
	.text:004018A5                 lea     ecx, [ecx+2]
	.text:004018A8                 inc     eax
	.text:004018A9                 cmp     eax, 39h
	.text:004018AC                 jle     short loc_4018A2

`0x4018b6`: 填充临时地址内容为a-z

	.text:004018B6                 mov     [ecx], ax
	.text:004018B9                 lea     ecx, [ecx+2]
	.text:004018BC                 inc     eax
	.text:004018BD                 cmp     eax, 7Ah
	.text:004018C0                 jle     short loc_4018B6

`0x4018e0`: 将临时地址中的a-z都转化为大写

	.text:004018E0                 movzx   eax, [ebp+ecx*2+var_50]
	.text:004018E5                 cmp     eax, 61h
	.text:004018E8                 jb      short loc_4018F7
	.text:004018EA                 cmp     eax, 7Ah
	.text:004018ED                 ja      short loc_4018F7
	.text:004018EF                 add     eax, 0FFFFFFE0h
	.text:004018F2                 mov     [ebp+ecx*2+var_50], ax
	.text:004018F7                 inc     ecx
	.text:004018F8                 cmp     ecx, edx
	.text:004018FA                 jb      short loc_4018E0

`0x401920`: 主要是还原之前异或输入

	.text:00401920                 cmp     eax, 2
	.text:00401923                 jnb     short loc_40192C
	.text:00401925                 xor     word ptr [edi+eax*2], 0Fh
	.text:0040192A                 jmp     short loc_40193D
	.text:0040192C loc_40192C:                             ; CODE XREF: sub_401870+B3j
	.text:0040192C                 cmp     eax, 4
	.text:0040192F                 jnb     short loc_401938
	.text:00401931                 xor     word ptr [edi+eax*2], 50h
	.text:00401936                 jmp     short loc_40193D
	.text:00401938 loc_401938:                             ; CODE XREF: sub_401870+BFj
	.text:00401938                 xor     word ptr [edi+eax*2], 42h
	.text:0040193D loc_40193D:                             ; CODE XREF: sub_401870+BAj
	.text:0040193D                                         ; sub_401870+C6j
	.text:0040193D                 inc     eax
	.text:0040193E                 cmp     eax, ecx
	.text:00401940                 jb      short loc_401920

`0x401960`: 将用户的输入中字母都转化为大写

	.text:00401960                 movzx   eax, word ptr [edi+ecx*2]
	.text:00401964                 cmp     eax, 61h
	.text:00401967                 jb      short loc_401975
	.text:00401969                 cmp     eax, 7Ah
	.text:0040196C                 ja      short loc_401975
	.text:0040196E                 add     eax, 0FFFFFFE0h
	.text:00401971                 mov     [edi+ecx*2], ax
	.text:00401975 loc_401975:                             ; CODE XREF: sub_401870+F7j
	.text:00401975                                         ; sub_401870+FCj
	.text:00401975                 inc     ecx
	.text:00401976                 cmp     ecx, edx
	.text:00401978                 jb      short loc_401960

`0x4019a3`: 遍历用户输入并保存找到的大写字母

	.text:004019A3                 cmp     dx, [ecx]
	.text:004019A6                 jz      short loc_4019B8
	.text:004019A8                 inc     eax
	.text:004019A9                 lea     ecx, [ebp+var_50]
	.text:004019AC                 cmp     word ptr [ecx+eax*2], 0
	.text:004019B1                 lea     ecx, [ecx+eax*2]
	.text:004019B4                 jnz     short loc_4019A3

`0x4019e0`: 比较获取到的字母个数是否为2

`0x401a10`： 判断输入中3-6，是否为15bp

	.text:00401A10                 mov     ax, word ptr [ebp+ecx*2+var_10]
	.text:00401A15                 cmp     ax, [esi]
	.text:00401A18                 jnz     short loc_401A39
	.text:00401A1A                 inc     ecx
	.text:00401A1B                 add     esi, 2
	.text:00401A1E                 cmp     ecx, 4
	.text:00401A21                 jb      short loc_401A10

接着进入最后的一个函数`0x401740`

在`0x401813`处判断前2个字符是否为12

	.text:00401810                 mov     ax, [ecx]
	.text:00401813                 cmp     ax, [esi+ecx]
	.text:00401817                 jnz     short loc_40185B
	.text:00401819                 add     edx, 6
	.text:0040181C                 add     ecx, 2
	.text:0040181F                 cmp     edx, 39h
	.text:00401822                 jle     short loc_401810

`0x401824`还会再次判断头2个字符相加是否为`0x63`

	.text:00401824                 movzx   ecx, word ptr [edi+12h]
	.text:00401828                 movzx   eax, word ptr [ebx]
	.text:0040182B                 add     ecx, eax
	.text:0040182D                 cmp     ecx, 63h

`0x40183e`来判断最后一个字符是否为8

	.text:00401832                 mov     eax, [ebp+var_4C]
	.text:00401835                 movzx   ecx, word ptr [edi+0Ch]
	.text:00401839                 add     ecx, [eax]
	.text:0040183B                 mov     eax, [ebp+var_50]
	.text:0040183E                 movzx   eax, word ptr [eax]
	.text:00401841                 cmp     eax, ecx

这样整理得出最终答案为:  1215pb8

### 0x03 总结 ###

分析过程中碰到的困惑：

很多函数并无法准确判断出功能，并且其中会嵌套很多函数，这里就直接根据参数和返回值来判断该函数的大致功能
程序的分支和跳转大部分都是通过经验和猜测来进行判断，是否为正常的验证跳转，目前无法解决
很多东西都很模糊，分析起来比较费劲效率低下，也只能继续啃

KEEP Going!!! :P
