---
layout: post
title: "[Reverse] 看雪2016ctf-第二题-solution"
---

### 0x00 题目分析 ###

自己分析的思路(只是找到验证函数)：

1. 一开始的切入点，通过`getwindowtext`断点进行跟踪调试，断下后分析之后紧跟的几个函数，简单判断用户的输入长度、是否为数字和字母、以及很关键的一个加密函数，会加密用户的输入，然后返回上层函数

2. 接着会申请新的内存并从`42d864`处`copy`数据，又调用解密函数会将传入的数据解密，然后通过后续的`4011c0`输出到程序的窗体中

3. 跟踪调试到调用`41aef1`处，后续有跳转，配合`setwindowtext`调试发现当`41aef1`返回0时，验证失败；判断`41aef1`为关键的验证函数


### 0x01 完整分析 ###


#### 1 确定关键的加密算法RC6 ####

首先通过`getwindowtext`获取用户的输入，后面进行了简单的判断

![ctf]({{ '/images/201809/kanxue2016_ctf_1_1.png' | prepend: site.baseurl }})

对于图中的`rc6_dec_msg`函数的识别，是通过对应ida的伪代码和C++实现的伪代码所的结论，对照结束后的标注如下：

	.text:0041B3B0                 mov     eax, offset loc_42C70F
	.text:0041B3B5                 call    __EH_prolog
	.text:0041B3BA                 sub     esp, 0A0h
	.text:0041B3C0                 push    esi
	.text:0041B3C1                 push    edi
	.text:0041B3C2                 lea     ecx, [ebp+var_AC]
	.text:0041B3C8                 call    obj_init
	.text:0041B3CD                 mov     edi, [ebp+arg_0]
	.text:0041B3D0                 mov     esi, [ebp+arg_4]
	.text:0041B3D3                 and     [ebp+var_4], 0
	.text:0041B3D7                 lea     ecx, [ebp+var_AC]
	.text:0041B3DD                 push    dword ptr [edi] ; void *
	.text:0041B3DF                 push    dword ptr [esi] ; unsigned int
	.text:0041B3E1                 push    [ebp+arg_8]     ; int
	.text:0041B3E4                 call    desc_via_rc6
	.text:0041B3E9                 push    dword ptr [edi] ; void *
	.text:0041B3EB                 lea     ecx, [ebp+var_AC]
	.text:0041B3F1                 push    dword ptr [esi] ; int
	.text:0041B3F3                 call    cpy_msg_to_input ; update userinput to encrypt text
	.text:0041B3F8                 xor     ecx, ecx
	.text:0041B3FA                 cmp     eax, [esi]
	.text:0041B3FC                 setz    cl
	.text:0041B3FF                 or      [ebp+var_4], 0FFFFFFFFh
	.text:0041B403                 mov     esi, ecx
	.text:0041B405                 lea     ecx, [ebp+var_AC]
	.text:0041B40B                 call    free_buff
	.text:0041B410                 mov     ecx, [ebp+var_C]
	.text:0041B413                 mov     eax, esi
	.text:0041B415                 pop     edi
	.text:0041B416                 pop     esi
	.text:0041B417                 mov     large fs:0, ecx
	.text:0041B41E                 leave
	.text:0041B41F                 retn    0Ch

在`desc_via_rc6`是主要的rc6算法的解密程序.

	.text:004030B9                 mov     [esi+8], edi
	.text:004030BC                 call    ??2@YAPAXI@Z    ; operator new(uint)
	.text:004030C1                 push    dword ptr [esi+8] ; size_t
	.text:004030C4                 mov     [esi+4], eax
	.text:004030C7                 push    [esp+10h+arg_8] ; void *
	.text:004030CB                 push    eax             ; void *
	.text:004030CC                 call    _memcpy
	.text:004030D1                 mov     eax, [esp+18h+arg_0]
	.text:004030D5                 add     esp, 10h
	.text:004030D8                 mov     ecx, esi
	.text:004030DA                 mov     [esi+9Ch], eax
	.text:004030E0                 push    eax
	.text:004030E1                 call    rc6_keyextend   ; sub_403438
	.text:004030E6                 mov     ecx, esi
	.text:004030E8                 call    rc6_desc        ; sub_40315b
	.text:004030ED                 push    1
	.text:004030EF                 pop     eax
	.text:004030F0                 jmp     short loc_4030F4

识别的关键是通过`rc6_keyextend`和`rc6_desc`来识别，通过ida的伪代码对比确认的

	.text:00403442                 call    sub_40342C      ; return 0x5163
	.text:00403447                 mov     ebx, eax
	.text:00403449                 mov     ecx, esi
	.text:0040344B                 or      ebx, 0B7E10000h 
	.text:00403451                 call    sub_403432
	.text:00403456                 push    [ebp+arg_0]	   ; return 0x79b9
	.text:00403459                 or      eax, 9E370000h

这个为密钥扩展中的关键信息为rc6的`magicnumber`，接着下图为`rc6_desc`的ida伪代码

![ctf]({{ '/images/201809/kanxue2016_ctf_1_2.png' | prepend: site.baseurl }})

对比公开的rc6的伪代码可以得出结论为rc6加密(其实这里需要很深的经验来判断，不过这个加密函数不一定非要分析确定出来)，通过rc6的解密程序来对用户的输入进行了加密

接着通过`rc6_enc_msg`的函数对数据进行了解密，同样是比对伪代码确定的功能

	.text:0040311B                 mov     [esi+8], edi
	.text:0040311E                 call    ??2@YAPAXI@Z    ; operator new(uint)
	.text:00403123                 push    dword ptr [esi+8] ; size_t
	.text:00403126                 mov     [esi+4], eax
	.text:00403129                 push    [esp+10h+arg_8] ; void *
	.text:0040312D                 push    eax             ; void *
	.text:0040312E                 call    _memcpy
	.text:00403133                 mov     eax, [esp+18h+arg_0]
	.text:00403137                 add     esp, 10h
	.text:0040313A                 mov     ecx, esi
	.text:0040313C                 mov     [esi+9Ch], eax
	.text:00403142                 push    eax
	.text:00403143                 call    rc6_keyextend   ; sub_403438
	.text:00403148                 mov     ecx, esi
	.text:0040314A                 call    rc6_enc         ; sub_4032b1
	.text:0040314F                 push    1
	.text:00403151                 pop     eax

这里使用了`rc6`的加密程序解密了数据，后续通过`sub_4011c0`输出

#### 2 验证函数中的LUA ####

在关键函数`41aef1`中，同样使用了`rc6_enc_msg`进行了解密数据,查看buffer中解密的数据如图

![ctf]({{ '/images/201809/kanxue2016_ctf_1_3.png' | prepend: site.baseurl }})

查看数据确定为lua的字节码，需要将该数据dump出来，并解行反编译。这里使用工具为`luadec`，通过vc编译出`lua53.dll`和`luadec`，直接解析会发生失败，发现头部的签名被改变为`ls 1 1`，这里将其修改为`LuaS`，`S`代表`lua5.3`

![ctf]({{ '/images/201809/kanxue2016_ctf_1_4.png' | prepend: site.baseurl }})

解密出来的lua脚本如下

![ctf]({{ '/images/201809/kanxue2016_ctf_1_5.png' | prepend: site.baseurl }})

可以发现脚本通过判断`fnGetRegSnToVerify()`的返回值和`fnCalcUserInputRegSnAfterEnc(g_strRegSn)`返回值是否相等来判断,接着明确思路开始分析这2个函数即可。通过`lua53.dll`尝试识别`lua`相关的函数.了解到`C`中载入`lua`代码需要调用的相关`API`

发现在解密后执行的一个函数通过比对函数发现为`luaL_loadbufferx`，用来将刚刚解密出来的字节码载入到`lua`虚拟机中,后续同样识别出调用了`lua_pcall`进行了`lua`代码的执行. 接着尝试定位`fnGetRegSnToVerify`和`fnCalcUserInputRegSnAfterEnc`函数，这里需要配合`rc6_enc_msg`的解密交叉引用断点来尝试分析相关的上下文，下断重启程序。挨个分析定到相关的字符解密的地方

![ctf]({{ '/images/201809/kanxue2016_ctf_1_6.png' | prepend: site.baseurl }})

定位到`winmain`函数中`41ad8f`函数首先对这2个函数分别解行解密然后注册对应的函数，使用`lua_pushcclosure`将函数压栈，然后配合`lua_setglobal`进行函数的注册，整理知道`fnGetRegSnToVerify`地址为`sub_4019A2`,`fnCalcUserInputRegSnAfterEnc`地址为`sub_4019C7`.

`fnGetRegSnToVerify`会返回固定的32字节数据。

	signed int __cdecl sub_4019A2(int a1)
	{
	  if ( !sub_40369C(a1) )
	    lua_pushlstring(a1, &unk_42D244, 0x20u);
	  return 1;
	}

将`42d244`处的32字节进行了压栈

	0042D244  A4 47 98 0C 9E 40 D7 F6 EB 76 6E 6D 7E A3 3E EB  ?濦做雟nm~?
	0042D254  D5 51 30 06 7D C0 FB 6C C2 7A 43 C5 A4 C9 B1 FD  誕0}利l聑C扭杀

接着`fnCalcUserInputRegSnAfterEnc`会接受用户被rc6加密的输入，先后通过2次xor.这里破解的思路是将`fnGetRegSnToVerify`返回的内容作为输入。其实也可以自己写程序来跑着一小段。

第一次异或

	0042D224  F5 91 23 5E 8D B0 87 E2 AE EE DE 93 88 F2 AC A3  鯌#^嵃団迵堯
	0042D234  4F 9F B7 61 10 23 FB 30 19 69 B8 AD CE 52 00 6C  O煼a#?i腑蜶.l

第二次异或

	003C6FB0  1A AB D4 70 AE 1A 31 D7 4E 7F 02 27 DA 3A D3 C0  p?1譔'?永
	003C6FC0  C7 BF A0 E2 D7 92 F0 E5 F8 64 D3 04 96 AD 17 41  强犫讙疱鴇?柇A

这里我们通过动态调试将`fnCalcUserInputRegSnAfterEnc`的输入设置为`fnGetRegSnToVerify`返回的固定的32字节数据。

![ctf]({{ '/images/201809/kanxue2016_ctf_1_7.png' | prepend: site.baseurl }})

返回的结果如下：

![ctf]({{ '/images/201809/kanxue2016_ctf_1_8.png' | prepend: site.baseurl }})

接着要获取明文就需要对以下密文进行rc6解密

	003C7050  4B 7D 6F 22 BD EA 61 C3 0B E7 B2 D9 2C 6B 41 88  K}o"疥a?绮?kA
	003C7060  5D 71 27 85 BA 71 F0 B9 23 77 28 6C FC 36 A6 D0  ]q'吅q鸸#w(l?π

这里同样使用小技巧，在任意的rc6的加密算法(因为该程序都是使用rc的加密程序来解密数据)处下断替换运行就可以了

![ctf]({{ '/images/201809/kanxue2016_ctf_1_9.png' | prepend: site.baseurl }})

替换完毕，运行查看解密情况

![ctf]({{ '/images/201809/kanxue2016_ctf_1_10.png' | prepend: site.baseurl }})

获取到注册码，这个当时测试了几个加密的地方，只有在加密lua字节码的地方可以解密成功，始终还是要写出加密算法解密才是正道。

PS：算法后续补上

#### 0x03 总结 ####

分析这个程序学到了很多东西：

- 对于一些函数通过部分关键字的特定确定使用了什么算法以及API，然后对比相应的伪代码来确认。
- 对于多个API的配合断点可以更快速的了解程序的运行
- 在分析出一个函数的功能后此时需要配合交叉引用来找到相关的关键点

一些比较薄弱的地方也凸显出来了：

- 常见的加密算法，不能自己识别出来，这个还需要自己多去看对应算法伪代码学习
- 对于工具的一些使用不是很熟练，例如od中直接dump某段地址的内存数据
- 一些常见的应用场景，例如c和lua的结合，相关的API调用
- 对于算法的逆向能力还是很弱，大佬们都可以通过汇编直接逆向出整个算法或者是根据伪代码来进行逆向，我这个地方还需要加强

KEEP Going!!!


