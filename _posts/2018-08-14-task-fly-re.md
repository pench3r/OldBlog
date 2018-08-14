---
layout: post
title: "[reverse] fly-solution"
---


### 0x00 题目分析 ###

程序是通过mfc编写的，运行程序后会初始化会出现3只苍蝇，鼠标选中苍蝇左键后，就会消除一只苍蝇，但会增加2只苍蝇，题目的描述为消灭所有苍蝇就会获得flag(但是题解跟这个没有太大关系)，对于该题目的切入，使用如下方式：

- 通过`messagebox`(在运行程序后会第一个弹出是否准备开始游戏的提示)，进行断点来追踪消息；后来思考因为要输出`flag`还是同样会利用`messagebox`进行输出，因此也可以通过这种方式找到关键算法
- 关键字搜索，通过`unicode`搜索发现有一处`success`,查找引用会发现关键算法
- 通过`dispatchmessage`配合条件断点，`[esi+4]==0111`可以断下关闭苍蝇的事件
- 之后通过捕获苍蝇的关闭事件，发现是使用`endialog`进行窗体的关闭，根据该API，查找到对应的创建`API CreateDialogIndirectParamW`
- 接着就是针对于感兴趣的函数进行分析就可以了

其中涉及到的关键数据结构

1. 该数据结构用来保存游戏中的一些信息，包括每个fly对象的地址、fly的创建总数，如下图地址`0x12fe68`保存的内容

![ctf]({{ '/images/201808/task_fly_re_0_1.png' | prepend: site.baseurl }})

偏移`0xA0`处保存的为fly对象的数组地址，偏移`0xA4`保存的为fly的创建的总数

2. 在对应的fly对象数组的地址可以观察到每个fly对象的地址，如下图地址`0x17fe90`保存的内容

![ctf]({{ '/images/201808/task_fly_re_0_2.png' | prepend: site.baseurl }})

目前保存的为3只fly对象的地址

3. 在每个fly对象的地址中，会保存关于该fly对象携带的字符、是否被点击的标记、vftable、以及是否更新携带字符的标记等信息，以`0x186600`为例

![ctf]({{ '/images/201808/task_fly_re_0_3.png' | prepend: site.baseurl }}) 

`+0x00`表示为vftable、`+0x20`代表苍蝇显示的窗体句柄、

![ctf]({{ '/images/201808/task_fly_re_0_4.png' | prepend: site.baseurl }})

`+C0`代表苍蝇是否可以进行更新字符的标记(为0表示可以进行更新)、`+0xE0`代表苍蝇携带的字符、`+0xE1`代表苍蝇是否已经被点击。

### 0x01 算法分析 ###

通过`messagebox`和关键字符串的搜索可以锁定到关键函数`0x403210`,对于关键点的分析如下

![ctf]({{ '/images/201808/task_fly_re_1_1.png' | prepend: site.baseurl }})

首先会先判断创建苍蝇的总数以及被点击过的苍蝇总数是否满足要求

![ctf]({{ '/images/201808/task_fly_re_1_2.png' | prepend: site.baseurl }})

上述代码会通过遍历所有的fly对象，并将被点击过的苍蝇将他所携带的字符与索引异或保存

![ctf]({{ '/images/201808/task_fly_re_1_3.png' | prepend: site.baseurl }})

最后通过messagebox进行输出

分析到这里的时候思路自然就想到如何才能获得到每个苍蝇所携带的原始字符的信息，接着在苍蝇的携带字符的对应位置上进行内存写断点，获取更多的关键函数信息，捕获到函数`0x4044d0`,分析到这里的时候发现无法进行下一步，因为每个苍蝇的携带的字符一直在变动，并且是根据苍蝇的移动的位置进行随机更新字符，苍蝇的长宽都为`0x3c`.后来这里只能根据出题者的wp，知道了`flag`是如何计算的,如下图：

![ctf]({{ '/images/201808/task_fly_re_1_4.png' | prepend: site.baseurl }})

会发现有几个固定的16进制数字会分别针对0x29,0x28,0x27,0x26,0x25,0x24进行异或，通过再配合之前收集到的信息一共要有24个字符，这样刚好够

### 0x02 计算flag ###

<pre>from pwn import *

p_v = [0]*6
p_v[0] = 0x53694273
p_v[1] = 0x1f4d1e74
p_v[2] = 0x4a1c434c
p_v[3] = 0x4f6a454e
p_v[4] = 0x4c7a5e78
p_v[5] = 0xe0f467d

val_xor_list = []

for i in range(7):
  print hex(0x29292929-i*0x01010101)
  val_xor_list.append(0x29292929-i*0x01010101)

data = ""

for i, item in enumerate(p_v):
  buff = p32(item ^ val_xor_list[i])
  for j, each in enumerate(buff):
    data += chr(ord(each) ^ (j + 4*i))
print "result: " +  data
print "plain flag: " + data.decode('base64')</pre>

运行输出如下：

![ctf]({{ '/images/201808/task_fly_re_2_1.png' | prepend: site.baseurl }})

ps：当看到这个题解的时候还是有个困惑，不知道为什么就能确定索引的顺序是从`0x53694273`开始的，可能这个题目确实是比较考验经验吧，感觉题目出的不是很严谨导致自己折腾了很久

### 0x03 总结 ###

题目刚开始做感觉很新颖，一开始完全没有思路，后来静下心来思考，当一切无从下手的手就先分析可以看到的所有信息，接着就开始找主函数，苍蝇的创建操作，苍蝇的删除操作，苍蝇的动作消息处理等功能，虽然这个题目最后的题解有点无厘头，但也是学到了很多，虽然有些东西看着让自己感觉很无力(很多函数功能现在还是不太了解，以及一些数据结构的内容代表什么)，也期待一下有大牛能完整的分析一下这个题目是最好的。

KEEP Going!!! :P


