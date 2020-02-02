---
layout: post
title: "Heart Bleed漏洞分析"
categories: "BinarySecurity"
---

#### 0x00 前言：

OpenSSL的heartbeat模块中的dtls1_process_heartbeat存在问题，对应源码文件为ssl/dl_both.c；通过控制心跳包中的长度字段，可以泄漏sslV3记录后的内存数据；对应漏洞编号CVE-2014-0160

#### 0x01 漏洞分析

直接来到关键漏洞函数：dtls1_process_heartbeat(ssl/dl_both.c)

```c
int
dtls1_process_heartbeat(SSL *s)
{
unsigned char *p = &s->s3->rrec.data[0], *pl;
unsigned short hbtype;
unsigned int payload;
unsigned int padding = 16; /* Use minimum padding */

/* Read type and payload length first */
hbtype = *p++;
n2s(p, payload);		// payload攻击者可控
pl = p;

if (s->msg_callback)
	s->msg_callback(0, s->version, TLS1_RT_HEARTBEAT,
		&s->s3->rrec.data[0], s->s3->rrec.length,
		s, s->msg_callback_arg);

if (hbtype == TLS1_HB_REQUEST)
	{
	unsigned char *buffer, *bp;
	int r;

	/* Allocate memory for the response, size is 1 byte
	 * message type, plus 2 bytes payload length, plus
	 * payload, plus padding
	 */
	buffer = OPENSSL_malloc(1 + 2 + payload + padding);
	bp = buffer;

	/* Enter response type, length and copy payload */
	*bp++ = TLS1_HB_RESPONSE;
	s2n(payload, bp);
	memcpy(bp, pl, payload);		// 未检查payload长度，造成越界读取内存
	bp += payload;
	/* Random padding */
	RAND_pseudo_bytes(bp, padding);

	r = dtls1_write_bytes(s, TLS1_RT_HEARTBEAT, buffer, 3 + payload + padding);

	if (r >= 0 && s->msg_callback)
		s->msg_callback(1, s->version, TLS1_RT_HEARTBEAT,
			buffer, 3 + payload + padding,
			s, s->msg_callback_arg);

	OPENSSL_free(buffer);
	...
return 0;
}
```

可以得到：

* 在memcpy处使用的payload长度未进行检测，同时payload可以控制，导致了内存越界
* 再通过dtls1_write_bytes将越界获取的信息进行回传

关键数据结构：

```c
typedef struct ssl_t {
	struct ssl3_state_st *s3; /* SSLv3 variables */
}

typedef struct ssl3_state_st {
	SSL3_RECORD rrec;	/* each decoded record goes in here */
}

typedef struct ssl3_record_st
	{
/*r */	int type;               /* type of record */
/*rw*/	unsigned int length;    /* How many bytes available */
/*r */	unsigned int off;       /* read/write offset into 'buf' */
/*rw*/	unsigned char *data;    /* pointer to the record data */
/*rw*/	unsigned char *input;   /* where the decode bytes are */
/*r */	unsigned char *comp;    /* only used with decompression - malloc()ed */
/*r */  unsigned long epoch;    /* epoch number, needed by DTLS1 */
/*r */  unsigned char seq_num[8]; /* sequence number, needed by DTLS1 */
	} SSL3_RECORD;
```

tls对应的数据包格式如下：

| 心跳包字段           | 长度                  | 说明                                                         |
| :------------------- | :-------------------- | :----------------------------------------------------------- |
| ContentType          | 1byte                 | 心跳包类型，IANA组织把type编号定义为24（0x18）               |
| ProtocolVersion      | 2bytes                | TLS的版本号，目前主要包括含有心跳扩展的TLS版本：TLSv1.0，TLSv1.1，TLSv1.2 |
| length               | 2bytes                | HeartbeatMessage的长度                                       |
| HeartbeatMessageType | 1byte                 | Heartbeat类型 01表示heartbeat_request 02表示heartbeat_response |
| payload_length       | 2bytes                | payload长度                                                  |
| payload              | payload_length个bytes | payload的具体内容                                            |
| padding              | >=16bytes             | padding填充，最少为16个字节                                  |

直接引用数据包中的payload_length，并未检测数据的有效性：

```
unsigned char *p = &s->s3->rrec.data[0]  // 获取数据包中的数据
/* Read type and payload length first */
hbtype = *p++;
n2s(p, payload);	// 通过p[0]和p[1]确定payload的大小
```

这里借助poc来更好的理解控制的数据：

```python
# TLSv1.1
# 这段数据是再进行发送hello数据后再发送的
hb2 = h2bin('''
18 			// ContentType
03 02 	// ProtocolVersion
00 03		// length
01			// HeartbeatMessageType: 01->heartbeat_request  02->heartbeat_response
04 00		// payload_length
''')
```

因此rrec.data[0]对应的位置即为poc中的01，payload最终获取的值为：1024

n2s宏的定义如下：

```c
((payload=(((unsigned int)(p[0]))<< 8)| (((unsigned int)(p[1])) )),p+=2)
```

对应的数据内容为：p[0]->04、p[1]->00

在关键的memcpy处，直接引用了payload的值进行复制

```c
memcpy(bp, pl, payload);
```

至此可以完美控制payload的大小，接着看pl指向的数据的范围

pl指向SSLV3 Record结构体，数据大小为接收心跳包中的数据；<strong>此处因为未检测payload和接收的数据包的实际大小进行校验导致了越界的产生</strong>

通过dtls1_write_bytes函数将越界后的数据回传给客户端

```c
r = dtls1_write_bytes(s, TLS1_RT_HEARTBEAT, buffer, 3 + payload + padding);
```

TLS1_RT_HEARTBEAT=24，因此poc中也是通过检测接收数据的type是否为24来判定漏洞的存在

poc中接收响应的逻辑：

```python
hdr = recvall(s, 5)	// 接收5个字节
typ, ver, ln = struct.unpack('>BHH', hdr)	// 大端：1字节、2字节、2字节
pay = recvall(s, ln, 10)	
return typ, ver, pay
```

漏洞利用的流程：

* socket连接
* 发送hello
* 发送恶意的tls数据包
* 接收响应判定是否存在漏洞

#### 总结

这里只是分析了漏洞的成因分析，并未从整个执行流程进行分析，例如：接收数据包的完整流程、返回响应数据包的完整流程；不过对于该漏洞的基本原理已经熟悉

参考： 

https://yaofeifly.github.io/2017/04/07/heartbleed/
