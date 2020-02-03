---
layout: post
title: "Heart Bleed漏洞分析"
categories: "BinarySecurity"
---

#### 0x00 前言：

OpenSSL的heartbeat模块中的dtls1_process_heartbeat存在问题，对应源码文件为ssl/dl_both.c；通过控制心跳包中的长度字段，可以泄漏sslV3记录后的内存数据；对应漏洞编号CVE-2014-0160

#### 0x01 漏洞成因

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

至此漏洞的基本成因比较清楚了，但在没有poc的场景下，如何确定SSLV3数据结构在网络数据包中映射？

#### 0x02 SSL/TLS协议

SSL/TLS协议在整个协议栈的中的位置如下图所示：

![tls]({{ '/images/202002/heart_bleed_2_1.png' | prepend: site.baseurl }})

可以看到协议分为两部分：TLS Record Subprotocol、Higher-layer Subprotocols

<strong>TLS Record Subprotocol(low-layer)</strong>： 会将Higher-layer的数据以<=16k字节单位进行分割；将数据进行压缩、并添加Message Authentication Code，最后使用协商的cipher spec加密整个数据并添加SSL Record header，整个流程如下：

```
        -----------+
          data   --+--------------> 1. Fragment data
        -----------+
                                    +------------------------+
                                    |                        |
                                    |                        |
                                    +------------------------+

                                    2. Compress data (generally no compression applied)

                                    +------------------------+----+
                                    |                        |MAC | Add a Message Authentication Code
                                    |                        |    |
                                    +------------------------+----+

                                    3. Encrypt data

                                    +-----------------------------+
                                    |ciphertext                   |
                                    |                             |
                                    +-----------------------------+

                                    4. Add header

                               +----+-----------------------------+
                    TLS Record |    |ciphertext                   | Add a TLS Record header
                      header   |    |                             |
                               +----+-----------------------------+

```

最后将TLS Record传递给传输层进行发送；客户端和服务端都是使用这样的方式进行数据传递；

<strong>Record Protocol format</strong>

TLS Record header包含3个字段：

- Byte 0: TLS record type
- Bytes 1-2: TLS version (major/minor)
- Bytes 3-4: Length of data in the record (excluding the header itself). The maximum supported is 16384 (16K).

```
         record type (1 byte)
        /
       /    version (1 byte major, 1 byte minor)
      /    /
     /    /         length (2 bytes)
    /    /         /
 +----+----+----+----+----+
 |    |    |    |    |    |
 |    |    |    |    |    | TLS Record header
 +----+----+----+----+----+


 Record Type Values       dec      hex
 -------------------------------------
 CHANGE_CIPHER_SPEC        20     0x14
 ALERT                     21     0x15
 HANDSHAKE                 22     0x16
 APPLICATION_DATA          23     0x17


 Version Values            dec     hex
 -------------------------------------
 SSL 3.0                   3,0  0x0300
 TLS 1.0                   3,1  0x0301
 TLS 1.1                   3,2  0x0302
 TLS 1.2                   3,3  0x0303
```

<strong>Higher-layer Subprotocols</strong>: 

​	包括多种subprotocols：Handshake Protocol、ChangeCipherSpec protocol、Alert Protocol、Application Data Protocol等,这些协议数据会被上述的low-layer进行分割包装，需要注意的是一个TLS Record可以封装多个相同类型的message数据。这里以Handshake数据包为例，整个数据包的结构如下：

```
                           |
                           |
                           |
         Record Layer      |  Handshake Layer
                           |                                  |
                           |                                  |  ...more messages
  +----+----+----+----+----+----+----+----+----+------ - - - -+--
  | 22 |    |    |    |    |    |    |    |    |              |
  |0x16|    |    |    |    |    |    |    |    |message       |
  +----+----+----+----+----+----+----+----+----+------ - - - -+--
    /               /      | \    \----\-----\                |
   /               /       |  \         \
  type: 22        /        |   \         handshake message length
                 /              type
                /
           length: arbitrary (up to 16k)


   Handshake Type Values    dec      hex
   -------------------------------------
   HELLO_REQUEST              0     0x00
   CLIENT_HELLO               1     0x01
   SERVER_HELLO               2     0x02
   CERTIFICATE               11     0x0b
   SERVER_KEY_EXCHANGE       12     0x0c
   CERTIFICATE_REQUEST       13     0x0d
   SERVER_DONE               14     0x0e
   CERTIFICATE_VERIFY        15     0x0f
   CLIENT_KEY_EXCHANGE       16     0x10
   FINISHED                  20     0x14
```

整理目前的信息：

s->s3->rrec的结构体为：

```c
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

该数据结构对应的数据包的位置即为：前面的TLS Record包

```
&s->s3->rrec.data[0]
```

data字段则指向TLS Record所封装的message，即除去TLS Record header部分

通过dtls1_process_heartbeat函数，整理最后的HeartBeat数据包格式如下：

```
                           |
                           |
                           |
         Record Layer      |  HeartBeat Layer
                           |                                  |
                           |                                  |  ...more HeartBeat messages
  +----+----+----+----+----+----+----+----+----+------ - - - -+--
  | 24 |    |    |    |    |    |    |    |                   |
  |0x18|    |    |    |    |    |    |    |     payload       |
  +----+----+----+----+----+----+----+----+----+------ - - - -+--
    /               /      | \    \-------\                |
   /               /       |  \         \
  type: 24        /        |   \         payload length
                 /              type
                /
           length: arbitrary (up to 16k)
```

由于server->client的数据包也是通过这样方式封装的

```
r = dtls1_write_bytes(s, TLS1_RT_HEARTBEAT, buffer, 3 + payload + padding);
```

回传的Record type为24，因此poc会检测该标记位来判定漏洞的触发

#### 0x03 总结

这里分析了漏洞的成因，以及相关的数据结构如何在数据包中映射；

漏洞的原理相对比较简单，但是要找到相关数据结构在网络数据包中的位置是比较困难的，如果没有前人的分析做参考，那可能需要去通过源码、官方文档去找答案

参考： 

https://yaofeifly.github.io/2017/04/07/heartbleed/

http://blog.fourthbit.com/2014/12/23/traffic-analysis-of-an-ssl-slash-tls-session/

https://www.ibm.com/support/knowledgecenter/SSB23S_1.1.0.12/gtps7/s5rcd.html
