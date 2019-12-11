---
layout: post
title: "[code] Ossec-Agentd模块分析"
categories: "SourceCodeAnalysis"
---

### 0x00 模块功能描述：

client使用keystore中存储的key加解密与server的通信数据；从Server接收相关的控制消息(Restart syscheck、active response、文件更新)；如果为active response转发到/queue/alerts/execq队列由execd模块进行命令执行；从/queue/ossec/queue接收其他模块(monitory、secure、syslog、syslogtcp)写入的消息并转发至Server端

### 0x01 模块流程图：

![ossec]({{ '/images/201907/ossec-agentd_1_1.png' | prepend: site.baseurl }})

### 0x02 关键功能解析：

#### OS_ReadKeys：
通过client.key(一般只存在一行)初始化结构体keystore, 主要初始化key用于通信的加解密。

```c
# 格式：
002 v1 192.168.32.165 aa90159807cd317c21f8e17ba7b1d5eb4c338036d8fe7833bff11a69a4b32654
while(fgets(buffer, OS_BUFFER_SIZE, fp) != NULL)
    {
        if((buffer[0] == '#') || (buffer[0] == ' '))
            continue;

        /* Getting ID */
        valid_str = buffer;
        tmp_str = strchr(buffer, ' ');
        strncpy(id, valid_str, KEYSIZE -1);
				...
        /* Getting name */
        valid_str = tmp_str;
        tmp_str = strchr(tmp_str, ' ');
        strncpy(name, valid_str, KEYSIZE -1);
				...
        /* Getting ip address */
        valid_str = tmp_str;
        tmp_str = strchr(tmp_str, ' ');
        strncpy(ip, valid_str, KEYSIZE -1);
				...
        /* Getting key */
        valid_str = tmp_str;
        tmp_str = strchr(tmp_str, '\n');
        strncpy(key, valid_str, KEYSIZE -1);
				...
        /* Generating the key hash */
        __chash(keys, id, name, ip, key);
		}
```

__chash: 主要功能根据name、id、key生成最终可以用来进行通信的加密key(只会存在内存中)

```c
    OSHash_Add(keys->keyhash_id,				# 通过hashtable保存id与keyentries映射的关系
               keys->keyentries[keys->keysize]->id,
               keys->keyentries[keys->keysize]);
    ...
    OSHash_Add(keys->keyhash_ip,				# hashtable保存ip与keyentries映射的关系
               keys->keyentries[keys->keysize]->ip->ip,
               keys->keyentries[keys->keysize]);    
    ...
		/* MD5 from name, id and key */
		OS_MD5_Str(name, filesum1);	
		OS_MD5_Str(id,  filesum2);
		/* Generating new filesum1 */
		snprintf(_finalstr, sizeof(_finalstr)-1, "%s%s", filesum1, filesum2);	
    /* Using just half of the first md5 (name/id) */
    OS_MD5_Str(_finalstr, filesum1);
    /* Second md is just the key */
    OS_MD5_Str(key, filesum2);	
		/* Generating final key */
		memset(_finalstr,'\0', sizeof(_finalstr));
		snprintf(_finalstr, 49, "%s%s", filesum2, filesum1);
    /* Final key is 48 * 4 = 192bits */
    os_strdup(_finalstr, keys->keyentries[keys->keysize]->key);
```

#### connect_server：
遍历agt->rip中保存的服务器ip，测试与服务器的网络是否联通；成功连接则保留连接的socket信息到agt->sock

```c
    while(agt->rip[rc])
    {
        /* Checking if we have a hostname. */
        tmp_str = strchr(agt->rip[rc], '/');
        if(tmp_str)
        {
            f_ip = OS_GetHost(agt->rip[rc], 5);
						...
        }
        /* IPv6 address: */
        if(strchr(tmp_str,':') != NULL)
        {
            verbose("%s: INFO: Using IPv6 for: %s .", ARGV0, tmp_str);
            agt->sock = OS_ConnectUDP(agt->port, tmp_str, 1);
        }
        else
        {
            verbose("%s: INFO: Using IPv4 for: %s .", ARGV0, tmp_str);
            agt->sock = OS_ConnectUDP(agt->port, tmp_str, 0);
        }
        if(agt->sock < 0)
        {
          ...
          merror("%s: ERROR: Unable to connect to any server.",ARGV0);
        }
        else
        {		# 说明服务器连接成功
            agt->rip_id = rc;
            return(1);
        }
    }
```

#### start_agent:

发送hello信息至服务器，接收服务返回的消息进行解密并校验消息完整性，判断是否为ack信息，如果失败一直尝试

```c
/* Sending start message and waiting for the ack */
    while(1)
    {
      	# 消息为："#!-agent startup"
        /* Sending start up message */
        send_msg(0, msg);
        /* Read until our reply comes back */
        while(((recv_b = recv(agt->sock, buffer, OS_MAXSTR,
                              MSG_DONTWAIT)) >= 0) || (attempts <= 5))
        {
            if(recv_b <= 0)
            {
								# 尝试重新发送信息
                send_msg(0, msg);
            }
            # 使用keys->keyentries[0]->key进行数据的解密
            tmp_msg = ReadSecMSG(&keys, buffer, cleartext, 0, recv_b -1);
            # 检查解密出来的消息头是否合格
            # "#!-"
            if(IsValidHeader(tmp_msg))
            {
                # 确认为ack信息
                # "agent ack"
                if(strcmp(tmp_msg, HC_ACK) == 0)
                {
                  	# 如果为初次连接则发送相关的信息
                    if(is_startup)
                    {
                        /* Send log message about start up */
                        snprintf(msg, OS_MAXSTR, OS_AG_STARTED,
                                keys.keyentries[0]->name,
                                keys.keyentries[0]->ip->ip);
                        snprintf(fmsg, OS_MAXSTR, "%c:%s:%s", LOCALFILE_MQ,
                                                  "ossec", msg);
                        send_msg(0, fmsg);
                    }
                    return;
                }
            }
        }
        /* If we have more than one server, try all. */
        if(agt->rip[1])
        {
						# 如果还有其他的Server都进行连接确认
            connect_server(agt->rip_id +1);
        }
        else
        {		# 如果尝试多次失败，则检测与Server的网络是否连通
            connect_server(0);
        }
    }
```

ReadSecMSG：使用keys中保存的key解密Server端发送过来的消息。

```c
    /* Decrypting message */
    if(!OS_BF_Str(buffer, cleartext, keys->keyentries[id]->key,
                  buffer_size, OS_DECRYPT))
		...
		else if(cleartext[0] == '!')
    {
				...
        /* 解压缩 */
        cmp_size = os_zlib_uncompress(cleartext, buffer, buffer_size, OS_MAXSTR);
        /* 检测数据的完整性  */
        f_msg = CheckSum(buffer);
    }
    # 旧的格式，不需要解压缩
    else if(cleartext[0] == ':')
    {
        /* 验证数据完整性  */
        f_msg = CheckSum(cleartext);
    }
```

OS_BF_Str: 封装的加解密函数,使用的算法为DES-CBC算法

```c
    static unsigned char cbc_iv [8]={0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
    memcpy(iv,cbc_iv,sizeof(iv));
    BF_set_key(&key, strlen(charkey), (uchar *)charkey);
    BF_cbc_encrypt((uchar *)input, (uchar *)output, size,
            &key, iv, action);
```

#### run_notify:

将agent的一些信息发送给Server

```c
    uname = getuname();
    /* get shared files */
    shared_files = getsharedfiles();
    /* creating message */
    rand_keepalive_str2(keep_alive_random, 700);
    snprintf(tmp_msg, OS_SIZE_1024, "#!-%s / %s\n%s\n%s",
                 uname, md5sum, shared_files, keep_alive_random);
   	..
    /* Sending status message */
    send_msg(0, tmp_msg);
```

#### 主循环:

使用select检测Server端发送的消息以及本地队列中接收的消息(Monitord、syslog、syslogtcp、secure等模块)

```c
    while(1)
    {
        /* Monitoring all available sockets from here */
        /* Wait with a timeout for any descriptor */
        rc = select(maxfd, &fdset, NULL, NULL, &fdtimeout);
        /* For the receiver */
        if(FD_ISSET(agt->sock, &fdset))
        {
            receive_msg();
        }
        /* For the forwarder */
        if(FD_ISSET(agt->m_queue, &fdset))
        {
            EventForward();
        }
    }
```

receive_msg: 用于接收Server端发送过来的消息，这里分别处理了active response、restart syscheck、ACK、文件更新、文件关闭等信息

```c
while((recv_b = recv(agt->sock, buffer, OS_SIZE_1024, MSG_DONTWAIT)) > 0)
    {
        tmp_msg = ReadSecMSG(&keys, buffer, cleartext, 0, recv_b -1);
        /* Check for commands */
        if(IsValidHeader(tmp_msg))
        {
						...
            /* If it is an active response message */
            if(strncmp(tmp_msg, EXECD_HEADER, strlen(EXECD_HEADER)) == 0)
            {
                if(agt->execdq >= 0)
                    if(OS_SendUnix(agt->execdq, tmp_msg, 0) < 0)
            }

            /* Restart syscheck. */
            else if(strcmp(tmp_msg, HC_SK_RESTART) == 0)
            {
                os_set_restart_syscheck();
                continue;
            }

            /* Ack from server */
            else if(strcmp(tmp_msg, HC_ACK) == 0)

            /* File update message */
            if(strncmp(tmp_msg, FILE_UPDATE_HEADER,
                       strlen(FILE_UPDATE_HEADER)) == 0)
            {
							...
            }
						# 文件关闭
            else if(strncmp(tmp_msg, FILE_CLOSE_HEADER,
                        strlen(FILE_CLOSE_HEADER)) == 0)
            {
							...
            }
            else		# 无效的信息
            {
                merror("%s: WARN: Unknown message received from server.", ARGV0);
            }
        }
    }
```

EventForward：将本地队列/queue/ossec/queue中接收到的消息转发至Server

```c
    while((recv_b = recv(agt->m_queue, msg, OS_MAXSTR, MSG_DONTWAIT)) > 0)
    {
        send_msg(0, msg);
				...
    }
```

### 0x03 关键数据结构：

- agent数据结构：对应与该模块的功能，主要包含主消息队列、Server IP、配置文件名称、Server socket、Execd执行队列

  ```c
  /* Configuration structure */
  typedef struct _agent
  {
      int port;
      int m_queue;	/* 主消息队列 */
      int sock;		/* 与Server的socket */
      int execdq;		/* 本地Active response执行队列 */
      int rip_id;
      char *lip;
      char **rip; /* remote (server) ip */
      int notify_time;
      int max_time_reconnect_try;
      char *profile;		/* 对应的配置文件名称 */
  }agent;
  ```

- keystore及keyentry结构体：保存client与Server之间的认证key；用于通信信息的加解密

  ```c
  /* Unique key for each agent. */
  typedef struct _keyentry
  {
      unsigned int rcvd;
      unsigned int local;
      unsigned int keyid;
      unsigned int global;
      char *id;
      char *key;		/* 通过id、name、client.keys中保存的key，加密生成 */
      char *name;
      os_ip *ip;
      struct sockaddr_in peer_info;
      FILE *fp;
  }keyentry;
  
  /* Key storage. */
  typedef struct _keystore
  {
      /* Array with all the keys */
      keyentry **keyentries;
      /* Hashes, based on the id/ip to lookup the keys. */
      void *keyhash_id;		/* 通过hashtable来保存对应的keyentry地址 */
      void *keyhash_ip;
      /* Total key size */
      int keysize;
      /* Key file stat */
      int file_change;
  }keystore;
  ```


### 0x04 接口的抽象化

ClientConf -> ReadConfig -> read_main_elements -> Read_Client

针对配置文件的加载，通过ReadConfig的主接口，首先解析配置文件的xml数据结构，再针对每个节点判定模块，再分发到不同的配置文件解析并初始化对应的数据结构。

ReadSecMSG -> OS_BF_Str -> BF_cbc_encrypt

通过OS_BF_Str接口传入对应的key和密文，可以进行数据的加解密

Send_msg -> CreateSecMSG & OS_SendUDPbySize

使用CreateSecMSG针对原数据进行压缩和加密，通过OS_SendUDPbySize发送UDP请求信息
