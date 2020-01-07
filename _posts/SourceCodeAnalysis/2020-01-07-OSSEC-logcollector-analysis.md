---
layout: post
title: "OSSEC logcollector模块分析"
categories: "SourceCodeAnalysis"
---

#### 0x00 模块功能：

在主配置文件ossec.conf中设置的localfile会在初始化中注册到内存中的`logreader *logff`数据结构；支持多种日志格式(syslog、iis 、mysql、command)；

```c
  <localfile>
    <log_format>command</log_format>
    <command>df -h</command>
  </localfile>
  ...
  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/apache2/access.log</location>
  </localfile>
```

通过固定的时间间隔检测文件中是否有新写入的数据，调用对应的处理函数将新的数据写入本地消息队列queue/ossec/queue中；如果格式为command会执行对应的命令并将输出结果写入到队列中

PS：Agentd模块会从该队列中读取数据并转发至Server端

#### 0x01 执行流程图：

![ossec-logcollector]({{ '/images/202001/ossec-logcollector_1_1.png' | prepend: site.baseurl }})

#### 0x02 关键数据结构：	

消息队列logr_queue: queue/ossec/queue(用于接收检测到的新数据)

```c
/* Logreader config */
typedef struct _logreader
{
    unsigned int size;	// 文件字节大小
    int ign;
    #ifdef WIN32
    HANDLE h;
    int fd;
    #else
    ino_t fd;		// 保存文件的序列号
    #endif
    /* ffile - format file is only used when
     * the file has format string to retrieve
     * the date,
     */
    char *ffile;	// 时间格式的文件名称，location中包含*、？、[、%等
    char *file;		// <location>/var/log/message</location>
    char *logformat;		// syslog | iis | mysql | command...
    char *djb_program_name;
    char *command;
    char *alias;
    char future;
    char *query;
	
    void (*read)(int i, int *rc, int drop_it);		// 对应的日志处理函数

    FILE *fp;		// 打开对应监控文件的句柄
}logreader;

typedef struct _logreader_config
{
    int agent_cfg;			// 0
    int accept_remote;	// etc/internal_options.conf logcollector.remote_commands=0
    logreader *config;
}logreader_config;
```

#### 0x03 关键功能：

##### 1 LogCollectorConfig -> ReadConfig -> Read_Localfile：

初始化该模块对应的logreader_config结构体，其中logreader *config保存配置文件中每个\<localfile>的内容；在该模块中全局使用`logff`来引用logreader *config中的内容:

```c
char *xml_localfile_location = "location";
char *xml_localfile_command = "command";
char *xml_localfile_logformat = "log_format";
...
logreader *logf;		// 用于保存每个对应的监控文件的信息
log_config = (logreader_config *)d1;		// 该模块的主结构体
os_calloc(2, sizeof(logreader), log_config->config);
logf = log_config->config;
else if(strcmp(node[i]->element,xml_localfile_command) == 0)
{ // 获取command字段中的数据
	os_strdup(node[i]->content, logf[pl].file);
}
else if(strcmp(node[i]->element,xml_localfile_location) == 0)
{	// 检测文件名中是否有格式化字符
	if(strchr(node[i]->content, '*') ||
           strchr(node[i]->content, '?') ||
           strchr(node[i]->content, '['))
        {
        	os_strdup(g.gl_pathv[glob_offset], logf[pl].file);
        }
  else if(strchr(node[i]->content, '%'))
  {
  	os_strdup(node[i]->content, logf[pl].file);
  }
  ...
}
else if(strcasecmp(node[i]->element,xml_localfile_logformat) == 0)
{
    os_strdup(node[i]->content, logf[pl].logformat);
		// 判断日志的格式
    if(strcmp(logf[pl].logformat, "syslog") == 0)
    {
    }
    else if(strcmp(logf[pl].logformat, "generic") == 0)
    {
    }
    else if(strcmp(logf[pl].logformat, "snort-full") == 0)
    ...
}
```

##### 2 获取配置文件中的loop_timeout(遍历文件的时间间隔)、open_file_attempts(打开异常文件尝试的最大次数)、accept_manager_commands：

```c
loop_timeout = getDefine_Int("logcollector","loop_timeout",1, 120);

open_file_attempts = getDefine_Int("logcollector", "open_attempts",2, 998);

accept_manager_commands = getDefine_Int("logcollector", "remote_commands",0, 1);
```

##### 3 移除logff中的重复项，通过logff[pos].logformat设置对应的处理函数：

```c
else if(strcmp(logff[i].logformat, "command") == 0)
{		// 处理特定的command格式
    logff[i].file = NULL;
    logff[i].fp = NULL;
    logff[i].size = 0;
    if(logff[i].command)
    {
        logff[i].read = (void *)read_command;
        verbose("%s: INFO: Monitoring output of command(%d): %s", ARGV0, logff[i].ign, logff[i].command);
    }
		...
}
// 设置不同的read日志处理函数
if(strcmp("snort-full", logff[i].logformat) == 0)
{
    logff[i].read = (void *)read_snortfull;
}
#ifndef WIN32
if(strcmp("ossecalert", logff[i].logformat) == 0)
{
    logff[i].read = (void *)read_ossecalert;
}
#endif
else if(strcmp("nmapg", logff[i].logformat) == 0)
{
    logff[i].read = (void *)read_nmapg;
}
```

##### 4 通过logff[pos].file获取对应文件的inode、size并设置SEEK_END

```c
int handle_file(int i, int do_fseek, int do_log)
{
    int fd;
    struct stat stat_fd;
    #ifndef WIN32
  	// 尝试打开文件
    logff[i].fp = fopen(logff[i].file, "r");
    /* Getting inode number for fp */
    fd = fileno(logff[i].fp);
    if(fstat(fd, &stat_fd) == -1)
		// 获取文件大小以及inode信息
    logff[i].fd = stat_fd.st_ino;
    logff[i].size =  stat_fd.st_size;

    /* Only seek the end of the file if set to. */
    if(do_fseek == 1 && S_ISREG(stat_fd.st_mode))
    {
        // 设置文件流为末尾位置
        #ifndef WIN32
        if(fseek(logff[i].fp, 0, SEEK_END) < 0)
        #endif
    }
    /* Setting ignore to zero */
    logff[i].ign = 0;
    return(0);
}
```

##### 5 主循环-00:使用select设定loop_timeout为超时时间

```c
fp_timeout.tv_sec = loop_timeout;
fp_timeout.tv_usec = 0;

/* Waiting for the select timeout */
if ((r = select(0, NULL, NULL, NULL, &fp_timeout)) < 0)
```

##### 6 主循环-01: 

执行日志格式为command的命令，并调用对应的read处理函数

```c
if(logff[i].command && (f_check %2))
{
    curr_time = time(0);
    if((curr_time - logff[i].size) >= logff[i].ign)
    {
        logff[i].size = curr_time;
        logff[i].read(i, &r, 0);
    }
}
```

使用对应的read处理函数获取对应日志文件中新添加的数据

```c
if((r = fgetc(logff[i].fp)) == EOF)	# 判断是否有新的数据写入
...
logff[i].read(i, &r, 0);	# 处理新添加的数据
```

这里以syslog日志格式的read函数为例：

```c
void *read_syslog(int pos, int *rc, int drop_it)
{
    /* Getting initial file location */
    fgetpos(logff[pos].fp, &fp_pos);
    while(fgets(str, OS_MAXSTR - OS_LOG_HEADER, logff[pos].fp) != NULL)
    {
      	// 判断接受数据的长度
    		...
        debug2("%s: DEBUG: Reading syslog message: '%s'", ARGV0, str);
        /* Sending message to queue */
        if(drop_it == 0)
        {
          	// 将接受的日志发送至队列
            if(SendMSG(logr_queue,str,logff[pos].file,
                        LOCALFILE_MQ) < 0)
						...
        }
				// 处理数据大的情况
      	...
        fgetpos(logff[pos].fp, &fp_pos);
        continue;
    }

    return(NULL);
}
```

##### 7 主循环-02:处理inode变更和大小变更的文件

```c
else if(logff[i].fd != tmp_stat.st_ino)
{	// 检测inode是否发生改变
	snprintf(msg_alert, 512, "ossec: File rotated (inode changed): '%s'.",logff[i].file);
  SendMSG(logr_queue, msg_alert,"ossec-logcollector", LOCALFILE_MQ);
  fclose(logff[i].fp);
  logff[i].fp = NULL;
  // 更新对应的logfile信息
  handle_file(i, 0, 1);
}
else if(logff[i].size > tmp_stat.st_size)
{	// 检测文件大小是否变更
  snprintf(msg_alert, 512, "ossec: File size reduced (inode remained): '%s'.",logff[i].file);
  SendMSG(logr_queue, msg_alert,"ossec-logcollector", LOCALFILE_MQ);
  logff[i].size = tmp_stat.st_size;
  fclose(logff[i].fp);
  logff[i].fp = NULL;
  // 更新对应的logfile信息
  handle_file(i, 1, 1);
}
```

通过logff[pos].ign记录对应文件的错误情况，并移除超过open_file_attempts次数的项

#### 0x04 抽象化的接口：

常见的初始化功能的接口：CREATEPID、信号注册、进入DAEMON模式

handle_file： 更新全局变量logff[pos]中对应文件的序列号和大小，并设置seek位置为结尾

update_fname:  更新格式化的文件名称，并保存到logff[pos].file中

#### 0x05 该模块实现的亮点

如何检查文件中是否有新的数据？

首先会使用handle_file，设置对应的文件stream至EOF的位置，然后在主循环中间隔时间内通过

```
if((r = fgetc(logff[i].fp)) == EOF)
```

判断文件stream当前位置是否还为EOF，接着处理新添加的数据，处理完毕后再使用handle_file更新对应文件stream的位置为EOF。
