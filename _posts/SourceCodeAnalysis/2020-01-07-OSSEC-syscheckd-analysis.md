---
layout: post
title: "OSSEC syscheckd模块分析"
categories: "SourceCodeAnalysis"
---

#### 0x00 模块功能描述：

通过hashtable保存需要监控目录下所有文件的hash值；linux通过inotify实现realtime功能，windows使用ReadDirectoryChangesW实现；模块产生的所有消息都会发送至本地队列queue/ossec/queue中

#### 0x01 模块流程图

![ossec-syscheckd]({{ '/images/202001/ossec-syscheckd_1_1.png' | prepend: site.baseurl }})

#### 0x02 模块流程

1. 初始化：解析命令行参数、daemon模式、创建本地队列(queue/ossec/queue)、注册信号事件处理、PIDFILE创建、输出监控目录信息及需要实时监控的目录
2. Read_Syscheck_Config初始化syscheck_config结构体、rootcheck_init运行rootcheck功能模块
3. 根据scan_on_start使用send_sk_db进行db存储的初始化：保存realtime的目录名并添加至inotify实例中；保存监控目录下的所有文件至syscheck.fp hashtable中。如果设置了scan_time和scan_day则判断是否已经扫描过
4. 主循环1:判断当前是否需要执行rootcheck功能；run_rk_check
5. 主循环2:判断当前时间是否需要执行syscheck功能，如果没有初始化db则调用send_sk_db；发送启动信息至本地队列，并调用run_dbcheck进行扫描：遍历所有目录中所有文件检测是否有hash值变化的，存在则发送至本地队列；发送扫描结束信息至本地队列
6. 主循环3:处理realtime标记的目录，使用select进行fd的监控，并使用realtime_process进行处理：通过read接收inotify实例检测到发生变化的目录，并使用realtime_checksumfile检测对应文件是否发生了改变将结果发送至本地队列

#### 0x03 模块中的数据结构

该模块使用的主要数据结构syscheck_config，主要是针对监控目录信息及配置信息

```c
typedef struct _rtfim
{
    int fd;					// Linux:inotify_init()；inotify实例
    void *dirtb;		// hashtable；保存需要realtime监控的目录名；windows保存的是文件的handler
    #ifdef WIN32
    HANDLE evt;			// Windows使用回调函数的方式来处理实时监控的问题
    #endif
}rtfim;

typedef struct _config
{
    int tsleep;            /* sleep for sometime for daemon to settle */
    int sleep_after;
    int rootcheck;         /* set to 0 when rootcheck is disabled */
    int disabled;          /* is syscheck disabled? */
    int scan_on_start;		 // 是否需要创建syscheck data db；
    int realtime_count;

    int time;              /* frequency (secs) for syscheck to run */
  												 // 每次syscheck执行的时间间隔
    int queue;             /* file descriptor of socket to write to queue */
  												 // 队列为queue/ossec/queue

    int *opts;             /* attributes set in the <directories> tag element */
  												 // 保存对应索引文件的属性标记，因为属性都为boolean类型，使用位标记就可以

    char *workdir;         /* set to the DEFAULTDIR (/var/ossec) */
    char *remote_db;
    char *db;

    char *scan_day;        /* run syscheck on this day eg: sunday, saturday, monday default：NULL */
    char *scan_time;       /* run syscheck at this time eg: 21pm, 8:30, 12am default: NULL */

    char **ignore;         /* list of files/dirs to ignore */
  												 // 排除目录下特定的子目录和文件的监控
    void **ignore_regex;   /* regex of files/dirs to ignore */
  												 // 排除支持正则的匹配方式

    char **dir;            /* array of directories to be scanned */
  												 // 监控的文件夹列表；配合索引与对应的opts监控属性进行映射
    void **filerestrict;

    /* Windows only registry checking */
    #ifdef WIN32
    char **registry_ignore;         /* list of registry entries to ignore */
    void **registry_ignore_regex;   /* regex of registry entries to ignore */
    char **registry;                /* array of registry entries to be scanned */
    FILE *reg_fp;
    #endif

    void *fp;							// hashtable；保存待监控目录中所有文件的hash值

    rtfim *realtime;

    char *prefilter_cmd;		// 检测每个文件都会进行执行的命令，会严重影响性能

}syscheck_config;
```

#### 0x04 模块关键功能

<strong>send_sk_db: syscheck.fp保存监控目录下所有文件的hash值；处理标记为realtime的目录，linux：inotify、windows：ReadDirectoryChangesW</strong>

处理的主循环：

```c
		do
    {
        if(read_dir(syscheck.dir[i], syscheck.opts[i], syscheck.filerestrict[i]) == 0)
        {
            #ifdef WIN32
            if(syscheck.opts[i] & CHECK_REALTIME)
            {
                realtime_adddir(syscheck.dir[i]);
            }
            #endif
        }
        i++;
    }while(syscheck.dir[i] != NULL);
```

read_dir的实现：遍历目录下的文件，如果标记了realtime则使用realtime_adddir处理；并使用read_file进行处理

```c
    /* Checking for real time flag. */
    if(opts & CHECK_REALTIME)
    {
        #ifdef USEINOTIFY
        realtime_adddir(dir_name);
        #endif
    }
		...
		while((entry = readdir(dp)) != NULL)
    {
				...
        strncpy(s_name, entry->d_name, PATH_MAX - dir_size -2);
        /* Check integrity of the file */
        read_file(f_name, opts, restriction);
    }
```

read_file: 通过hash值判断文件是否发生变更

```c
    if(S_ISDIR(statbuf.st_mode))	// 如果是目录则使用read_dir处理
    {
        return(read_dir(file_name, opts, restriction));
    }
...
// 获取对应文件的sha1值和md5值
												if(OS_MD5_SHA1_File(file_name, syscheck.prefilter_cmd, mf_sum, sf_sum) < 0)
                        {
                            strncpy(mf_sum, "xxx", 4);
                            strncpy(sf_sum, "xxx", 4);
                        }
// 尝试从hashtable中获取该文件的old hash
buf = OSHash_Get(syscheck.fp, file_name);
        if(!buf)
        {
						...
            // 不存在添加至hashtable中
            if(OSHash_Add(syscheck.fp, strdup(file_name), strdup(alert_msg)) <= 0)
            /* changed by chris st_size int to long, 912 to 916*/
            snprintf(alert_msg, 916, "%ld:%d:%d:%d:%s:%s %s",
                     opts & CHECK_SIZE?(long)statbuf.st_size:0,
                     opts & CHECK_PERM?(int)statbuf.st_mode:0,
                     opts & CHECK_OWNER?(int)statbuf.st_uid:0,
                     opts & CHECK_GROUP?(int)statbuf.st_gid:0,
                     opts & CHECK_MD5SUM?mf_sum:"xxx",
                     opts & CHECK_SHA1SUM?sf_sum:"xxx",
                     file_name);
            // 发送相关信息至本地队列
            send_syscheck_msg(alert_msg);
        }
        else
        {
						// 存在old hash，则判断文件是否变更
            /* If it returns < 0, we will already have alerted. */
            if(c_read_file(file_name, buf, c_sum) < 0)
                return(0);
						// 判断新旧hash是否相同
            if(strcmp(c_sum, buf+6) != 0)
            {
                ...
                /* Sending the new checksum to the analysis server */
              	// 如果不同发送新的文件hash信息至本地队列
                snprintf(alert_msg, 916, "%s %s", c_sum, file_name);
                send_syscheck_msg(alert_msg);
            }
        }
```

<strong>windows版的realtime_adddir实现：</strong>

```c
    win32rtfim *rtlocald;
    os_calloc(1, sizeof(win32rtfim), rtlocald);
		// 获取目录的句柄
    rtlocald->h = CreateFile(dir,
                             FILE_LIST_DIRECTORY,
                             FILE_SHARE_DELETE|FILE_SHARE_READ|FILE_SHARE_WRITE,
                             NULL,
                             OPEN_EXISTING,
                             FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OVERLAPPED,
                             NULL);

    /* Setting key for hash. */
    wdchar[32] = '\0';
    snprintf(wdchar, 32, "%d", (int)rtlocald->overlap.Offset);
		...
    /* Adding final elements to the hash. */
    os_strdup(dir, rtlocald->dir);
		// 添加至realtime的hashtable中
    OSHash_Add(syscheck.realtime->dirtb, strdup(wdchar), rtlocald);
    /* Adding directory to be monitored. */
		// 具体的windows realtime的封装
    realtime_win32read(rtlocald);
```

realtime_win32read：

```c
    rc = ReadDirectoryChangesW(rtlocald->h,
                               rtlocald->buffer,	// 通过该buffer来接收事件触发的通知内容
                               sizeof(rtlocald->buffer) / sizeof(TCHAR),
                               TRUE,
                               FILE_NOTIFY_CHANGE_FILE_NAME|FILE_NOTIFY_CHANGE_DIR_NAME|FILE_NOTIFY_CHANGE_SIZE|FILE_NOTIFY_CHANGE_LAST_WRITE,
                               0,
                               &rtlocald->overlap,  // 可以传递给回调函数
                               RTCallBack);	// 异步io完成时，在可提醒的线程中的apc队列中调用该回调函数
```

这里使用接收通知的方式为可提醒io，通过WaitForSingleObjectEx来接收执行线程中apc队列的函数；这里于linux不同每次调用ReadDirectoryChangesW相当于发送一次请求，当请求触发完成时会调用次回调函数，因此在回调函数中需要再调用一次ReadDirectoryChangesW才能继续进行对应目录的监控。

```c
void CALLBACK RTCallBack(DWORD dwerror, DWORD dwBytes, LPOVERLAPPED overlap)
{
    int lcount;
    size_t offset = 0;

    char *ptfile;
    char wdchar[32 +1];
    char final_path[MAX_LINE +1];

    win32rtfim *rtlocald;

    PFILE_NOTIFY_INFORMATION pinfo;
    TCHAR finalfile[MAX_PATH];
		...
    /* Getting hash to parse the data. */
    wdchar[32] = '\0';
    snprintf(wdchar, 32, "%d", (int)overlap->Offset);
  	// 获取对应文件的win32rtfim结构体
    rtlocald = OSHash_Get(syscheck.realtime->dirtb, wdchar);
		...
    do
    {
        pinfo = (PFILE_NOTIFY_INFORMATION) &rtlocald->buffer[offset];
        offset += pinfo->NextEntryOffset;
			  // 获取发生变动的文件名
        lcount = WideCharToMultiByte(CP_ACP, 0, pinfo->FileName,
                                     pinfo->FileNameLength / sizeof(WCHAR),
                                     finalfile, MAX_PATH - 1, NULL, NULL);
        finalfile[lcount] = TEXT('\0');
        /* Change forward slashes to backslashes on finalfile. */
        ptfile = strchr(finalfile, '\\');
        while(ptfile)
        {
            *ptfile = '/';
            ptfile++;

            ptfile = strchr(ptfile, '\\');
        }

        final_path[MAX_LINE] = '\0';
        snprintf(final_path, MAX_LINE, "%s/%s", rtlocald->dir, finalfile);
				// 这里检查对应文件的hash值是否发生了变更
        /* Checking the change. */
        realtime_checksumfile(final_path);
        /*
        if(pinfo->Action == FILE_ACTION_ADDED)
        else if(pinfo->Action == FILE_ACTION_REMOVED)
        else if(pinfo->Action == FILE_ACTION_MODIFIED)
        else if(pinfo->Action == FILE_ACTION_RENAMED_OLD_NAME)
        else if(pinfo->Action == FILE_ACTION_RENAMED_NEW_NAME)
        else
        */
    }while(pinfo->NextEntryOffset != 0);
	  // 这里重新发送异步io请求
    realtime_win32read(rtlocald);
    return;
}
```

<strong>linux版的realtime_adddir实现：</strong>

```c
    if(syscheck.realtime->fd < 0)
    {
      	// 如果inotify的实例不存在则退出
        return(-1);
    }
    else
    {
				// 将目录添加至inotify的实例中
        wd = inotify_add_watch(syscheck.realtime->fd,
                               dir,
                               REALTIME_MONITOR_FLAGS);
        if(wd < 0)
        {
            merror("%s: ERROR: Unable to add directory to real time "
                   "monitoring: '%s'. %d %d", ARGV0, dir, wd, errno);
        }
        else
        {
            /* Entry not present. */
            // 将目录名保存到realtime的hashtable中
            if(!OSHash_Get(syscheck.realtime->dirtb, wdchar))
            {
                OSHash_Add(syscheck.realtime->dirtb, strdup(wdchar), ndir);
                debug1("%s: DEBUG: Directory added for real time monitoring: "
                       "'%s'.", ARGV0, ndir);
            }
        }
    }
```

<strong>主循环01:</strong>

定期执行rootkitcheck

```c
        if(syscheck.rootcheck)
        {
            if(((curr_time - prev_time_rk) > rootcheck.time) || run_now)
            {
                run_rk_check();
                prev_time_rk = time(0);
            }
        }
```

<strong>主循环02:  定期执行syscheck扫描功能</strong>

```c
        // 扫描间隔
        if(((curr_time - prev_time_sk) > syscheck.time) || run_now)
        {
            /* We need to create the db, if scan on start is not set. */
            if(syscheck.scan_on_start == 0)
            {   // 如果未初始化则进行db的初始化工作
                send_sk_db();
                syscheck.scan_on_start = 1;
            }
            else
            {
                #ifdef WIN32
                /* Checking for registry changes on Windows */
                // windows上所有的hash内容保存在db文件中
                os_winreg_check();
                #endif
                /* Checking for changes */
                // 遍历监控目录中所有文件是否发生变更
                run_dbcheck();
            }
        }
```

run_dbcheck：使用read_dir遍历所有目录下的文件：

```c
    while(syscheck.dir[i] != NULL)
    {
        read_dir(syscheck.dir[i], syscheck.opts[i], syscheck.filerestrict[i]);
        i++;
    }
```

<strong>主循环03: 处理realtime监控的目录</strong>

linux实现逻辑：使用select进行fd的扫描，使用realtime_process处理检测到的事件

```c
        #ifdef USEINOTIFY
        // linux版本
        if(syscheck.realtime && (syscheck.realtime->fd >= 0))
        {
						/* zero-out the fd_set */
            FD_ZERO (&rfds);
            FD_SET(syscheck.realtime->fd, &rfds);
            run_now = select(syscheck.realtime->fd + 1, &rfds,
                             NULL, NULL, &selecttime);
						...
            else if (FD_ISSET (syscheck.realtime->fd, &rfds))
            {
                realtime_process();
            }
        }
        else
        {
            sleep(SYSCHECK_WAIT);
        }
```

realtime_process：获取事件中对应的文件名，检查文件hash值是否发生了改变，将对应的消息发送至本地队列：

```c
    // 使用read接收具体的inofiy事件
		len = read(syscheck.realtime->fd, buf, REALTIME_EVENT_BUFFER);
    if (len < 0)
    {
        merror("%s: ERROR: Unable to read from real time buffer.", ARGV0);
    }
    else if (len > 0)
    {
        while (i < len)
        {
            event = (struct inotify_event *) &buf[i];

            if(event->len)
            {
                snprintf(wdchar, 32, "%d", event->wd);
                snprintf(final_name, MAX_LINE, "%s/%s",
                         (char *)OSHash_Get(syscheck.realtime->dirtb, wdchar),
                         event->name);
                // 检测文件hash是否发生了改变
                realtime_checksumfile(final_name);
            }
        }
    }
```

Windows实现的逻辑：使用WaitForSingleObjectEx接收触发的事件

```c
        #elif WIN32
        if(syscheck.realtime && (syscheck.realtime->fd >= 0))
        {
            run_now = WaitForSingleObjectEx(syscheck.realtime->evt, SYSCHECK_WAIT * 1000, TRUE);
            if(run_now == WAIT_FAILED)
            {
                merror("%s: ERROR: WaitForSingleObjectEx failed (for realtime fim).", ARGV0);
                sleep(SYSCHECK_WAIT);
            }
        }
        else
        {
            sleep(SYSCHECK_WAIT);
        }
```

#### 0x05 好的实现思路：

windows中使用ReadDirectoryChangesW函数的可提醒io方式进行文件的实时监控，函数原型：

```c
BOOL WINAPI ReadDirectoryChangesW(
  _In_        HANDLE                          hDirectory,
  _Out_       LPVOID                          lpBuffer,
  _In_        DWORD                           nBufferLength,
  _In_        BOOL                            bWatchSubtree,
  _In_        DWORD                           dwNotifyFilter,
  _Out_opt_   LPDWORD                         lpBytesReturned,
  _Inout_opt_ LPOVERLAPPED                    lpOverlapped,
  _In_opt_    LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
);
```

该接口有3种接收通知方式：

- 使用可提醒IO, 在参数*lpComletionRoutine*指定一个回调函数。当*ReadDirectoryChangesW*异步请求完成时，驱动会将指定的回调函数(*lpComletionRoutine*)投递到调用线程的APC队列中
- 在*OVERLAPPED*结构中的hEvent成员中设置一个事件句柄，使用*GetOverlappedResult* 获取完成结果。
- 使用IO完成端口，通过*GetQueuedComletionStatus*获取完成结果。

通过设置lpCompletionRoutine函数进行事件触发时的回调处理，同时可以将lpOverlapped传递给回调函数。

详细的使用可参考：https://www.jianshu.com/p/9f6529127f1a

