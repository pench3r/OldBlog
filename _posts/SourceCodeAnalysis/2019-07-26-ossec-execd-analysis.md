---
layout: post
title: "OSSEC execd功能模块分析"
categories: "SourceCodeAnalysis"
---

#### 0x00 前言

ossec是开源的HIDS框架，通过分析源码可以掌握常见的HIDS架构，以及各个模块的功能具体实现的方案，对于HIDS安全开发有很好的借鉴作用。

代码git地址：https://github.com/ossec/ossec-hids/tree/v2.8.2/src/os_execd

#### 0x01 模块的功能

active response功能对应这个模块.通过/var/ossec/queue/alerts/execq实时接收命令信息，解析命令并执行。接收的信息格式如下：

```
name arg1 arg2 ...
```

ar.conf中定义name与命令的映射：

```
# ar.conf中的内容
restart-ossec0 - restart-ossec.sh - 0			# 对应linux系统
restart-ossec0 - restart-ossec.cmd - 0		# 对应windows系统
host-deny600 - host-deny.sh - 600
firewall-drop600 - firewall-drop.sh - 600
```

可执行的命令都保存在/var/ossec/active-response/bin目录下：

```
disable-account.sh  ip-customblock.sh  ossec-tweeter.sh  route-null.sh
firewall-drop.sh    ipfw_mac.sh        pf.sh
host-deny.sh        ipfw.sh            restart-ossec.sh
```

<strong>功能演示</strong>

为了方便演示，下载[源码](https://github.com/ossec/ossec-hids/archive/v2.8.2.tar.gz)后，在agent端中src/os_execd/execd.c中使用verbose添加如下输出:

![fastjson]({{ '/images/201907/ossec-execd_1_1.png' | prepend: site.baseurl }})

添加完后再编译安装(演示在两台虚拟机中，安装模式分别为server,agent)；server安装模式时需要开启active-response功能(默认选项即为开启)：

![fastjson]({{ '/images/201907/ossec-execd_1_2.png' | prepend: site.baseurl }})

安装完毕后；默认安装路径在/var/ossec中，在server端和agent端使用manage_agents(/var/ossec/bin目录下)命令分别进行agent添加(server)和key的导入(agent)这里不截图了，添加成功后可以在server端看到如下信息：

![fastjson]({{ '/images/201907/ossec-execd_1_3.png' | prepend: site.baseurl }})

显示了已经连接的agent和可用的active-response命令。这里向agent发送重启命令：

```
root@pwn:/var/ossec# bin/agent_control -R 001

OSSEC HIDS agent_control: Restarting agent: 001
```

查看agent端的日志/var/ossec/logs/ossec.log:

![fastjson]({{ '/images/201907/ossec-execd_1_4.png' | prepend: site.baseurl }})

可以看到解析后的命令及参数，最终会在agent上执行/var/ossec/active-response/bin/restart-ossec.sh脚本

其他的active-response可以自定义为触发特殊规则会进行执行对应命令：

```
  <active-response>
    <!-- Firewall Drop response. Block the IP for
       - 600 seconds on the firewall (iptables,
       - ipfilter, etc).
      -->
    <command>firewall-drop</command>
    <location>local</location>
    <level>6</level>
    <timeout>600</timeout>
  </active-response>
```

如果触发规则等级>=6时，就可以执行对应的active-response。

#### 0x02 模块总览

- 核心功能：通过队列接收消息，解析消息再执行对应命令

- 流程图：

  ![fastjson]({{ '/images/201907/ossec-execd_1_5.png' | prepend: site.baseurl }})

#### 0x03 模块的主要框架

下面3部分是抽象出来的主要部分，还有一些细节进行了过滤，了解主框架后，可以根据该框架实现该模块功能，不必拘泥于现有的代码。

* <strong>模块程序的初始化</strong>

  OS_SetName设置全局变量__local_name，用于标示当前程序的名称：

  ```c
  __local_name = ossec-execd
  ```

  解析命令行参数：

  ```c
      while((c = getopt(argc, argv, "Vtdhfu:g:D:c:")) != -1){
          switch(c){
              case 'V':
                  print_version();
                  break;
  						...
          }
      }
  ```

  判断ossec组是否存在并设置为当前进程的有效组：

  ```c
      /* Check if the group given is valid */
      gid = Privsep_GetGroup(group);
      /* Privilege separation */
      if (Privsep_SetGroup(gid) < 0) {
  ```

  通过ExecdConfig读取主配置文件/etc/conf/ossec.conf,判断是否开启了Active-Response，以及初始化repeated_offenders_timeout(缓存执行过的命令):

  ```c
  disable_entry = OS_GetOneContentforElement(&xml, "ossec_config", "active-response", "disabled");
  if (strcmp(disable_entry, "yes") == 0) {
              is_disabled = 1;
  } else if (strcmp(disable_entry, "no") == 0) {
              is_disabled = 0;
  }
  ...
  repeated_t = OS_GetOneContentforElement(&xml, "ossec_config", "active-response", "repeated_offenders");
  repeated_offenders_timeout[j] = atoi(tmpt);
  ```

  使用StartSIG2在当前进程中注册相关信号处理：

  ```c
      pidfile = process_name;	# 当前进程ossec-execd
      signal(SIGHUP, SIG_IGN);
      signal(SIGINT, func);
      signal(SIGQUIT, func);
      signal(SIGTERM, func);
      signal(SIGALRM, func);
      signal(SIGPIPE, HandleSIGPIPE);
  ```

  goDaemon进入demo模式：

  ```c
      pid = fork();
      if (pid) {
          exit(0);			# 退出父进程
      }
      /* Become session leader */
      if (setsid() < 0) 
      /* Fork again */
      pid = fork();
  		if (pid) {
          exit(0);	# 继续退出父进程
      }
      /* Dup stdin, stdout and stderr to /dev/null */
      if ((fd = open("/dev/null", O_RDWR)) >= 0) {
          dup2(fd, 0);
          dup2(fd, 1);
          dup2(fd, 2);
          close(fd);
      }
      /* Go to / */
      if (chdir("/") == -1)
  ```

  CreatePID创建对应的PIDFILE:

  ```c
      if(isChroot())
      {
          snprintf(file,255,"%s/%s-%d.pid",OS_PIDFILE,name,pid);
      }
      else
      {
          snprintf(file,255,"%s%s/%s-%d.pid",DEFAULTDIR,
                  OS_PIDFILE,name,pid);
      }
  ```

  StartMQ创建核心队列，默认为/var/ossec/queue/alerts/execq:

  ```c
      /* Start exec queue */
      if ((m_queue = StartMQ(EXECQUEUEPATH, READ)) < 0) {
  ```

* <strong>模块相关配置文件加载</strong>

  在初始化的过程中已经加载过主配置文件，判断active-response功能是否开启、初始化repeated_offenders_timeout。另外加载一个配置文件/var/ossec/etc/shared/ar.conf，该配置文件用于定义name与命令的映射，server与client之间传递的是name。

  ReadExecConfig用于解析配置文件，将映射保存在exec_name、exec_cmd、exec_timeout数组中

  ```c
      while (fgets(buffer, OS_MAXSTR, fp) != NULL) {
  		# 命令的格式为: name - command - timeout\n
          /* Clean up the buffer */
          tmp_str = strstr(buffer, " - ");
          /* Set the name */
          strncpy(exec_names[exec_size], str_pt, OS_FLSIZE);
          /* Search for ' ' and - */
          tmp_str = strstr(tmp_str, " - ");
          // Directory traversal test
          if (w_ref_parent_folder(str_pt)) {
  					...
           } else {
              /* Write the full command path */
              snprintf(exec_cmd[exec_size], OS_FLSIZE,
                       "%s/%s",
                       AR_BINDIRPATH,
                       str_pt);
  						# 检查命令文件是否可以访问
                  exec_cmd[exec_size][0] = '\0';
              }
          }
          tmp_str = strchr(tmp_str, '\n');
          /* Get the exec timeout */
          exec_timeout[exec_size] = atoi(str_pt);
          /* Check if name is duplicated */
  				# 检测是否有重复命令，存在则进行重置
      }
  ```

  使用w_ref_parent_folder来阻止目录穿越漏洞

* <strong>主循环</strong>

  循环开始进行子进程执行情况的统计更新(子进程为执行命令)

  ```c
          /* Cleaning up any child. */
          while (childcount)
          {
              wp = waitpid((pid_t) -1, NULL, WNOHANG);
              if (wp > 0)
              {
                  childcount--;
              }
          }
  ```

  通过waitpid非阻塞的状态获取执行情况；通过timeout_list进行超时任务的检测执行

  ```c
          timeout_node = OSList_GetFirstNode(timeout_list);
          while(timeout_node)
          {
              /* Timeouted */
              if(timeout_node is timeout)
              {
                  ExecCmd(list_entry->command);
                  OSList_DeleteCurrentlyNode(timeout_list);
                  childcount++;
              }
              else
              {
                  timeout_node = OSList_GetNextNode(timeout_list);
              }
          }
  ```

  执行并删除超时的节点；select检测主队列中是否有需要执行的任务：

  ```c
          /* Adding timeout */
          if(select(q+1, &fdset, NULL, NULL, &socket_timeout) == 0)
          {
              /* Timeout .. */
              continue;
          }
          ...
          /* Receiving the message */
          if(OS_RecvUnix(q, buffer, OS_MAXSTR, 0) == -1)
  ```

  解析接收的命令使用GetCommandbyName获取到实际需要执行的脚本：

  ```c
      for (; i < exec_size; i++) {
          if (strcmp(name, exec_names[i]) == 0) {
              *timeout = exec_timeout[i];
              return (exec_cmd[i]);
          }
      }
  ```

  最后使用ExecCmd进行命令的执行，选择是否需要添加至timeout_list中。

#### 0x04 模块代码中的关键点

* <strong>数据结构</strong>

  Timeout_list用于保存超时任务：

  ```c
  typedef struct _OSListNode
  {
      struct _OSListNode *next;
      struct _OSListNode *prev;
      void *data;
  }OSListNode;
  
  
  typedef struct _OSList
  {
      OSListNode *first_node;
      OSListNode *last_node;
      OSListNode *cur_node;
  
      int currently_size;
      int max_size;
  
      void (*free_data_function)(void *data);
  }OSList;
  ```

  repeated_hash用于保存执行过命令的次数：

  ```c
  /* Node structure */
  typedef struct _OSHashNode
  {
      struct _OSHashNode *next;
  
      void *key;
      void *data;
  }OSHashNode;
  
  
  typedef struct _OSHash
  {
      unsigned int rows;
      unsigned int initial_seed;
      unsigned int constant;
  
      OSHashNode **table;
  }OSHash;
  ```

  类似于key-value的结构

* /var/ossec/queue/alerts/execq是该功能模块对外的唯一接口，信息会由agentd模块和analysis模块产生

* ar.conf配置文件中定义name与命令的映射，定义格式为：

  ```restart-ossec0 - restart-ossec.sh - 0
  name - cmd - timeout
  
  例子：
  restart-ossec0 - restart-ossec.sh - 0
  ```

  该cmd会与目录/var/ossec/active-response/bin/进行拼接形成最后的执行命令.

  w_ref_parent_folder用来防止目录穿越：

  ```c
     switch (path[0]) {
      case '\0':
          return 0;
      case '.':
          switch (path[1]) {
          case '\0':
              return 0;
          case '.':
              switch (path[2]) {
              case '\0':
                  return 1;
              case '/':
                  return 1;
              }
          }
      }
      for (str = path; ptr = strstr(str, "/.."), ptr; str = ptr + 3) {
          if (ptr[3] == '\0' || ptr[3] == '/') {
              return 1;
          }
      }
      return 0;
  ```

* 主循环中的timeout_list(用于保存timeout值大于0的任务)，如果后续接收的命令存在于该结构体时，则会通过repeated_offenders_timeout对应的hashtable更新命令时间设置

  ```c
          while(timeout_node)
          {
              timeout_data *list_entry;
  
              list_entry = (timeout_data *)timeout_node->data;
              if(命令和参数与该节点的相同)
              {
                  /* Means we executed this command before
                   * and we don't need to add it again.
                   */
                  added_before = 1;
                  /* updating the timeout */
                  list_entry->time_of_addition = curr_time;
  
                  if(hash存在 并且 命令的参数为'-')
                  {
                      snprintf(rkey, 255, "%s%s", list_entry->command[0], timeout_args[3]);
                    	# 更新或添加至hashtable中
                  }
                  break;
              }
              /* Continue with the next entry in timeout list*/
              timeout_node = OSList_GetNextNode(timeout_list);
          }
  ```

  以及在最后执行命令时，会根据映射命令的timeout值来决定是否添加到timeout_list和hashtable中

  ```c
          if(!added_before)
          {
              /* executing command */
              ExecCmd(cmd_args);
              /* We don't need to add to the list if the timeout_value == 0 */
              if(timeout_value)
              {
                  snprintf(rkey, 255, "%s%s", timeout_args[0],
                                              timeout_args[3]);
  								# 判断是否需要添加至hashtable中
                  /* Creating the timeout entry */
                  timeout_entry->command = timeout_args;
                  timeout_entry->time_of_addition = curr_time;
                  timeout_entry->time_to_block = timeout_value;
                  /* Adding command to the timeout list */
                  if(!OSList_AddData(timeout_list, timeout_entry))
              }
  ```



#### 0x05 分层的模块结构

Ps:下面出现的模块指函数或者子功能；而功能模块指实现的特定功能的程序

* 初始化阶段的多个功能都封装成公共模块、便于其他功能模块进行调用

  ```
  goDaemon: 开启demo模式
  verbose： 日志记录
  StartSIG2： 注册信号事件
  ...
  ```

* 该功能模块中也封装了一些内部模块，而这些内部模块的实现还是依靠公共模块实现

  内部ExecdConfig模块中：

  ```
  OS_ReadXML: 解析xml配置文件
  OS_GetOneContentforElement：获取特定节点的内容
  ```

  外部StartMQ模块中：

  ```
  OS_BindUnixDomain: 来创建和绑定socket实现于外部通信的功能
  
  OS_BindUnixDomain本身由socket的原生函数构建的
  ```


