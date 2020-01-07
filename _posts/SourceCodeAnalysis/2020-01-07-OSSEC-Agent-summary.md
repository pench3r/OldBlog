---
layout: post
title: "OSSEC Agent功能总结"
categories: "SourceCodeAnalysis"
---

该篇可以针对所有模块做一个总结，也算是对ossec agent端的功能总结。

首先介绍最后一个模块，agentd模块：将其他模块联合起来，统一进行信息的转发处理。

#### 0x00 Agentd模块功能分析

* 初始化：daemon模式、groupid、chroot、user、主队列(read /queue/ossec/queue)、PIDFILE、key列表、server网络连接测试、exec队列(write /queue/alert/execq)
* 与server建立连接、发送启动信息至server
* 监听server端回传的信息：先解密、再分别处理不同的信息类型
  * active response：写入exec队列，由execd模块进行信息处理
  * restart syscheck：调用syscheckd模块执行systemcheck
  * file update：更新指定文件内容
* 监听主队列的信息：
  * 主队列中的信息为agent上syscheckd、logcollectord、execd模块产生的
  * 将主队列接收到的信息，加密发送至server端

相比其他模块该模块功能比较简单，通过队列与其他模块之前打通关联

#### 0x01 回顾agent端的功能

在InstallAgent.sh中看到与Agent相关的可执行程序：

```bash
cp -pr client-agent/ossec-agentd ${DIR}/bin/
cp -pr os_auth/agent-auth ${DIR}/bin/
cp -pr logcollector/ossec-logcollector ${DIR}/bin/
cp -pr syscheckd/ossec-syscheckd ${DIR}/bin/
cp -pr os_execd/ossec-execd ${DIR}/bin/
cp -pr ./init/ossec-client.sh ${DIR}/bin/ossec-control
cp -pr addagent/manage_agents ${DIR}/bin/
cp -pr ../contrib/util.sh ${DIR}/bin/
cp -pr external/lua/src/ossec-lua ${DIR}/bin/
cp -pr external/lua/src/ossec-luac ${DIR}/bin/
chown root:${GROUP} ${DIR}/bin/util.sh
chmod +x ${DIR}/bin/util.sh
```

<strong>涉及到的模块功能：</strong>

```
ossec-execd ossec-agentd ossec-logcollector ossec-syscheckd
```

<strong>每个模块的功能总结：</strong>

* ossec-execd模块

  通过execq队列接收消息，解析消息再执行对应命令; 执行的命令脚本保存在`active-response/bin/`目录下，例如`restart-ossec.sh`脚本用于重启agent

* ossec-logcollector模块

  通过检测指定日志文件是否有新数据的写入，通过对应的日志处理函数写入主队列`queue/ossec/queue`中；模块也可以指定command类型，执行对应命令并将结果写入到主队列中

* ossec-syschecked模块

  通过hashtable保存监控文件的hash值，变动的文件信息会写入主队列`queue/ossec/queue`中；该模块也支持指定文件的实时监控

* ossec-agentd模块

  先获取agent的密钥信息，通过密钥检测与server的连接；

  接着分别处理队列和server端发来的信息：

  * 从`Server`接收相关的控制消息(Restart syscheck、active response、文件更新)，并执行对应的操作
  * 从主队列`queue/ossec/queue`接收其他模块(monitory、secure、syslog、syslogtcp)写入的消息并转发至Server端

#### 0x02 Ossec Agent架构图

![ossec-agent]({{ '/images/202001/ossec-agent_2_1.png' | prepend: site.baseurl }})

#### 0x03 总结

目前分析完Ossec Agent的所有功能模块，发现还是有一些可借鉴的地方：

* 代码通过分层的架构，针对常用的模块功能进行层层封装；例如针对每个模块的配置文件初始化、对于加密和解密的操作，底层会单独把加密算法再封装一层
* 模块代码保存在各自的目录下，通过常用模块的更好的实现模块的逻辑实现；每个模块的实现都是通过固定的模式，并配对专门的配置数据结构用于服务模块运行
* 代码同样进行不同平台的接口封装，支持windows、linux
* 代码针对每层封装的接口都进行了测试，提高了接口的稳定性和实用性
* 各个模块的通信通过队列实现
* 监控文件是否有新数据写入，通过判定固定位置是否还为EOF标示

以上都是自己觉得实现比较好的地方，也给自己提供了思路储备，当然该架构无法满足中大型场景中的：海量机器和海量数据。
