---
layout: post
title: "Shiro 1.2.4 rememberMe 反序列化"
categories: "WebSecurity"
---

#### 0x00 前言：

Apache Shiro是提供安全功能的java框架，包括：认证、授权、加密和回话管理等功能，攻击者通过密钥key构造恶意的RememberMe cookie触发人序列化漏洞。

切入点可以通过以下两种方式开始：

* 漏洞的是关于RememberMe，因此查找相关的类
* 使用poc直接触发异常，回溯调用栈

#### 0x01 漏洞分析

通过切入点，可以定位到关键的反序列化触发点在AbstractRememberMeManager中

```java
org.apache.shiro.mgt.AbstractRememberMeManager#convertBytesToPrincipals
protected PrincipalCollection convertBytesToPrincipals(byte[] bytes, SubjectContext subjectContext) {
    if (getCipherService() != null) {
        bytes = decrypt(bytes);		# 解密数据
    }
    return deserialize(bytes);		# 反序列化
}
```

整个漏洞触发的调用链：

```
org.apache.shiro.mgt.DefaultSecurityManager#getRememberedIdentity
org.apache.shiro.mgt.AbstractRememberMeManager#getRememberedPrincipals
org.apache.shiro.web.mgt.CookieRememberMeManager#getRememberedSerializedIdentity   
org.apache.shiro.mgt.DefaultSecurityManager#resolvePrincipals
org.apache.shiro.mgt.DefaultSecurityManager#createSubject(SubjectContext)
org.apache.shiro.subject.Subject.Builder#buildSubject
org.apache.shiro.web.subject.WebSubject$Builder.buildWebSubject(WebSubject.java:148)
org.apache.shiro.web.servlet.AbstractShiroFilter.createSubject(AbstractShiroFilter.java:292)
org.apache.shiro.web.servlet.AbstractShiroFilter.doFilterInternal(AbstractShiroFilter.java:359)
org.apache.shiro.web.servlet.OncePerRequestFilter.doFilter(OncePerRequestFilter.java:125)
```

在调用链中的getRememberedPrincipals会获取构造的输入和反序列化操作

```java
org.apache.shiro.mgt.AbstractRememberMeManager#getRememberedPrincipals
public PrincipalCollection getRememberedPrincipals(SubjectContext subjectContext) {
    PrincipalCollection principals = null;

    try {
        byte[] bytes = this.getRememberedSerializedIdentity(subjectContext);	# 获取传入的输入
        if (bytes != null && bytes.length > 0) {
            principals = this.convertBytesToPrincipals(bytes, subjectContext);	# 针对数据的反序列化
        }
    } catch (RuntimeException var4) {
        principals = this.onRememberedPrincipalFailure(var4, subjectContext);
    }

    return principals;
}
```

使用getRememberedSerializedIdentity获取rememberMe的cookie值

```java
org.apache.shiro.web.mgt.CookieRememberMeManager#getRememberedSerializedIdentity
protected byte[] getRememberedSerializedIdentity(SubjectContext subjectContext) {

    HttpServletRequest request = WebUtils.getHttpRequest(wsc);
    HttpServletResponse response = WebUtils.getHttpResponse(wsc);

    String base64 = getCookie().readValue(request, response);	// 这里获取rememberMe Cookie值
    // Browsers do not always remove cookies immediately (SHIRO-183)
    // ignore cookies that are scheduled for removal
    if (Cookie.DELETED_COOKIE_VALUE.equals(base64)) return null;

    if (base64 != null) {
        base64 = ensurePadding(base64);
```

已经知道接收数据的接口，接着查看数据的解密流程：

```java
org.apache.shiro.mgt.AbstractRememberMeManager#decrypt
protected byte[] decrypt(byte[] encrypted) {
    byte[] serialized = encrypted;
    CipherService cipherService = getCipherService();
    if (cipherService != null) {
        ByteSource byteSource = cipherService.decrypt(encrypted, getDecryptionCipherKey());
        serialized = byteSource.getBytes();
    }
    return serialized;
}
```

这里使用的是AesCipherService.decrypt进行解密，如果知道key就可以进行特定cookie的构造，在AbstractRememberMeManager的构造函数中，会使用以下默认key

```java
private static final byte[] DEFAULT_CIPHER_KEY_BYTES = Base64.decode("kPH+bIxk5D2deZiIxcaaaA==");
```

此时已经了解到：

* 如何获取传入的cookie值
* 对cookie值的加解密
* 反序列化的触发点

目前还有最后一个问题，如何从最外层触发整个调用链，通过观察整个调用链即可得知：

```
org.apache.shiro.web.servlet.AbstractShiroFilter.doFilterInternal(AbstractShiroFilter.java:359)
```

该过滤器是在web.xml中进行配置的：

```xml
<filter>
    <filter-name>ShiroFilter</filter-name>
    <filter-class>org.apache.shiro.web.servlet.ShiroFilter</filter-class>
</filter>
<filter-mapping>
    <filter-name>ShiroFilter</filter-name>
    <url-pattern>/*</url-pattern>
</filter-mapping>
```

那么整个流程就很清晰了，总结如下：

* 通过AbstractShiroFilter过滤器，进入整个回话的处理流程
* 直接获取cookie中的rememeberMe的值
* 最终通过convertBytesToPrincipals进行反序列化操作，在反序列化前会使用decrypt进行解密操作

#### 0x02 总结

该漏洞直接通过框架的默认过滤器中的cookie处理流程，触发整个漏洞链。

虽然cookie有加密机制，但是由于该key大部分都会使用默认的，因此攻击者可以搜集常用的key进行利用

