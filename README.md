
## About

Detection script for CVE-2021-42278 and CVE-2021-42287

## Usage
```
The detection script uses the domain account credentials to determine the possibility of the vulnerabilities.

usage: noPac-detection.py [-h] [-debug] -dc-ip <IP address> -targetUser <Target Username> credentials

optional arguments:
  -h, --help            show this help message and exit
  -debug                Turn DEBUG output ON

mandatory:
  -dc-ip <IP address>   IP of the domain controller to use. Useful if you can't translate the FQDN.specified in the
                        account parameter will be used
  -targetUser <Target Username>
                        The target user to retrieve the PAC of
  credentials           domain/username[:password]. Valid domain credentials to use for grabbing targetUser's PAC

```
>Note: All mandatory values are necessary for the script to function, supportes debug mode,the TargetUser can be any domain connected user account, always set domain as domain.local For Ex: megacorp.local, cars.local etc.,

***
### Examples:

+  `$ python noPac-detection.py MARVEL.local/pparker:P#%DG323c89 -targetUser fcastle -dc-ip 192.168.10.13`
![1.png](./resources/1.png)

***
