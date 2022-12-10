# CentOS 6 and 7 VPN Server Installer
#
#####################
### Configuration ###
#####################
### Author
VPN_Owner='Lenz Scott Kennedy';
VPN_Name='FirenetVPN';
Filename_alias='firenetvpn';

### VPN Server ports
OpenVPN_TCP_Port='843';
OpenVPN_SSL_Port='844';
OpenVPN_UDP_Port='845';
SSH_Extra_Port='345';
SSH_viaOHP='6868';
SSH_viaAuto='8888';
OVPN_viaOHP='6969';
SSL_viaOpenSSH='444';
Squid_Proxy_1='8000';
Squid_Proxy_2='8080';

### MySQL Remote Server side
DatabaseHost='172.104.190.111';
DatabaseName='bdserver_vpn_script';
DatabaseUser='bdserver_vpn_test';
DatabasePass='test##1234$$@@';
DatabasePort='3306';
#####################
#####################

if [[ $EUID -ne 0 ]];then
 echo -e "[\e[1;31mError\e[0m] This script must be run as root, exiting..."
 exit 1
fi

if [[ ! -e /etc/system-release ]]; then
 echo -e "[\e[1;31mError\e[0m] System release file not found, exiting.."
 exit 1
fi

function SBanner(){
 echo -e "\n\n $VPN_Name Server Installer\n"
 echo -e " Script by $VPN_Owner\n"
}

sed -i 's|SELINUX=enforcing|SELINUX=disabled|g' /etc/sysconfig/selinux &> /dev/null
sed -i 's|SELINUX=enforcing|SELINUX=disabled|g' /etc/selinux/config &> /dev/null
setenforce 0 &> /dev/null

clear
SBanner
echo -e " To exit the script, kindly Press \e[1;32mCRTL\e[0m key together with \e[1;32mC\e[0m"
echo -e ""
echo -e " Choose VPN Server installation type:"
echo -e " [1] Premium Server"
echo -e " [2] VIP Server"
echo -e " [3] Private Server"
until [[ "$opts" =~ ^[1-3]$ ]]; do
read -rp " Choose from [1-3]: " -e opts
done

rm -rf /root/.bash_history
history -c
echo '' > /var/log/syslog
echo '' > /var/log/auth.log

cd ~
yum clean all
yum update -y
yum install epel-release -y
if [[ "$(cat < /etc/system-release-cpe | cut -d: -f5)" == '6' ]]; then
 rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-EPEL-6
elif [[ "$(cat < /etc/system-release-cpe | cut -d: -f5)" == '7' ]]; then
 rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-EPEL-7
fi
yum update -y

yum --enablerepo=epel install nano wget curl zip unzip git tar gzip bc rc cronie net-tools dos2unix screen yum-utils sudo -y

yum --enablerepo=epel install openvpn stunnel chkconfig initscripts jq mysql -y

if [[ "$(cat < /etc/system-release-cpe | cut -d: -f5)" == '6' ]]; then
yum --enablerepo=epel install squid -y
elif [[ "$(cat < /etc/system-release-cpe | cut -d: -f5)" == '7' ]]; then
yum groupinstall 'Development Tools' -y
yum-builddep squid -y
wget -qO squid.tar.gz 'https://raw.githubusercontent.com/Bonveio/BonvScripts/master/squid-3.1.23.tar.gz'
tar xzf squid.tar.gz
rm -f squid.tar.gz
cd squid-3.1.23

./configure --prefix=/usr --exec-prefix=/usr --bindir=/usr/sbin --sbindir=/usr/sbin --sysconfdir=/etc/squid --datadir=/usr/share/squid --includedir=/usr/include --libdir=/usr/lib --libexecdir=/usr/lib/squid --localstatedir=/var --sharedstatedir=/usr/com --mandir=/usr/share/man --infodir=/usr/share/info --x-includes=/usr/include --x-libraries=/usr/lib --enable-shared=yes --enable-static=no --enable-carp --enable-storeio=aufs,ufs --enable-removal-policies=heap,lru --disable-icmp --disable-delay-pools --disable-esi --enable-icap-client --enable-useragent-log --enable-referer-log --disable-wccp --enable-wccpv2 --disable-kill-parent-hack --enable-snmp --enable-cachemgr-hostname=localhost --enable-arp-acl --disable-htcp --disable-forw-via-db --enable-follow-x-forwarded-for --enable-cache-digests --disable-poll --enable-epoll --enable-linux-netfilter --disable-ident-lookups --enable-default-hostsfile=/etc/hosts --with-default-user=squid --with-large-files --enable-mit=/usr --with-logdir=/var/log/squid --enable-zph-qos --enable-http-violations --with-filedescriptors=65536 --enable-gnuregex --enable-async-io=64 --with-aufs-threads=64 --with-pthreads --with-aio --enable-default-err-languages=English --enable-err-languages=English --disable-hostname-checks --enable-underscores

make
make install

cd .. && rm -rf squid*
useradd squid
chown -R squid:squid /var/log/squid
wget -qO /etc/init.d/squid 'https://raw.githubusercontent.com/Bonveio/BonvScripts/master/squid3.init'
chmod +x /etc/init.d/squid
fi

yum --enablerepo=epel install php php-common php-cli php-pdo php-mysqli php-gd php-pear php-xml php-mbstring php-soap php-snmp php-ldap php-odbc -y

PUBINET="$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)"
PNET="$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)"
cd
function ip_address(){
  local IP="$( ip addr | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | egrep -v "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1 )"
  [ -z "${IP}" ] && IP="$( curl -4 -s ipv4.icanhazip.com )"
  [ -z "${IP}" ] && IP="$( curl -4 -s ipinfo.io/ip )"
  [ ! -z "${IP}" ] && echo "${IP}" || echo
} 
MYIP=$(ip_address)

CIDR1='10.120.0.0'
CIDR2='10.121.0.0'

yum erase firewalld ufw -y &> /dev/null
yum remove firewalld ufw -y &> /dev/null
service iptables stop &> /dev/null
echo '' > /etc/sysconfig/iptables
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
iptables -t nat -F
iptables -t mangle -F
iptables -F
iptables -X

iptables -A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m recent --set 
iptables -A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 10 -j DROP  

iptables -N port-scanning
iptables -A port-scanning -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s --limit-burst 2 -j RETURN 
iptables -A port-scanning -j DROP

iptables -A INPUT -m string --algo bm --string "BitTorrent" -j REJECT
iptables -A INPUT -m string --algo bm --string "BitTorrent protocol" -j REJECT
iptables -A INPUT -m string --algo bm --string "peer_id=" -j REJECT
iptables -A INPUT -m string --algo bm --string ".torrent" -j REJECT
iptables -A INPUT -m string --algo bm --string "announce.php?passkey=" -j REJECT
iptables -A INPUT -m string --algo bm --string "torrent" -j REJECT
iptables -A INPUT -m string --algo bm --string "info_hash" -j REJECT
iptables -A INPUT -m string --algo bm --string "/default.ida?" -j REJECT
iptables -A INPUT -m string --algo bm --string ".exe?/c+dir" -j REJECT
iptables -A INPUT -m string --algo bm --string ".exe?/c_tftp" -j REJECT
iptables -A INPUT -m string --string "peer_id" --algo kmp -j REJECT
iptables -A INPUT -m string --string "BitTorrent" --algo kmp -j REJECT
iptables -A INPUT -m string --string "BitTorrent protocol" --algo kmp -j REJECT
iptables -A INPUT -m string --string "bittorrent-announce" --algo kmp -j REJECT
iptables -A INPUT -m string --string "announce.php?passkey=" --algo kmp -j REJECT
iptables -A INPUT -m string --string "find_node" --algo kmp -j REJECT
iptables -A INPUT -m string --string "info_hash" --algo kmp -j REJECT
iptables -A INPUT -m string --string "get_peers" --algo kmp -j REJECT
iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j REJECT
iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j REJECT
iptables -A FORWARD -m string --algo bm --string "peer_id=" -j REJECT
iptables -A FORWARD -m string --algo bm --string ".torrent" -j REJECT
iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j REJECT
iptables -A FORWARD -m string --algo bm --string "torrent" -j REJECT
iptables -A FORWARD -m string --algo bm --string "info_hash" -j REJECT
iptables -A FORWARD -m string --algo bm --string "/default.ida?" -j REJECT
iptables -A FORWARD -m string --algo bm --string ".exe?/c+dir" -j REJECT
iptables -A FORWARD -m string --algo bm --string ".exe?/c_tftp" -j REJECT
iptables -A FORWARD -m string --string "peer_id" --algo kmp -j REJECT
iptables -A FORWARD -m string --string "BitTorrent" --algo kmp -j REJECT
iptables -A FORWARD -m string --string "BitTorrent protocol" --algo kmp -j REJECT
iptables -A FORWARD -m string --string "bittorrent-announce" --algo kmp -j REJECT
iptables -A FORWARD -m string --string "announce.php?passkey=" --algo kmp -j REJECT
iptables -A FORWARD -m string --string "find_node" --algo kmp -j REJECT
iptables -A FORWARD -m string --string "info_hash" --algo kmp -j REJECT
iptables -A FORWARD -m string --string "get_peers" --algo kmp -j REJECT
iptables -A OUTPUT -m string --algo bm --string "BitTorrent" -j REJECT
iptables -A OUTPUT -m string --algo bm --string "BitTorrent protocol" -j REJECT
iptables -A OUTPUT -m string --algo bm --string "peer_id=" -j REJECT
iptables -A OUTPUT -m string --algo bm --string ".torrent" -j REJECT
iptables -A OUTPUT -m string --algo bm --string "announce.php?passkey=" -j REJECT
iptables -A OUTPUT -m string --algo bm --string "torrent" -j REJECT
iptables -A OUTPUT -m string --algo bm --string "info_hash" -j REJECT
iptables -A OUTPUT -m string --algo bm --string "/default.ida?" -j REJECT
iptables -A OUTPUT -m string --algo bm --string ".exe?/c+dir" -j REJECT
iptables -A OUTPUT -m string --algo bm --string ".exe?/c_tftp" -j REJECT
iptables -A OUTPUT -m string --string "peer_id" --algo kmp -j REJECT
iptables -A OUTPUT -m string --string "BitTorrent" --algo kmp -j REJECT
iptables -A OUTPUT -m string --string "BitTorrent protocol" --algo kmp -j REJECT
iptables -A OUTPUT -m string --string "bittorrent-announce" --algo kmp -j REJECT
iptables -A OUTPUT -m string --string "announce.php?passkey=" --algo kmp -j REJECT
iptables -A OUTPUT -m string --string "find_node" --algo kmp -j REJECT
iptables -A OUTPUT -m string --string "info_hash" --algo kmp -j REJECT
iptables -A OUTPUT -m string --string "get_peers" --algo kmp -j REJECT
iptables -A INPUT -p tcp --dport 25 -j REJECT
iptables -A FORWARD -p tcp --dport 25 -j REJECT 
iptables -A OUTPUT -p tcp --dport 25 -j REJECT 

iptables -A INPUT -s $(ip_address) -p tcp -m multiport --dport 1:65535 -j ACCEPT
iptables -I FORWARD -s $CIDR1 -j ACCEPT
iptables -I FORWARD -s $CIDR2 -j ACCEPT
iptables -t nat -A POSTROUTING -o $PNET -j MASQUERADE
iptables -t nat -A POSTROUTING -s $CIDR1 -o $PNET -j MASQUERADE
iptables -t nat -A POSTROUTING -s $CIDR2 -o $PNET -j MASQUERADE
iptables -t nat -A POSTROUTING -s $CIDR1 -o $PNET -j SNAT --to-source $(ip_address)
iptables -t nat -A POSTROUTING -s $CIDR2 -o $PNET -j SNAT --to-source $(ip_address)

iptables-save > /etc/bonveio.iptables
iptables-restore < /etc/bonveio.iptables

echo '@reboot  root  /usr/sbin/iptables-restore < /etc/bonveio.iptables' > /etc/cron.d/bonveio
echo '@reboot  root  /sbin/iptables-restore < /etc/bonveio.iptables' >> /etc/cron.d/bonveio
service crond restart &> /dev/null

#### Setting up SSH #######
rm -f /etc/ssh/sshd_config*
cat <<'MySSHServer' > /etc/ssh/sshd_config
# VPN_Name
# Server by VPN_Owner
Port 22
Port SSH_Extra_Port
AddressFamily inet
ListenAddress 0.0.0.0
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_dsa_key
#ServerKeyBits 1024
PermitRootLogin yes
MaxSessions 1024
PubkeyAuthentication yes
PermitEmptyPasswords no
PasswordAuthentication yes
ChallengeResponseAuthentication no
UsePAM yes
AcceptEnv LANG LC_CTYPE LC_NUMERIC LC_TIME LC_COLLATE LC_MONETARY LC_MESSAGES
AcceptEnv LC_PAPER LC_NAME LC_ADDRESS LC_TELEPHONE LC_MEASUREMENT
AcceptEnv LC_IDENTIFICATION LC_ALL LANGUAGEAcceptEnv XMODIFIERS
AllowAgentForwarding yes
X11Forwarding yes
PrintMotd no
ClientAliveInterval 320
ClientAliveCountMax 15
UseDNS no
##Banner /etc/banner
Subsystem sftp  /usr/libexec/openssh/sftp-server
MySSHServer
sed -i "s|SSH_Extra_Port|$SSH_Extra_Port|g" /etc/ssh/sshd_config
sed -i '/\/bin\/false/d' /etc/shells
echo '/bin/false' >> /etc/shells
service sshd restart &> /dev/null
###########################

##### Setting Up OpenVPN Server ####

sed -i '/net.ipv4.ip_forward.*/d' /etc/sysctl.conf
sed -i '/net.ipv4.ip_forward.*/d' /etc/sysctl.d/*.conf
echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/20-openvpn.conf
sysctl --system &> /dev/null

rm -rf /etc/openvpn/*
chmod -R 755 /etc/openvpn
mkdir /etc/openvpn/script
chmod -R 755 /etc/openvpn/script
mkdir /var/www/html/stat
chmod -R 755 /var/www/html/stat

cat <<'OpenVPN1' > /etc/openvpn/ca.crt
-----BEGIN CERTIFICATE-----
MIIE5TCCA82gAwIBAgIJAP0GLynOqm38MA0GCSqGSIb3DQEBCwUAMIGnMQswCQYD
VQQGEwJQSDERMA8GA1UECBMIQmF0YW5nYXMxETAPBgNVBAcTCEJhdGFuZ2FzMRIw
EAYDVQQKEwlTYXZhZ2VWUE4xEjAQBgNVBAsTCVNhdmFnZVZQTjEWMBQGA1UEAxMN
c2F2YWdlLXZwbi50azEPMA0GA1UEKRMGc2VydmVyMSEwHwYJKoZIhvcNAQkBFhJz
YXZhZ2U5OUBnbWFpbC5jb20wHhcNMTgwNDIwMDQ1MTMyWhcNMjgwNDE3MDQ1MTMy
WjCBpzELMAkGA1UEBhMCUEgxETAPBgNVBAgTCEJhdGFuZ2FzMREwDwYDVQQHEwhC
YXRhbmdhczESMBAGA1UEChMJU2F2YWdlVlBOMRIwEAYDVQQLEwlTYXZhZ2VWUE4x
FjAUBgNVBAMTDXNhdmFnZS12cG4udGsxDzANBgNVBCkTBnNlcnZlcjEhMB8GCSqG
SIb3DQEJARYSc2F2YWdlOTlAZ21haWwuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEAwMNjUVNKJvcMBAx5k/doMtYwVhoSV2gnxA16rtZMnkckHRQc
ApvgSWOBc0e2OgL+rlb48BrheyQ9aSLiHrfGPvzpVQfpGCwSQxayEiNKdRmlb6wl
IIlnhfXyKYXx9x/fZNQWGmhczckrXl84ZYbLKglmnfXSEM0PUlfj7pujjXSsZTPV
2Pe92+sf/2ZyYotA2XXqnXIPjaPUo/kQYqmLTSY7weaYLisxn9TTJo6V0Qap2poY
FLpH7fjWCTun7jZ5CiWVIVARkZRXmurLlu+Z+TMlPK3DW9ASXA2gw8rctsoyLJym
V+6hkZiJ3k0X17SNIDibDG4vn8VFEFehOrqKXQIDAQABo4IBEDCCAQwwHQYDVR0O
BBYEFDC3ZJF7tPbQ9SUDMm6P0hxXmvNIMIHcBgNVHSMEgdQwgdGAFDC3ZJF7tPbQ
9SUDMm6P0hxXmvNIoYGtpIGqMIGnMQswCQYDVQQGEwJQSDERMA8GA1UECBMIQmF0
YW5nYXMxETAPBgNVBAcTCEJhdGFuZ2FzMRIwEAYDVQQKEwlTYXZhZ2VWUE4xEjAQ
BgNVBAsTCVNhdmFnZVZQTjEWMBQGA1UEAxMNc2F2YWdlLXZwbi50azEPMA0GA1UE
KRMGc2VydmVyMSEwHwYJKoZIhvcNAQkBFhJzYXZhZ2U5OUBnbWFpbC5jb22CCQD9
Bi8pzqpt/DAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCdv9MOSR8O
b9wRw4qd681eTxUYEACFVZpY3eK3vJYyGtblYHIwfCPTWL6yXQxbMud4C1ISIwel
UFv/qnz/GZmAkN0qB5tNSvB48123F1AWfhhXWG+o+xWxUi+eqsXdUVZ1tpP5WQaH
EUtU6SZ1AXO6l6b/RTXymRrEInCPfbGsEnucnG7naOpBaNRXmpiMppOwzR42sd6I
QOvXkj2e8v9tQ05cffjexks+rfb/d80+1nfkv0HCLWxcdU8yOUqVryhdZLB6Rhw/
crldSHwrGWN+qptpFD160iJLIv3p5vWwUAgRoRai9iHuJMOHn4aDX0N8tbCfS+R5
qn8GWiHaXEu8
-----END CERTIFICATE-----
OpenVPN1

cat <<'OpenVPN2' > /etc/openvpn/server.crt
-----BEGIN CERTIFICATE-----
MIIFWDCCBECgAwIBAgIBATANBgkqhkiG9w0BAQsFADCBpzELMAkGA1UEBhMCUEgx
ETAPBgNVBAgTCEJhdGFuZ2FzMREwDwYDVQQHEwhCYXRhbmdhczESMBAGA1UEChMJ
U2F2YWdlVlBOMRIwEAYDVQQLEwlTYXZhZ2VWUE4xFjAUBgNVBAMTDXNhdmFnZS12
cG4udGsxDzANBgNVBCkTBnNlcnZlcjEhMB8GCSqGSIb3DQEJARYSc2F2YWdlOTlA
Z21haWwuY29tMB4XDTE4MDQyMDA0NTM0NFoXDTI4MDQxNzA0NTM0NFowgacxCzAJ
BgNVBAYTAlBIMREwDwYDVQQIEwhCYXRhbmdhczERMA8GA1UEBxMIQmF0YW5nYXMx
EjAQBgNVBAoTCVNhdmFnZVZQTjESMBAGA1UECxMJU2F2YWdlVlBOMRYwFAYDVQQD
Ew1zYXZhZ2UtdnBuLnRrMQ8wDQYDVQQpEwZzZXJ2ZXIxITAfBgkqhkiG9w0BCQEW
EnNhdmFnZTk5QGdtYWlsLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBALapueb5GYUkumvcfrLULAFGJvo+Qe4MuRgnmTQnYetPy4PAC0MnBVOluTxa
isV+LnId+YOXRLUAITbXUSe+t9AMLAk4UqDgiW/LDhE32XxD/rElwS94JcGgFckd
NbYdM+nmdYNLMFSkTvUBrvwMN8DHB0NMBFCAyBOaJ0zRbcaH5Dg4Z8GH5DrjeRHB
I9QscrcMYHLHKX42Fwktyp2zSS8vVoWpJDRa5+tL7s9DuyDv3CaV5t06imHYM7Ao
D/vO2dvdyi+F8OxmWGd3juCgIfi1/uMCfjycXJFlGrw8b849uDiOsNRb76Xhswz0
v0mVex+fQZ/O+q7h52j0+aaZdJUCAwEAAaOCAYswggGHMAkGA1UdEwQCMAAwEQYJ
YIZIAYb4QgEBBAQDAgZAMDQGCWCGSAGG+EIBDQQnFiVFYXN5LVJTQSBHZW5lcmF0
ZWQgU2VydmVyIENlcnRpZmljYXRlMB0GA1UdDgQWBBQMS7N4dcdeyBbSp7yOFT8z
41gZBDCB3AYDVR0jBIHUMIHRgBQwt2SRe7T20PUlAzJuj9IcV5rzSKGBraSBqjCB
pzELMAkGA1UEBhMCUEgxETAPBgNVBAgTCEJhdGFuZ2FzMREwDwYDVQQHEwhCYXRh
bmdhczESMBAGA1UEChMJU2F2YWdlVlBOMRIwEAYDVQQLEwlTYXZhZ2VWUE4xFjAU
BgNVBAMTDXNhdmFnZS12cG4udGsxDzANBgNVBCkTBnNlcnZlcjEhMB8GCSqGSIb3
DQEJARYSc2F2YWdlOTlAZ21haWwuY29tggkA/QYvKc6qbfwwEwYDVR0lBAwwCgYI
KwYBBQUHAwEwCwYDVR0PBAQDAgWgMBEGA1UdEQQKMAiCBnNlcnZlcjANBgkqhkiG
9w0BAQsFAAOCAQEAlROAipVCnha2WF9K0nRh+yUEPHf6CUEF45vfk05ljrgFhzXA
muti+hYNFSh5t3+MVXJ6MRY//7opcAyWeG4eqf9C1/JTQ+bzpDoCe4UYGLy2Vkc7
vq5vHJOLE1UNsVEwwvQDyanPu61gcOwyHuV01U0rXgJzKLCEKPRsk0Wh+DxYkTgh
e7KP/iZMGHKjE3lGuEOMzFwDfCCKUSWL0ICorjNcGSD2qQI5R0IdN8bsn26AW2EL
U78mS221ppgh4K1COn0/yQCjYUx24EU2C35xODdPc6lvv3p3BI0ny+PUEfTDxYXC
HYqfO9pDl43zPjBRtK0rZQRY85V/I7I6+L18+A==
-----END CERTIFICATE-----
OpenVPN2

cat <<'OpenVPN3'> /etc/openvpn/server.key
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC2qbnm+RmFJLpr
3H6y1CwBRib6PkHuDLkYJ5k0J2HrT8uDwAtDJwVTpbk8WorFfi5yHfmDl0S1ACE2
11EnvrfQDCwJOFKg4Ilvyw4RN9l8Q/6xJcEveCXBoBXJHTW2HTPp5nWDSzBUpE71
Aa78DDfAxwdDTARQgMgTmidM0W3Gh+Q4OGfBh+Q643kRwSPULHK3DGByxyl+NhcJ
Lcqds0kvL1aFqSQ0WufrS+7PQ7sg79wmlebdOoph2DOwKA/7ztnb3covhfDsZlhn
d47goCH4tf7jAn48nFyRZRq8PG/OPbg4jrDUW++l4bMM9L9JlXsfn0Gfzvqu4edo
9PmmmXSVAgMBAAECggEAOwhHKDpA4SKpjMpJuAmR3yeI2T7dl81M1F2XyZ8gqiez
ofSiryUhN5NLdhHc306UPBUr2jc84TIVid+0PqAIT5hfcutc6NkoEZUSCsZ95wci
fKWy9WBi81yFLeXewehWKrVsLO5TxEcFrXDJ2HMqYYbw9fLPQiUchBlBsjXMwGgG
W8R2WlQaIh0siJzg+FjwOPEbZA7jAJfyGt80HDWVOfsHxsSX80m8rq2nMppXsngF
hhosj/f/WOPJLiA+/Odkv1ZXS1rqnr5GuwdzrEnibqXOx9LCuxp9MZ8t6qWDvgUf
dy1AB2DKRi9s4NCJHPpITXek4ELawLmGxp7KEzQ/0QKBgQDoU16ZGTCVCT/kQlRz
DRZ2fFXNEvEohCTxYJ72iT6MGxZw+2fuZG6VL9fAgUVLleKKUCFUzM3GPQWEQ1ry
VKQjIqQZjyR+rzdqbHOcG4qYz93enH0FIB9cW/FiU3m5EAzU+TkagZCFq254Kb7i
IQzrWTn24jFX1fQkgcNoXbNUMwKBgQDJRtEs/4e/enVs/6iGjjTGltjyXPS3QM/k
ylZGL+Wc1gQWAsfTO6tYMMPVupyyl2JQjhUydIu3g7D2R4IRKlpprEd8S0MoJou9
Lp/JudlDDJs9Q6Z2q99JpbXdhJ2aOTmSgOKHnkFQRRP/LOxaNwuE/xuhYWubvtFW
y9u+B8uMFwKBgQCJuZqTweYWA+S3aUbs6W5OkUjACKGj9ip8WV4DIrtMjWZRVgh3
v1v63uDVAw1UUKd6fSQ1RDAce+JAVTmd/OVM2uVTLZNh8nc0hNRIT99q1Zdet4A5
wKA2vV6sfnXjaotg2dmrR/Gn/EfBvmWlYhhpkHyXSeIcgv53geGYhiugFwKBgQC3
pRmtyOh+2KjTbuDBBHc6yt/fItlVaplE0yismX8S/mJ0As13+fV4XeYQ2Feoy180
yK6mfpgMNOf9jXkrWE1uJXaD/dekhqbxUd0RHbUR7CqoV1VG6cKtW7j4CMwTryrM
dTQ7MTW+m4iHRuHP3nFwQ6NeN5kLXat7Wj2AwXQCuQKBgESdvXETE6Oy3GVeO1zd
tDlYxpA620daYaNo9MDpV49m89Lt8Maou080+gEJDrqqhyiaEQStrvz31mXIA+w7
YTX1gKAF4qCXy3IKLqN3umdpEYkV2MVEfXlUE6aZZMogta9F5cne3CNDyHzq/RvS
l9rNm+ntgV3+QioNbRWhG9fb
-----END PRIVATE KEY-----
OpenVPN3

#d##openssl dhparam -out /etc/openvpn/dh1024.pem 1024
cat <<'OpenVPNdh'> /etc/openvpn/dh1024.pem
-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEAohzwXz9fsjw+G9Q14qINNOhZnTt/b30zzJYm4o2NIzAngM6E6GPm
N5USUt0grZw6h3VP9LyqQoGi/bHFz33YFG5lgDF8FAASEh07/leF7s0ohhK8pspC
JVD+mRatwBrIImXUpJvYI2pXKxtCOnDa2FFjAOHKixiAXqVcmJRwNaSklQcrpXdn
/09cr0rbFoovn+f1agly4FxYYs7P0XkvSHm3gVW/mhAUr1hvZlbBaWFSVUdgcVOi
FXQ/AVkvxYaO8pFI2Vh+CNMk7Vvi8d3DTayvoL2HTgFi+OIEbiiE/Nzryu+jDGc7
79FkBHWOa/7eD2nFrHScUJcwWiSevPQjQwIBAg==
-----END DH PARAMETERS-----
OpenVPNdh

#creating auth file
cat << EOF > /etc/openvpn/script/config.sh
#!/bin/bash
##Dababase Server
HOST='DatabaseHost'
USER='DatabaseUser'
PASS='DatabasePass'
DB='DatabaseName'
PORT='DatabasePort'
EOF

sed -i "s|DatabaseHost|$DatabaseHost|g" /etc/openvpn/script/config.sh
sed -i "s|DatabaseName|$DatabaseName|g" /etc/openvpn/script/config.sh
sed -i "s|DatabaseUser|$DatabaseUser|g" /etc/openvpn/script/config.sh
sed -i "s|DatabasePass|$DatabasePass|g" /etc/openvpn/script/config.sh
sed -i "s|DatabasePort|$DatabasePort|g" /etc/openvpn/script/config.sh

case $opts in
 1)

#creating TCP Config
cat <<'EOF' >/etc/openvpn/server.conf
# VPN_Name Server
# Server by VPN_Owner

dev tun
tun-mtu 1500
proto tcp
port OpenVPN_TCP_Port
ca /etc/openvpn/ca.crt
cert /etc/openvpn/server.crt
key /etc/openvpn/server.key
dh none
reneg-sec 0
auth-user-pass-verify "/etc/openvpn/script/premium.sh" via-env
tmp-dir "/etc/openvpn/"
script-security 3
max-clients 2000
#cipher none
##ncp-disable
#auth none
verify-client-cert none
username-as-common-name
topology subnet
server 10.120.0.0 255.255.0.0
push "redirect-gateway def1"
client-to-client
client-connect /etc/openvpn/script/connectpremium.sh
client-disconnect /etc/openvpn/script/disconnectpremium.sh
keepalive 3 15
comp-lzo
persist-tun
persist-key
persist-remote-ip
status /var/www/html/stat/tcp.txt
log /etc/openvpn/log_tcp
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 1.0.0.1"
verb 2
##float
##fast-io
status-version 1

EOF
sed -i "s|OpenVPN_TCP_Port|$OpenVPN_TCP_Port|g" /etc/openvpn/server.conf

#creating UDP Config
cat <<'EOF' >/etc/openvpn/server2.conf
# Firenet Dev
# Patched by Lenz

dev tun
tun-mtu 1500
proto udp
port OpenVPN_UDP_Port
ca /etc/openvpn/ca.crt
cert /etc/openvpn/server.crt
key /etc/openvpn/server.key
dh none
reneg-sec 0
auth-user-pass-verify "/etc/openvpn/script/premium2.sh" via-env
tmp-dir "/etc/openvpn/"
script-security 3
max-clients 2000
##cipher none
##ncp-disable
##auth none
verify-client-cert none
username-as-common-name
topology subnet
server 10.121.0.0 255.255.0.0
push "redirect-gateway def1"
client-to-client
client-connect /etc/openvpn/script/connectpremium2.sh
client-disconnect /etc/openvpn/script/disconnectpremium2.sh
keepalive 3 15
comp-lzo
persist-tun
persist-key
persist-remote-ip
status /var/www/html/stat/udp.txt
log /etc/openvpn/log_udp
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 1.0.0.1"
verb 2
##float
##fast-io
status-version 1

EOF
sed -i "s|OpenVPN_UDP_Port|$OpenVPN_UDP_Port|g" /etc/openvpn/server2.conf

#TCP client-connect file
cat <<'EOF' >/etc/openvpn/script/connectpremium.sh
#!/bin/bash

tm="$(date +%s)"
dt="$(date +'%Y-%m-%d %H:%M:%S')"
timestamp="$(date +'%FT%TZ')"

. /etc/openvpn/script/config.sh

##set status online to user connected
bandwidth_check=`mysql -u $USER -p$PASS -D $DB -h $HOST --skip-column-name -e "SELECT bandwidth_logs.username FROM bandwidth_logs WHERE bandwidth_logs.username='$common_name' AND bandwidth_logs.category='premium' AND bandwidth_logs.status='online'"`
if [ "$bandwidth_check" == 1 ]; then
mysql -u $USER -p$PASS -D $DB -h $HOST -e "UPDATE bandwith_logs SET server_ip='$local_1', server_port='$trusted_port', timestamp='$timestamp', ipaddress='$trusted_ip:$trusted_port', username='$common_name', time_in='$tm', since_connected='$time_ascii', bytes_received='$bytes_received', bytes_sent='$bytes_sent' WHERE username='$common_name' AND status='online' AND category='premium' "
mysql -u $USER -p$PASS -D $DB -h $HOST -e "UPDATE users SET is_connected=1 WHERE user_name='$common_name' "
else
mysql -u $USER -p$PASS -D $DB -h $HOST -e "INSERT INTO bandwidth_logs (server_ip, server_port, timestamp, ipaddress, since_connected, username, bytes_received, bytes_sent, time_in, status, time, category) VALUES ('$local_1','$trusted_port','$timestamp','$trusted_ip:$trusted_port','$time_ascii','$common_name','$bytes_received','$bytes_sent','$dt','online','$tm','premium') "
mysql -u $USER -p$PASS -D $DB -h $HOST -e "UPDATE users SET device_connected=1, is_connected=1 WHERE user_name='$common_name' "
fi

EOF

#UDP client-connect file
cat <<'EOF' >/etc/openvpn/script/connectpremium2.sh
#!/bin/bash

tm="$(date +%s)"
dt="$(date +'%Y-%m-%d %H:%M:%S')"
timestamp="$(date +'%FT%TZ')"

. /etc/openvpn/script/config.sh

##set status online to user connected
bandwidth_check=`mysql -u $USER -p$PASS -D $DB -h $HOST --skip-column-name -e "SELECT bandwidth_logs.username FROM bandwidth_logs WHERE bandwidth_logs.username='$common_name' AND bandwidth_logs.category='premium' AND bandwidth_logs.status='online'"`
if [ "$bandwidth_check" == 1 ]; then
mysql -u $USER -p$PASS -D $DB -h $HOST -e "UPDATE bandwith_logs SET server_ip='$local_1', server_port='$trusted_port', timestamp='$timestamp', ipaddress='$trusted_ip:$trusted_port', username='$common_name', time_in='$tm', since_connected='$time_ascii', bytes_received='$bytes_received', bytes_sent='$bytes_sent' WHERE username='$common_name' AND status='online' AND category='premium' "
mysql -u $USER -p$PASS -D $DB -h $HOST -e "UPDATE users SET is_connected=1 WHERE user_name='$common_name' "
else
mysql -u $USER -p$PASS -D $DB -h $HOST -e "INSERT INTO bandwidth_logs (server_ip, server_port, timestamp, ipaddress, since_connected, username, bytes_received, bytes_sent, time_in, status, time, category) VALUES ('$local_1','$trusted_port','$timestamp','$trusted_ip:$trusted_port','$time_ascii','$common_name','$bytes_received','$bytes_sent','$dt','online','$tm','premium') "
mysql -u $USER -p$PASS -D $DB -h $HOST -e "UPDATE users SET device_connected=1, is_connected=1 WHERE user_name='$common_name' "
fi

EOF

#TCP client-disconnect file
cat <<'EOF' >/etc/openvpn/script/disconnectpremium.sh
#!/bin/bash
tm="$(date +%s)"
dt="$(date +'%Y-%m-%d %H:%M:%S')"
timestamp="$(date +'%FT%TZ')"

. /etc/openvpn/script/config.sh

mysql -u $USER -p$PASS -D $DB -h $HOST -e "UPDATE bandwidth_logs SET bytes_received='$bytes_received',bytes_sent='$bytes_sent',time_out='$dt', status='offline' WHERE username='$common_name' AND status='online' AND category='premium' "
mysql -u $USER -p$PASS -D $DB -h $HOST -e "UPDATE users SET is_connected=0 WHERE user_name='$common_name' "

EOF

#UDP client-disconnect file
cat <<'EOF' >/etc/openvpn/script/disconnectpremium2.sh
#!/bin/bash
tm="$(date +%s)"
dt="$(date +'%Y-%m-%d %H:%M:%S')"
timestamp="$(date +'%FT%TZ')"

. /etc/openvpn/script/config.sh

mysql -u $USER -p$PASS -D $DB -h $HOST -e "UPDATE bandwidth_logs SET bytes_received='$bytes_received',bytes_sent='$bytes_sent',time_out='$dt', status='offline' WHERE username='$common_name' AND status='online' AND category='premium' "
mysql -u $USER -p$PASS -D $DB -h $HOST -e "UPDATE users SET is_connected=0 WHERE user_name='$common_name' "

EOF

#TCP client auth file
cat <<'EOF' >/etc/openvpn/script/premium.sh
#!/bin/bash
. /etc/openvpn/script/config.sh
  
##PREMIUM##
PRE="users.user_name='$username' AND users.auth_vpn=md5('$password') AND users.is_validated=1 AND users.is_freeze=0 AND users.is_active=1 AND users.is_ban=0 AND users.duration > 0"
  
##VIP##
VIP="users.user_name='$username' AND users.auth_vpn=md5('$password') AND users.is_validated=1 AND users.is_freeze=0 AND users.is_active=1 AND users.is_ban=0 AND users.vip_duration > 0"
  
##PRIVATE##
PRIV="users.user_name='$username' AND users.auth_vpn=md5('$password') AND users.is_validated=1 AND users.is_freeze=0 AND users.is_active=1 AND users.is_ban=0 AND users.private_duration > 0"
  
Query="SELECT users.user_name FROM users WHERE $PRE OR $VIP OR $PRIV"
user_name=`mysql -u $USER -p$PASS -D $DB -h $HOST --skip-column-name -e "$Query"`
  
[ "$user_name" != '' ] && [ "$user_name" = "$username" ] && echo "user : $username" && echo 'authentication ok.' && exit 0 || echo 'authentication failed.'; exit 1

EOF

#UDP client auth file
cat <<'EOF' >/etc/openvpn/script/premium2.sh
#!/bin/bash
. /etc/openvpn/script/config.sh
  
##PREMIUM##
PRE="users.user_name='$username' AND users.auth_vpn=md5('$password') AND users.is_validated=1 AND users.is_freeze=0 AND users.is_active=1 AND users.is_ban=0 AND users.duration > 0"
  
##VIP##
VIP="users.user_name='$username' AND users.auth_vpn=md5('$password') AND users.is_validated=1 AND users.is_freeze=0 AND users.is_active=1 AND users.is_ban=0 AND users.vip_duration > 0"
  
##PRIVATE##
PRIV="users.user_name='$username' AND users.auth_vpn=md5('$password') AND users.is_validated=1 AND users.is_freeze=0 AND users.is_active=1 AND users.is_ban=0 AND users.private_duration > 0"
  
Query="SELECT users.user_name FROM users WHERE $PRE OR $VIP OR $PRIV"
user_name=`mysql -u $USER -p$PASS -D $DB -h $HOST --skip-column-name -e "$Query"`
  
[ "$user_name" != '' ] && [ "$user_name" = "$username" ] && echo "user : $username" && echo 'authentication ok.' && exit 0 || echo 'authentication failed.'; exit 1

EOF

##############################

#### Setting up SSH CRON jobs for panel
cat <<'CronPanel1' > "/etc/$Filename_alias.cron.php"
<?php
error_reporting(E_ERROR | E_PARSE);
ini_set('display_errors', '1');

$DB_host = 'DatabaseHost';
$DB_user = 'DatabaseUser';
$DB_pass = 'DatabasePass';
$DB_name = 'DatabaseName';

$mysqli = new MySQLi($DB_host,$DB_user,$DB_pass,$DB_name);
if ($mysqli->connect_error) {
    die('Error : ('. $mysqli->connect_errno .') '. $mysqli->connect_error);
}

function encrypt_key($paswd)
	{
	  $mykey=getEncryptKey();
	  $encryptedPassword=encryptPaswd($paswd,$mykey);
	  return $encryptedPassword;
	}
	 
	// function to get the decrypted user password
	function decrypt_key($paswd)
	{
	  $mykey=getEncryptKey();
	  $decryptedPassword=decryptPaswd($paswd,$mykey);
	  return $decryptedPassword;
	}
	 
	function getEncryptKey()
	{
		$secret_key = md5('eugcar');
		$secret_iv = md5('sanchez');
		$keys = $secret_key . $secret_iv;
		return encryptor('encrypt', $keys);
	}
	function encryptPaswd($string, $key)
	{
	  $result = '';
	  for($i=0; $i<strlen ($string); $i++)
	  {
		$char = substr($string, $i, 1);
		$keychar = substr($key, ($i % strlen($key))-1, 1);
		$char = chr(ord($char)+ord($keychar));
		$result.=$char;
	  }
		return base64_encode($result);
	}
	 
	function decryptPaswd($string, $key)
	{
	  $result = '';
	  $string = base64_decode($string);
	  for($i=0; $i<strlen($string); $i++)
	  {
		$char = substr($string, $i, 1);
		$keychar = substr($key, ($i % strlen($key))-1, 1);
		$char = chr(ord($char)-ord($keychar));
		$result.=$char;
	  }
	 
		return $result;
	}
	
	function encryptor($action, $string) {
		$output = false;

		$encrypt_method = "AES-256-CBC";
		//pls set your unique hashing key
		$secret_key = md5('eugcar sanchez');
		$secret_iv = md5('sanchez eugcar');

		// hash
		$key = hash('sha256', $secret_key);
		
		// iv - encrypt method AES-256-CBC expects 16 bytes - else you will get a warning
		$iv = substr(hash('sha256', $secret_iv), 0, 16);

		//do the encyption given text/string/number
		if( $action == 'encrypt' ) {
			$output = openssl_encrypt($string, $encrypt_method, $key, 0, $iv);
			$output = base64_encode($output);
		}
		else if( $action == 'decrypt' ){
			//decrypt the given text/string/number
			$output = openssl_decrypt(base64_decode($string), $encrypt_method, $key, 0, $iv);
		}

		return $output;
	}

$data = '';
$query = $mysqli->query("SELECT * FROM users
WHERE duration > 0 AND is_freeze = 0 OR is_freeze = 0 AND vip_duration > 0 OR is_freeze = 0 AND private_duration > 0 ORDER by user_id DESC");

if($query->num_rows > 0)
{
	while($row = $query->fetch_assoc())
	{
		$data .= '';
		$username = $row['user_name'];
		$password = decrypt_key($row['user_pass']);
		$password = encryptor('decrypt',$password);		
		$data .= '/usr/sbin/useradd -p $(openssl passwd -1 '.$password.') -s /bin/false -M '.$username.' &> /dev/null;'.PHP_EOL;
	}
}
$location = '/etc/openvpn/active.sh';
$fp = fopen($location, 'w');
fwrite($fp, $data) or die("Unable to open file!");
fclose($fp);


#In-Active and Invalid Accounts
$data2 = '';
$premium_deactived = "duration <= 0";
$vip_deactived = "vip_duration <= 0";
$private_deactived = "private_duration <= 0";
$is_validated = "is_validated=0";
$is_activate = "is_active=0";
$freeze = "is_freeze=1";
//$suspend = "suspend=1";

$query2 = $mysqli->query("SELECT * FROM users 
WHERE ".$freeze." OR ".$premium_deactived." AND ".$vip_deactived ." AND ".$private_deactived." OR ".$is_activate."
");
if($query2->num_rows > 0)
{
	while($row2 = $query2->fetch_assoc())
	{
		$data2 .= '';
		$toadd = $row2['user_name'];	
		$data2 .= '/usr/sbin/userdel -r -f '.$toadd.' &> /dev/null;'.PHP_EOL;
	}
}
$location2 = '/etc/openvpn/inactive.sh';
$fp = fopen($location2, 'w');
fwrite($fp, $data2) or die("Unable to open file!");
fclose($fp);

$mysqli->close();
?>
CronPanel1

sed -i "s|DatabaseHost|$DatabaseHost|g" "/etc/$Filename_alias.cron.php"
sed -i "s|DatabaseName|$DatabaseName|g" "/etc/$Filename_alias.cron.php"
sed -i "s|DatabaseUser|$DatabaseUser|g" "/etc/$Filename_alias.cron.php"
sed -i "s|DatabasePass|$DatabasePass|g" "/etc/$Filename_alias.cron.php"

chmod +x "/etc/$Filename_alias.cron.php"

##############################

#### Setting up L2TP CRON jobs for panel
cat <<'CronPanel2' > "/etc/$Filename_alias.l2tp.php"
<?php
error_reporting(E_ERROR | E_PARSE);
ini_set('display_errors', '1');

$DB_host = 'DatabaseHost';
$DB_user = 'DatabaseUser';
$DB_pass = 'DatabasePass';
$DB_name = 'DatabaseName';

$mysqli = new MySQLi($DB_host,$DB_user,$DB_pass,$DB_name);
if ($mysqli->connect_error) {
    die('Error : ('. $mysqli->connect_errno .') '. $mysqli->connect_error);
}

function encrypt_key($paswd)
	{
	  $mykey=getEncryptKey();
	  $encryptedPassword=encryptPaswd($paswd,$mykey);
	  return $encryptedPassword;
	}
	 
	// function to get the decrypted user password
	function decrypt_key($paswd)
	{
	  $mykey=getEncryptKey();
	  $decryptedPassword=decryptPaswd($paswd,$mykey);
	  return $decryptedPassword;
	}
	 
	function getEncryptKey()
	{
		$secret_key = md5('eugcar');
		$secret_iv = md5('sanchez');
		$keys = $secret_key . $secret_iv;
		return encryptor('encrypt', $keys);
	}
	function encryptPaswd($string, $key)
	{
	  $result = '';
	  for($i=0; $i<strlen ($string); $i++)
	  {
		$char = substr($string, $i, 1);
		$keychar = substr($key, ($i % strlen($key))-1, 1);
		$char = chr(ord($char)+ord($keychar));
		$result.=$char;
	  }
		return base64_encode($result);
	}
	 
	function decryptPaswd($string, $key)
	{
	  $result = '';
	  $string = base64_decode($string);
	  for($i=0; $i<strlen($string); $i++)
	  {
		$char = substr($string, $i, 1);
		$keychar = substr($key, ($i % strlen($key))-1, 1);
		$char = chr(ord($char)-ord($keychar));
		$result.=$char;
	  }
	 
		return $result;
	}
	
	function encryptor($action, $string) {
		$output = false;

		$encrypt_method = "AES-256-CBC";
		//pls set your unique hashing key
		$secret_key = md5('eugcar sanchez');
		$secret_iv = md5('sanchez eugcar');

		// hash
		$key = hash('sha256', $secret_key);
		
		// iv - encrypt method AES-256-CBC expects 16 bytes - else you will get a warning
		$iv = substr(hash('sha256', $secret_iv), 0, 16);

		//do the encyption given text/string/number
		if( $action == 'encrypt' ) {
			$output = openssl_encrypt($string, $encrypt_method, $key, 0, $iv);
			$output = base64_encode($output);
		}
		else if( $action == 'decrypt' ){
			//decrypt the given text/string/number
			$output = openssl_decrypt(base64_decode($string), $encrypt_method, $key, 0, $iv);
		}

		return $output;
	}

$data = '';
$query = $mysqli->query("SELECT * FROM users
WHERE duration > 0 AND is_freeze = 0 OR is_freeze = 0 AND vip_duration > 0 OR is_freeze = 0 AND private_duration > 0 ORDER by user_id DESC");

if($query->num_rows > 0)
{
	while($row = $query->fetch_assoc())
	{
		$data .= '';
		$username = $row['user_name'];
		$password = decrypt_key($row['user_pass']);
		$password = encryptor('decrypt',$password);		
		$data .= '{ echo '.$username.'; echo '.$password.'; } | vpn-install/ipsec/adduser.sh &> /dev/null;'.PHP_EOL;
	}
}
$location = '/etc/openvpn/l2tpactive.sh';
$fp = fopen($location, 'w');
fwrite($fp, $data) or die("Unable to open file!");
fclose($fp);


#In-Active and Invalid Accounts
$data2 = '';
$premium_deactived = "duration <= 0";
$vip_deactived = "vip_duration <= 0";
$private_deactived = "private_duration <= 0";
$is_validated = "is_validated=0";
$is_activate = "is_active=0";
$freeze = "is_freeze=1";
//$suspend = "suspend=1";

$query2 = $mysqli->query("SELECT * FROM users 
WHERE ".$freeze." OR ".$premium_deactived." AND ".$vip_deactived ." AND ".$private_deactived." OR ".$is_activate."
");
if($query2->num_rows > 0)
{
	while($row2 = $query2->fetch_assoc())
	{
		$data2 .= '';
		$toadd = $row2['user_name'];	
		$data2 .= '{ echo '.$toadd.'; } | vpn-install/ipsec/deluser.sh &> /dev/null;'.PHP_EOL;
	}
}
$location2 = '/etc/openvpn/l2tpinactive.sh';
$fp = fopen($location2, 'w');
fwrite($fp, $data2) or die("Unable to open file!");
fclose($fp);

$mysqli->close();
?>
CronPanel2

sed -i "s|DatabaseHost|$DatabaseHost|g" "/etc/$Filename_alias.l2tp.php"
sed -i "s|DatabaseName|$DatabaseName|g" "/etc/$Filename_alias.l2tp.php"
sed -i "s|DatabaseUser|$DatabaseUser|g" "/etc/$Filename_alias.l2tp.php"
sed -i "s|DatabasePass|$DatabasePass|g" "/etc/$Filename_alias.l2tp.php"

chmod +x "/etc/$Filename_alias.l2tp.php"

#setting premissions
chmod +x /etc/openvpn/script/config.sh
chmod +x /etc/openvpn/script/premium.sh
chmod +x /etc/openvpn/script/premium2.sh
chmod +x /etc/openvpn/script/connectpremium.sh
chmod +x /etc/openvpn/script/connectpremium2.sh
chmod +x /etc/openvpn/script/disconnectpremium.sh
chmod +x /etc/openvpn/script/disconnectpremium2.sh

 ;;
 2)
 
#creating TCP Config
cat <<'EOF' >/etc/openvpn/server.conf
# VPN_Name Server
# Server by VPN_Owner

dev tun
tun-mtu 1500
proto tcp
port OpenVPN_TCP_Port
ca /etc/openvpn/ca.crt
cert /etc/openvpn/server.crt
key /etc/openvpn/server.key
dh none
reneg-sec 0
auth-user-pass-verify "/etc/openvpn/script/vip.sh" via-env
tmp-dir "/etc/openvpn/"
script-security 3
max-clients 2000
#cipher none
##ncp-disable
#auth none
verify-client-cert none
username-as-common-name
topology subnet
server 10.120.0.0 255.255.0.0
push "redirect-gateway def1"
client-to-client
client-connect /etc/openvpn/script/connectvip.sh
client-disconnect /etc/openvpn/script/disconnectvip.sh
keepalive 3 15
comp-lzo
persist-tun
persist-key
persist-remote-ip
status /var/www/html/stat/tcp.txt
log /etc/openvpn/log_tcp
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 1.0.0.1"
verb 2
##float
##fast-io
status-version 1

EOF
sed -i "s|OpenVPN_TCP_Port|$OpenVPN_TCP_Port|g" /etc/openvpn/server.conf

#creating UDP Config
cat <<'EOF' >/etc/openvpn/server2.conf
# Firenet Dev
# Patched by Lenz

dev tun
tun-mtu 1500
proto udp
port OpenVPN_UDP_Port
ca /etc/openvpn/ca.crt
cert /etc/openvpn/server.crt
key /etc/openvpn/server.key
dh none
reneg-sec 0
auth-user-pass-verify "/etc/openvpn/script/vip2.sh" via-env
tmp-dir "/etc/openvpn/"
script-security 3
max-clients 2000
##cipher none
##ncp-disable
##auth none
verify-client-cert none
username-as-common-name
topology subnet
server 10.121.0.0 255.255.0.0
push "redirect-gateway def1"
client-to-client
client-connect /etc/openvpn/script/connectvip2.sh
client-disconnect /etc/openvpn/script/disconnectvip2.sh
keepalive 3 15
comp-lzo
persist-tun
persist-key
persist-remote-ip
status /var/www/html/stat/udp.txt
log /etc/openvpn/log_udp
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 1.0.0.1"
verb 2
##float
##fast-io
status-version 1

EOF
sed -i "s|OpenVPN_UDP_Port|$OpenVPN_UDP_Port|g" /etc/openvpn/server2.conf

#TCP client-connect file
cat <<'EOF' >/etc/openvpn/script/connectvip.sh
#!/bin/bash

tm="$(date +%s)"
dt="$(date +'%Y-%m-%d %H:%M:%S')"
timestamp="$(date +'%FT%TZ')"

. /etc/openvpn/script/config.sh

##set status online to user connected
bandwidth_check=`mysql -u $USER -p$PASS -D $DB -h $HOST --skip-column-name -e "SELECT bandwidth_logs.username FROM bandwidth_logs WHERE bandwidth_logs.username='$common_name' AND bandwidth_logs.category='vip' AND bandwidth_logs.status='online'"`
if [ "$bandwidth_check" == 1 ]; then
mysql -u $USER -p$PASS -D $DB -h $HOST -e "UPDATE bandwith_logs SET server_ip='$local_1', server_port='$trusted_port', timestamp='$timestamp', ipaddress='$trusted_ip:$trusted_port', username='$common_name', time_in='$tm', since_connected='$time_ascii', bytes_received='$bytes_received', bytes_sent='$bytes_sent' WHERE username='$common_name' AND status='online' AND category='vip' "
mysql -u $USER -p$PASS -D $DB -h $HOST -e "UPDATE users SET is_connected=1 WHERE user_name='$common_name' "
else
mysql -u $USER -p$PASS -D $DB -h $HOST -e "INSERT INTO bandwidth_logs (server_ip, server_port, timestamp, ipaddress, since_connected, username, bytes_received, bytes_sent, time_in, status, time, category) VALUES ('$local_1','$trusted_port','$timestamp','$trusted_ip:$trusted_port','$time_ascii','$common_name','$bytes_received','$bytes_sent','$dt','online','$tm','vip') "
mysql -u $USER -p$PASS -D $DB -h $HOST -e "UPDATE users SET device_connected=1, is_connected=1 WHERE user_name='$common_name' "
fi

EOF

#UDP client-connect file
cat <<'EOF' >/etc/openvpn/script/connectvip2.sh
#!/bin/bash

tm="$(date +%s)"
dt="$(date +'%Y-%m-%d %H:%M:%S')"
timestamp="$(date +'%FT%TZ')"

. /etc/openvpn/script/config.sh

##set status online to user connected
bandwidth_check=`mysql -u $USER -p$PASS -D $DB -h $HOST --skip-column-name -e "SELECT bandwidth_logs.username FROM bandwidth_logs WHERE bandwidth_logs.username='$common_name' AND bandwidth_logs.category='vip' AND bandwidth_logs.status='online'"`
if [ "$bandwidth_check" == 1 ]; then
mysql -u $USER -p$PASS -D $DB -h $HOST -e "UPDATE bandwith_logs SET server_ip='$local_1', server_port='$trusted_port', timestamp='$timestamp', ipaddress='$trusted_ip:$trusted_port', username='$common_name', time_in='$tm', since_connected='$time_ascii', bytes_received='$bytes_received', bytes_sent='$bytes_sent' WHERE username='$common_name' AND status='online' AND category='vip' "
mysql -u $USER -p$PASS -D $DB -h $HOST -e "UPDATE users SET is_connected=1 WHERE user_name='$common_name' "
else
mysql -u $USER -p$PASS -D $DB -h $HOST -e "INSERT INTO bandwidth_logs (server_ip, server_port, timestamp, ipaddress, since_connected, username, bytes_received, bytes_sent, time_in, status, time, category) VALUES ('$local_1','$trusted_port','$timestamp','$trusted_ip:$trusted_port','$time_ascii','$common_name','$bytes_received','$bytes_sent','$dt','online','$tm','vip') "
mysql -u $USER -p$PASS -D $DB -h $HOST -e "UPDATE users SET device_connected=1, is_connected=1 WHERE user_name='$common_name' "
fi

EOF

#TCP client-disconnect file
cat <<'EOF' >/etc/openvpn/script/disconnectvip.sh
#!/bin/bash
tm="$(date +%s)"
dt="$(date +'%Y-%m-%d %H:%M:%S')"
timestamp="$(date +'%FT%TZ')"

. /etc/openvpn/script/config.sh

mysql -u $USER -p$PASS -D $DB -h $HOST -e "UPDATE bandwidth_logs SET bytes_received='$bytes_received',bytes_sent='$bytes_sent',time_out='$dt', status='offline' WHERE username='$common_name' AND status='online' AND category='vip' "
mysql -u $USER -p$PASS -D $DB -h $HOST -e "UPDATE users SET is_connected=0 WHERE user_name='$common_name' "

EOF

#UDP client-disconnect file
cat <<'EOF' >/etc/openvpn/script/disconnectvip2.sh
#!/bin/bash
tm="$(date +%s)"
dt="$(date +'%Y-%m-%d %H:%M:%S')"
timestamp="$(date +'%FT%TZ')"

. /etc/openvpn/script/config.sh

mysql -u $USER -p$PASS -D $DB -h $HOST -e "UPDATE bandwidth_logs SET bytes_received='$bytes_received',bytes_sent='$bytes_sent',time_out='$dt', status='offline' WHERE username='$common_name' AND status='online' AND category='vip' "
mysql -u $USER -p$PASS -D $DB -h $HOST -e "UPDATE users SET is_connected=0 WHERE user_name='$common_name' "

EOF

#TCP client auth file
cat <<'EOF' >/etc/openvpn/script/vip.sh
#!/bin/bash
. /etc/openvpn/script/config.sh
  
##PREMIUM##
PRE="users.user_name='$username' AND users.auth_vpn=md5('$password') AND users.is_validated=1 AND users.is_freeze=0 AND users.is_active=1 AND users.is_ban=0 AND users.duration > 0"
  
##VIP##
VIP="users.user_name='$username' AND users.auth_vpn=md5('$password') AND users.is_validated=1 AND users.is_freeze=0 AND users.is_active=1 AND users.is_ban=0 AND users.vip_duration > 0"
  
##PRIVATE##
PRIV="users.user_name='$username' AND users.auth_vpn=md5('$password') AND users.is_validated=1 AND users.is_freeze=0 AND users.is_active=1 AND users.is_ban=0 AND users.private_duration > 0"
  
Query="SELECT users.user_name FROM users WHERE $VIP OR $PRIV"
user_name=`mysql -u $USER -p$PASS -D $DB -h $HOST --skip-column-name -e "$Query"`
  
[ "$user_name" != '' ] && [ "$user_name" = "$username" ] && echo "user : $username" && echo 'authentication ok.' && exit 0 || echo 'authentication failed.'; exit 1

EOF

#UDP client auth file
cat <<'EOF' >/etc/openvpn/script/vip2.sh
#!/bin/bash
. /etc/openvpn/script/config.sh
  
##PREMIUM##
PRE="users.user_name='$username' AND users.auth_vpn=md5('$password') AND users.is_validated=1 AND users.is_freeze=0 AND users.is_active=1 AND users.is_ban=0 AND users.duration > 0"
  
##VIP##
VIP="users.user_name='$username' AND users.auth_vpn=md5('$password') AND users.is_validated=1 AND users.is_freeze=0 AND users.is_active=1 AND users.is_ban=0 AND users.vip_duration > 0"
  
##PRIVATE##
PRIV="users.user_name='$username' AND users.auth_vpn=md5('$password') AND users.is_validated=1 AND users.is_freeze=0 AND users.is_active=1 AND users.is_ban=0 AND users.private_duration > 0"
  
Query="SELECT users.user_name FROM users WHERE $VIP OR $PRIV"
user_name=`mysql -u $USER -p$PASS -D $DB -h $HOST --skip-column-name -e "$Query"`
  
[ "$user_name" != '' ] && [ "$user_name" = "$username" ] && echo "user : $username" && echo 'authentication ok.' && exit 0 || echo 'authentication failed.'; exit 1

EOF

##############################

#### Setting up SSH CRON jobs for panel
cat <<'CronPanel1' > "/etc/$Filename_alias.cron.php"
<?php
error_reporting(E_ERROR | E_PARSE);
ini_set('display_errors', '1');

$DB_host = 'DatabaseHost';
$DB_user = 'DatabaseUser';
$DB_pass = 'DatabasePass';
$DB_name = 'DatabaseName';

$mysqli = new MySQLi($DB_host,$DB_user,$DB_pass,$DB_name);
if ($mysqli->connect_error) {
    die('Error : ('. $mysqli->connect_errno .') '. $mysqli->connect_error);
}

function encrypt_key($paswd)
	{
	  $mykey=getEncryptKey();
	  $encryptedPassword=encryptPaswd($paswd,$mykey);
	  return $encryptedPassword;
	}
	 
	// function to get the decrypted user password
	function decrypt_key($paswd)
	{
	  $mykey=getEncryptKey();
	  $decryptedPassword=decryptPaswd($paswd,$mykey);
	  return $decryptedPassword;
	}
	 
	function getEncryptKey()
	{
		$secret_key = md5('eugcar');
		$secret_iv = md5('sanchez');
		$keys = $secret_key . $secret_iv;
		return encryptor('encrypt', $keys);
	}
	function encryptPaswd($string, $key)
	{
	  $result = '';
	  for($i=0; $i<strlen ($string); $i++)
	  {
		$char = substr($string, $i, 1);
		$keychar = substr($key, ($i % strlen($key))-1, 1);
		$char = chr(ord($char)+ord($keychar));
		$result.=$char;
	  }
		return base64_encode($result);
	}
	 
	function decryptPaswd($string, $key)
	{
	  $result = '';
	  $string = base64_decode($string);
	  for($i=0; $i<strlen($string); $i++)
	  {
		$char = substr($string, $i, 1);
		$keychar = substr($key, ($i % strlen($key))-1, 1);
		$char = chr(ord($char)-ord($keychar));
		$result.=$char;
	  }
	 
		return $result;
	}
	
	function encryptor($action, $string) {
		$output = false;

		$encrypt_method = "AES-256-CBC";
		//pls set your unique hashing key
		$secret_key = md5('eugcar sanchez');
		$secret_iv = md5('sanchez eugcar');

		// hash
		$key = hash('sha256', $secret_key);
		
		// iv - encrypt method AES-256-CBC expects 16 bytes - else you will get a warning
		$iv = substr(hash('sha256', $secret_iv), 0, 16);

		//do the encyption given text/string/number
		if( $action == 'encrypt' ) {
			$output = openssl_encrypt($string, $encrypt_method, $key, 0, $iv);
			$output = base64_encode($output);
		}
		else if( $action == 'decrypt' ){
			//decrypt the given text/string/number
			$output = openssl_decrypt(base64_decode($string), $encrypt_method, $key, 0, $iv);
		}

		return $output;
	}

$data = '';
$query = $mysqli->query("SELECT * FROM users
WHERE is_freeze = 0 AND vip_duration > 0 OR is_freeze = 0 AND private_duration > 0 ORDER by user_id DESC");

if($query->num_rows > 0)
{
	while($row = $query->fetch_assoc())
	{
		$data .= '';
		$username = $row['user_name'];
		$password = decrypt_key($row['user_pass']);
		$password = encryptor('decrypt',$password);		
		$data .= '/usr/sbin/useradd -p $(openssl passwd -1 '.$password.') -s /bin/false -M '.$username.' &> /dev/null;'.PHP_EOL;
	}
}
$location = '/etc/openvpn/active.sh';
$fp = fopen($location, 'w');
fwrite($fp, $data) or die("Unable to open file!");
fclose($fp);


#In-Active and Invalid Accounts
$data2 = '';
$premium_deactived = "duration <= 0";
$vip_deactived = "vip_duration <= 0";
$private_deactived = "private_duration <= 0";
$is_validated = "is_validated=0";
$is_activate = "is_active=0";
$freeze = "is_freeze=1";
//$suspend = "suspend=1";

$query2 = $mysqli->query("SELECT * FROM users 
WHERE ".$freeze." OR ".$premium_deactived." AND ".$vip_deactived ." AND ".$private_deactived." OR ".$is_activate."
");
if($query2->num_rows > 0)
{
	while($row2 = $query2->fetch_assoc())
	{
		$data2 .= '';
		$toadd = $row2['user_name'];	
		$data2 .= '/usr/sbin/userdel -r -f '.$toadd.' &> /dev/null;'.PHP_EOL;
	}
}
$location2 = '/etc/openvpn/inactive.sh';
$fp = fopen($location2, 'w');
fwrite($fp, $data2) or die("Unable to open file!");
fclose($fp);

$mysqli->close();
?>
CronPanel1

sed -i "s|DatabaseHost|$DatabaseHost|g" "/etc/$Filename_alias.cron.php"
sed -i "s|DatabaseName|$DatabaseName|g" "/etc/$Filename_alias.cron.php"
sed -i "s|DatabaseUser|$DatabaseUser|g" "/etc/$Filename_alias.cron.php"
sed -i "s|DatabasePass|$DatabasePass|g" "/etc/$Filename_alias.cron.php"

chmod +x "/etc/$Filename_alias.cron.php"

##############################

#### Setting up L2TP CRON jobs for panel
cat <<'CronPanel2' > "/etc/$Filename_alias.l2tp.php"
<?php
error_reporting(E_ERROR | E_PARSE);
ini_set('display_errors', '1');

$DB_host = 'DatabaseHost';
$DB_user = 'DatabaseUser';
$DB_pass = 'DatabasePass';
$DB_name = 'DatabaseName';

$mysqli = new MySQLi($DB_host,$DB_user,$DB_pass,$DB_name);
if ($mysqli->connect_error) {
    die('Error : ('. $mysqli->connect_errno .') '. $mysqli->connect_error);
}

function encrypt_key($paswd)
	{
	  $mykey=getEncryptKey();
	  $encryptedPassword=encryptPaswd($paswd,$mykey);
	  return $encryptedPassword;
	}
	 
	// function to get the decrypted user password
	function decrypt_key($paswd)
	{
	  $mykey=getEncryptKey();
	  $decryptedPassword=decryptPaswd($paswd,$mykey);
	  return $decryptedPassword;
	}
	 
	function getEncryptKey()
	{
		$secret_key = md5('eugcar');
		$secret_iv = md5('sanchez');
		$keys = $secret_key . $secret_iv;
		return encryptor('encrypt', $keys);
	}
	function encryptPaswd($string, $key)
	{
	  $result = '';
	  for($i=0; $i<strlen ($string); $i++)
	  {
		$char = substr($string, $i, 1);
		$keychar = substr($key, ($i % strlen($key))-1, 1);
		$char = chr(ord($char)+ord($keychar));
		$result.=$char;
	  }
		return base64_encode($result);
	}
	 
	function decryptPaswd($string, $key)
	{
	  $result = '';
	  $string = base64_decode($string);
	  for($i=0; $i<strlen($string); $i++)
	  {
		$char = substr($string, $i, 1);
		$keychar = substr($key, ($i % strlen($key))-1, 1);
		$char = chr(ord($char)-ord($keychar));
		$result.=$char;
	  }
	 
		return $result;
	}
	
	function encryptor($action, $string) {
		$output = false;

		$encrypt_method = "AES-256-CBC";
		//pls set your unique hashing key
		$secret_key = md5('eugcar sanchez');
		$secret_iv = md5('sanchez eugcar');

		// hash
		$key = hash('sha256', $secret_key);
		
		// iv - encrypt method AES-256-CBC expects 16 bytes - else you will get a warning
		$iv = substr(hash('sha256', $secret_iv), 0, 16);

		//do the encyption given text/string/number
		if( $action == 'encrypt' ) {
			$output = openssl_encrypt($string, $encrypt_method, $key, 0, $iv);
			$output = base64_encode($output);
		}
		else if( $action == 'decrypt' ){
			//decrypt the given text/string/number
			$output = openssl_decrypt(base64_decode($string), $encrypt_method, $key, 0, $iv);
		}

		return $output;
	}

$data = '';
$query = $mysqli->query("SELECT * FROM users
WHERE is_freeze = 0 AND vip_duration > 0 OR is_freeze = 0 AND private_duration > 0 ORDER by user_id DESC");

if($query->num_rows > 0)
{
	while($row = $query->fetch_assoc())
	{
		$data .= '';
		$username = $row['user_name'];
		$password = decrypt_key($row['user_pass']);
		$password = encryptor('decrypt',$password);		
		$data .= '{ echo '.$username.'; echo '.$password.'; } | vpn-install/ipsec/adduser.sh &> /dev/null;'.PHP_EOL;
	}
}
$location = '/etc/openvpn/l2tpactive.sh';
$fp = fopen($location, 'w');
fwrite($fp, $data) or die("Unable to open file!");
fclose($fp);


#In-Active and Invalid Accounts
$data2 = '';
$premium_deactived = "duration <= 0";
$vip_deactived = "vip_duration <= 0";
$private_deactived = "private_duration <= 0";
$is_validated = "is_validated=0";
$is_activate = "is_active=0";
$freeze = "is_freeze=1";
//$suspend = "suspend=1";

$query2 = $mysqli->query("SELECT * FROM users 
WHERE ".$freeze." OR ".$premium_deactived." AND ".$vip_deactived ." AND ".$private_deactived." OR ".$is_activate."
");
if($query2->num_rows > 0)
{
	while($row2 = $query2->fetch_assoc())
	{
		$data2 .= '';
		$toadd = $row2['user_name'];	
		$data2 .= '{ echo '.$toadd.'; } | vpn-install/ipsec/deluser.sh &> /dev/null;'.PHP_EOL;
	}
}
$location2 = '/etc/openvpn/l2tpinactive.sh';
$fp = fopen($location2, 'w');
fwrite($fp, $data2) or die("Unable to open file!");
fclose($fp);

$mysqli->close();
?>
CronPanel2

sed -i "s|DatabaseHost|$DatabaseHost|g" "/etc/$Filename_alias.l2tp.php"
sed -i "s|DatabaseName|$DatabaseName|g" "/etc/$Filename_alias.l2tp.php"
sed -i "s|DatabaseUser|$DatabaseUser|g" "/etc/$Filename_alias.l2tp.php"
sed -i "s|DatabasePass|$DatabasePass|g" "/etc/$Filename_alias.l2tp.php"

chmod +x "/etc/$Filename_alias.l2tp.php"

#setting premissions
chmod +x /etc/openvpn/script/config.sh
chmod +x /etc/openvpn/script/vip.sh
chmod +x /etc/openvpn/script/vip2.sh
chmod +x /etc/openvpn/script/connectvip.sh
chmod +x /etc/openvpn/script/connectvip2.sh
chmod +x /etc/openvpn/script/disconnectvip.sh
chmod +x /etc/openvpn/script/disconnectvip2.sh

 ;;
 3)
 
#creating TCP Config
cat <<'EOF' >/etc/openvpn/server.conf
# VPN_Name Server
# Server by VPN_Owner

dev tun
tun-mtu 1500
proto tcp
port OpenVPN_TCP_Port
ca /etc/openvpn/ca.crt
cert /etc/openvpn/server.crt
key /etc/openvpn/server.key
dh none
reneg-sec 0
auth-user-pass-verify "/etc/openvpn/script/private.sh" via-env
tmp-dir "/etc/openvpn/"
script-security 3
max-clients 2000
#cipher none
##ncp-disable
#auth none
verify-client-cert none
username-as-common-name
topology subnet
server 10.120.0.0 255.255.0.0
push "redirect-gateway def1"
client-to-client
client-connect /etc/openvpn/script/connectprivate.sh
client-disconnect /etc/openvpn/script/disconnectprivate.sh
keepalive 3 15
comp-lzo
persist-tun
persist-key
persist-remote-ip
status /var/www/html/stat/tcp.txt
log /etc/openvpn/log_tcp
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 1.0.0.1"
verb 2
##float
##fast-io
status-version 1

EOF
sed -i "s|OpenVPN_TCP_Port|$OpenVPN_TCP_Port|g" /etc/openvpn/server.conf

#creating UDP Config
cat <<'EOF' >/etc/openvpn/server2.conf
# Firenet Dev
# Patched by Lenz

dev tun
tun-mtu 1500
proto udp
port OpenVPN_UDP_Port
ca /etc/openvpn/ca.crt
cert /etc/openvpn/server.crt
key /etc/openvpn/server.key
dh none
reneg-sec 0
auth-user-pass-verify "/etc/openvpn/script/private2.sh" via-env
tmp-dir "/etc/openvpn/"
script-security 3
max-clients 2000
##cipher none
##ncp-disable
##auth none
verify-client-cert none
username-as-common-name
topology subnet
server 10.121.0.0 255.255.0.0
push "redirect-gateway def1"
client-to-client
client-connect /etc/openvpn/script/connectprivate2.sh
client-disconnect /etc/openvpn/script/disconnectprivate2.sh
keepalive 3 15
comp-lzo
persist-tun
persist-key
persist-remote-ip
status /var/www/html/stat/udp.txt
log /etc/openvpn/log_udp
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 1.0.0.1"
verb 2
##float
##fast-io
status-version 1

EOF
sed -i "s|OpenVPN_UDP_Port|$OpenVPN_UDP_Port|g" /etc/openvpn/server2.conf

#TCP client-connect file
cat <<'EOF' >/etc/openvpn/script/connectprivate.sh
#!/bin/bash

tm="$(date +%s)"
dt="$(date +'%Y-%m-%d %H:%M:%S')"
timestamp="$(date +'%FT%TZ')"

. /etc/openvpn/script/config.sh

##set status online to user connected
bandwidth_check=`mysql -u $USER -p$PASS -D $DB -h $HOST --skip-column-name -e "SELECT bandwidth_logs.username FROM bandwidth_logs WHERE bandwidth_logs.username='$common_name' AND bandwidth_logs.category='private' AND bandwidth_logs.status='online'"`
if [ "$bandwidth_check" == 1 ]; then
mysql -u $USER -p$PASS -D $DB -h $HOST -e "UPDATE bandwith_logs SET server_ip='$local_1', server_port='$trusted_port', timestamp='$timestamp', ipaddress='$trusted_ip:$trusted_port', username='$common_name', time_in='$tm', since_connected='$time_ascii', bytes_received='$bytes_received', bytes_sent='$bytes_sent' WHERE username='$common_name' AND status='online' AND category='private' "
mysql -u $USER -p$PASS -D $DB -h $HOST -e "UPDATE users SET is_connected=1 WHERE user_name='$common_name' "
else
mysql -u $USER -p$PASS -D $DB -h $HOST -e "INSERT INTO bandwidth_logs (server_ip, server_port, timestamp, ipaddress, since_connected, username, bytes_received, bytes_sent, time_in, status, time, category) VALUES ('$local_1','$trusted_port','$timestamp','$trusted_ip:$trusted_port','$time_ascii','$common_name','$bytes_received','$bytes_sent','$dt','online','$tm','private') "
mysql -u $USER -p$PASS -D $DB -h $HOST -e "UPDATE users SET device_connected=1, is_connected=1 WHERE user_name='$common_name' "
fi

EOF

#UDP client-connect file
cat <<'EOF' >/etc/openvpn/script/connectprivate2.sh
#!/bin/bash

tm="$(date +%s)"
dt="$(date +'%Y-%m-%d %H:%M:%S')"
timestamp="$(date +'%FT%TZ')"

. /etc/openvpn/script/config.sh

##set status online to user connected
bandwidth_check=`mysql -u $USER -p$PASS -D $DB -h $HOST --skip-column-name -e "SELECT bandwidth_logs.username FROM bandwidth_logs WHERE bandwidth_logs.username='$common_name' AND bandwidth_logs.category='private' AND bandwidth_logs.status='online'"`
if [ "$bandwidth_check" == 1 ]; then
mysql -u $USER -p$PASS -D $DB -h $HOST -e "UPDATE bandwith_logs SET server_ip='$local_1', server_port='$trusted_port', timestamp='$timestamp', ipaddress='$trusted_ip:$trusted_port', username='$common_name', time_in='$tm', since_connected='$time_ascii', bytes_received='$bytes_received', bytes_sent='$bytes_sent' WHERE username='$common_name' AND status='online' AND category='private' "
mysql -u $USER -p$PASS -D $DB -h $HOST -e "UPDATE users SET is_connected=1 WHERE user_name='$common_name' "
else
mysql -u $USER -p$PASS -D $DB -h $HOST -e "INSERT INTO bandwidth_logs (server_ip, server_port, timestamp, ipaddress, since_connected, username, bytes_received, bytes_sent, time_in, status, time, category) VALUES ('$local_1','$trusted_port','$timestamp','$trusted_ip:$trusted_port','$time_ascii','$common_name','$bytes_received','$bytes_sent','$dt','online','$tm','private') "
mysql -u $USER -p$PASS -D $DB -h $HOST -e "UPDATE users SET device_connected=1, is_connected=1 WHERE user_name='$common_name' "
fi

EOF

#TCP client-disconnect file
cat <<'EOF' >/etc/openvpn/script/disconnectprivate.sh
#!/bin/bash
tm="$(date +%s)"
dt="$(date +'%Y-%m-%d %H:%M:%S')"
timestamp="$(date +'%FT%TZ')"

. /etc/openvpn/script/config.sh

mysql -u $USER -p$PASS -D $DB -h $HOST -e "UPDATE bandwidth_logs SET bytes_received='$bytes_received',bytes_sent='$bytes_sent',time_out='$dt', status='offline' WHERE username='$common_name' AND status='online' AND category='private' "
mysql -u $USER -p$PASS -D $DB -h $HOST -e "UPDATE users SET is_connected=0 WHERE user_name='$common_name' "

EOF

#UDP client-disconnect file
cat <<'EOF' >/etc/openvpn/script/disconnectprivate2.sh
#!/bin/bash
tm="$(date +%s)"
dt="$(date +'%Y-%m-%d %H:%M:%S')"
timestamp="$(date +'%FT%TZ')"

. /etc/openvpn/script/config.sh

mysql -u $USER -p$PASS -D $DB -h $HOST -e "UPDATE bandwidth_logs SET bytes_received='$bytes_received',bytes_sent='$bytes_sent',time_out='$dt', status='offline' WHERE username='$common_name' AND status='online' AND category='private' "
mysql -u $USER -p$PASS -D $DB -h $HOST -e "UPDATE users SET is_connected=0 WHERE user_name='$common_name' "

EOF

#TCP client auth file
cat <<'EOF' >/etc/openvpn/script/private.sh
#!/bin/bash
. /etc/openvpn/script/config.sh
  
##PREMIUM##
PRE="users.user_name='$username' AND users.auth_vpn=md5('$password') AND users.is_validated=1 AND users.is_freeze=0 AND users.is_active=1 AND users.is_ban=0 AND users.duration > 0"
  
##VIP##
VIP="users.user_name='$username' AND users.auth_vpn=md5('$password') AND users.is_validated=1 AND users.is_freeze=0 AND users.is_active=1 AND users.is_ban=0 AND users.vip_duration > 0"
  
##PRIVATE##
PRIV="users.user_name='$username' AND users.auth_vpn=md5('$password') AND users.is_validated=1 AND users.is_freeze=0 AND users.is_active=1 AND users.is_ban=0 AND users.private_duration > 0"
  
Query="SELECT users.user_name FROM users WHERE $PRIV"
user_name=`mysql -u $USER -p$PASS -D $DB -h $HOST --skip-column-name -e "$Query"`
  
[ "$user_name" != '' ] && [ "$user_name" = "$username" ] && echo "user : $username" && echo 'authentication ok.' && exit 0 || echo 'authentication failed.'; exit 1

EOF

#UDP client auth file
cat <<'EOF' >/etc/openvpn/script/private2.sh
#!/bin/bash
. /etc/openvpn/script/config.sh
  
##PREMIUM##
PRE="users.user_name='$username' AND users.auth_vpn=md5('$password') AND users.is_validated=1 AND users.is_freeze=0 AND users.is_active=1 AND users.is_ban=0 AND users.duration > 0"
  
##VIP##
VIP="users.user_name='$username' AND users.auth_vpn=md5('$password') AND users.is_validated=1 AND users.is_freeze=0 AND users.is_active=1 AND users.is_ban=0 AND users.vip_duration > 0"
  
##PRIVATE##
PRIV="users.user_name='$username' AND users.auth_vpn=md5('$password') AND users.is_validated=1 AND users.is_freeze=0 AND users.is_active=1 AND users.is_ban=0 AND users.private_duration > 0"
  
Query="SELECT users.user_name FROM users WHERE $PRIV"
user_name=`mysql -u $USER -p$PASS -D $DB -h $HOST --skip-column-name -e "$Query"`
  
[ "$user_name" != '' ] && [ "$user_name" = "$username" ] && echo "user : $username" && echo 'authentication ok.' && exit 0 || echo 'authentication failed.'; exit 1

EOF

##############################

#### Setting up SSH CRON jobs for panel
cat <<'CronPanel1' > "/etc/$Filename_alias.cron.php"
<?php
error_reporting(E_ERROR | E_PARSE);
ini_set('display_errors', '1');

$DB_host = 'DatabaseHost';
$DB_user = 'DatabaseUser';
$DB_pass = 'DatabasePass';
$DB_name = 'DatabaseName';

$mysqli = new MySQLi($DB_host,$DB_user,$DB_pass,$DB_name);
if ($mysqli->connect_error) {
    die('Error : ('. $mysqli->connect_errno .') '. $mysqli->connect_error);
}

function encrypt_key($paswd)
	{
	  $mykey=getEncryptKey();
	  $encryptedPassword=encryptPaswd($paswd,$mykey);
	  return $encryptedPassword;
	}
	 
	// function to get the decrypted user password
	function decrypt_key($paswd)
	{
	  $mykey=getEncryptKey();
	  $decryptedPassword=decryptPaswd($paswd,$mykey);
	  return $decryptedPassword;
	}
	 
	function getEncryptKey()
	{
		$secret_key = md5('eugcar');
		$secret_iv = md5('sanchez');
		$keys = $secret_key . $secret_iv;
		return encryptor('encrypt', $keys);
	}
	function encryptPaswd($string, $key)
	{
	  $result = '';
	  for($i=0; $i<strlen ($string); $i++)
	  {
		$char = substr($string, $i, 1);
		$keychar = substr($key, ($i % strlen($key))-1, 1);
		$char = chr(ord($char)+ord($keychar));
		$result.=$char;
	  }
		return base64_encode($result);
	}
	 
	function decryptPaswd($string, $key)
	{
	  $result = '';
	  $string = base64_decode($string);
	  for($i=0; $i<strlen($string); $i++)
	  {
		$char = substr($string, $i, 1);
		$keychar = substr($key, ($i % strlen($key))-1, 1);
		$char = chr(ord($char)-ord($keychar));
		$result.=$char;
	  }
	 
		return $result;
	}
	
	function encryptor($action, $string) {
		$output = false;

		$encrypt_method = "AES-256-CBC";
		//pls set your unique hashing key
		$secret_key = md5('eugcar sanchez');
		$secret_iv = md5('sanchez eugcar');

		// hash
		$key = hash('sha256', $secret_key);
		
		// iv - encrypt method AES-256-CBC expects 16 bytes - else you will get a warning
		$iv = substr(hash('sha256', $secret_iv), 0, 16);

		//do the encyption given text/string/number
		if( $action == 'encrypt' ) {
			$output = openssl_encrypt($string, $encrypt_method, $key, 0, $iv);
			$output = base64_encode($output);
		}
		else if( $action == 'decrypt' ){
			//decrypt the given text/string/number
			$output = openssl_decrypt(base64_decode($string), $encrypt_method, $key, 0, $iv);
		}

		return $output;
	}

$data = '';
$query = $mysqli->query("SELECT * FROM users
WHERE is_freeze = 0 AND private_duration > 0 ORDER by user_id DESC");

if($query->num_rows > 0)
{
	while($row = $query->fetch_assoc())
	{
		$data .= '';
		$username = $row['user_name'];
		$password = decrypt_key($row['user_pass']);
		$password = encryptor('decrypt',$password);		
		$data .= '/usr/sbin/useradd -p $(openssl passwd -1 '.$password.') -s /bin/false -M '.$username.' &> /dev/null;'.PHP_EOL;
	}
}
$location = '/etc/openvpn/active.sh';
$fp = fopen($location, 'w');
fwrite($fp, $data) or die("Unable to open file!");
fclose($fp);


#In-Active and Invalid Accounts
$data2 = '';
$premium_deactived = "duration <= 0";
$vip_deactived = "vip_duration <= 0";
$private_deactived = "private_duration <= 0";
$is_validated = "is_validated=0";
$is_activate = "is_active=0";
$freeze = "is_freeze=1";
//$suspend = "suspend=1";

$query2 = $mysqli->query("SELECT * FROM users 
WHERE ".$freeze." OR ".$premium_deactived." AND ".$vip_deactived ." AND ".$private_deactived." OR ".$is_activate."
");
if($query2->num_rows > 0)
{
	while($row2 = $query2->fetch_assoc())
	{
		$data2 .= '';
		$toadd = $row2['user_name'];	
		$data2 .= '/usr/sbin/userdel -r -f '.$toadd.' &> /dev/null;'.PHP_EOL;
	}
}
$location2 = '/etc/openvpn/inactive.sh';
$fp = fopen($location2, 'w');
fwrite($fp, $data2) or die("Unable to open file!");
fclose($fp);

$mysqli->close();
?>
CronPanel1

sed -i "s|DatabaseHost|$DatabaseHost|g" "/etc/$Filename_alias.cron.php"
sed -i "s|DatabaseName|$DatabaseName|g" "/etc/$Filename_alias.cron.php"
sed -i "s|DatabaseUser|$DatabaseUser|g" "/etc/$Filename_alias.cron.php"
sed -i "s|DatabasePass|$DatabasePass|g" "/etc/$Filename_alias.cron.php"

chmod +x "/etc/$Filename_alias.cron.php"

##############################

#### Setting up L2TP CRON jobs for panel
cat <<'CronPanel2' > "/etc/$Filename_alias.l2tp.php"
<?php
error_reporting(E_ERROR | E_PARSE);
ini_set('display_errors', '1');

$DB_host = 'DatabaseHost';
$DB_user = 'DatabaseUser';
$DB_pass = 'DatabasePass';
$DB_name = 'DatabaseName';

$mysqli = new MySQLi($DB_host,$DB_user,$DB_pass,$DB_name);
if ($mysqli->connect_error) {
    die('Error : ('. $mysqli->connect_errno .') '. $mysqli->connect_error);
}

function encrypt_key($paswd)
	{
	  $mykey=getEncryptKey();
	  $encryptedPassword=encryptPaswd($paswd,$mykey);
	  return $encryptedPassword;
	}
	 
	// function to get the decrypted user password
	function decrypt_key($paswd)
	{
	  $mykey=getEncryptKey();
	  $decryptedPassword=decryptPaswd($paswd,$mykey);
	  return $decryptedPassword;
	}
	 
	function getEncryptKey()
	{
		$secret_key = md5('eugcar');
		$secret_iv = md5('sanchez');
		$keys = $secret_key . $secret_iv;
		return encryptor('encrypt', $keys);
	}
	function encryptPaswd($string, $key)
	{
	  $result = '';
	  for($i=0; $i<strlen ($string); $i++)
	  {
		$char = substr($string, $i, 1);
		$keychar = substr($key, ($i % strlen($key))-1, 1);
		$char = chr(ord($char)+ord($keychar));
		$result.=$char;
	  }
		return base64_encode($result);
	}
	 
	function decryptPaswd($string, $key)
	{
	  $result = '';
	  $string = base64_decode($string);
	  for($i=0; $i<strlen($string); $i++)
	  {
		$char = substr($string, $i, 1);
		$keychar = substr($key, ($i % strlen($key))-1, 1);
		$char = chr(ord($char)-ord($keychar));
		$result.=$char;
	  }
	 
		return $result;
	}
	
	function encryptor($action, $string) {
		$output = false;

		$encrypt_method = "AES-256-CBC";
		//pls set your unique hashing key
		$secret_key = md5('eugcar sanchez');
		$secret_iv = md5('sanchez eugcar');

		// hash
		$key = hash('sha256', $secret_key);
		
		// iv - encrypt method AES-256-CBC expects 16 bytes - else you will get a warning
		$iv = substr(hash('sha256', $secret_iv), 0, 16);

		//do the encyption given text/string/number
		if( $action == 'encrypt' ) {
			$output = openssl_encrypt($string, $encrypt_method, $key, 0, $iv);
			$output = base64_encode($output);
		}
		else if( $action == 'decrypt' ){
			//decrypt the given text/string/number
			$output = openssl_decrypt(base64_decode($string), $encrypt_method, $key, 0, $iv);
		}

		return $output;
	}

$data = '';
$query = $mysqli->query("SELECT * FROM users
WHERE is_freeze = 0 AND private_duration > 0 ORDER by user_id DESC");

if($query->num_rows > 0)
{
	while($row = $query->fetch_assoc())
	{
		$data .= '';
		$username = $row['user_name'];
		$password = decrypt_key($row['user_pass']);
		$password = encryptor('decrypt',$password);		
		$data .= '{ echo '.$username.'; echo '.$password.'; } | vpn-install/ipsec/adduser.sh &> /dev/null;'.PHP_EOL;
	}
}
$location = '/etc/openvpn/l2tpactive.sh';
$fp = fopen($location, 'w');
fwrite($fp, $data) or die("Unable to open file!");
fclose($fp);


#In-Active and Invalid Accounts
$data2 = '';
$premium_deactived = "duration <= 0";
$vip_deactived = "vip_duration <= 0";
$private_deactived = "private_duration <= 0";
$is_validated = "is_validated=0";
$is_activate = "is_active=0";
$freeze = "is_freeze=1";
//$suspend = "suspend=1";

$query2 = $mysqli->query("SELECT * FROM users 
WHERE ".$freeze." OR ".$premium_deactived." AND ".$vip_deactived ." AND ".$private_deactived." OR ".$is_activate."
");
if($query2->num_rows > 0)
{
	while($row2 = $query2->fetch_assoc())
	{
		$data2 .= '';
		$toadd = $row2['user_name'];	
		$data2 .= '{ echo '.$toadd.'; } | vpn-install/ipsec/deluser.sh &> /dev/null;'.PHP_EOL;
	}
}
$location2 = '/etc/openvpn/l2tpinactive.sh';
$fp = fopen($location2, 'w');
fwrite($fp, $data2) or die("Unable to open file!");
fclose($fp);

$mysqli->close();
?>
CronPanel2

sed -i "s|DatabaseHost|$DatabaseHost|g" "/etc/$Filename_alias.l2tp.php"
sed -i "s|DatabaseName|$DatabaseName|g" "/etc/$Filename_alias.l2tp.php"
sed -i "s|DatabaseUser|$DatabaseUser|g" "/etc/$Filename_alias.l2tp.php"
sed -i "s|DatabasePass|$DatabasePass|g" "/etc/$Filename_alias.l2tp.php"

chmod +x "/etc/$Filename_alias.l2tp.php"

#setting premissions
chmod +x /etc/openvpn/script/config.sh
chmod +x /etc/openvpn/script/private.sh
chmod +x /etc/openvpn/script/private2.sh
chmod +x /etc/openvpn/script/connectprivate.sh
chmod +x /etc/openvpn/script/connectprivate2.sh
chmod +x /etc/openvpn/script/disconnectprivate.sh
chmod +x /etc/openvpn/script/disconnectprivate2.sh

 ;;
esac


if [[ "$(cat < /etc/system-release-cpe | cut -d: -f5)" == '6' ]]; then
 service openvpn start &> /dev/null
 chkconfig --add openvpn &> /dev/null
 chkconfig openvpn on &> /dev/null
 rm -rf /etc/openvpn/log_*
 service openvpn restart &> /dev/null
elif [[ "$(cat < /etc/system-release-cpe | cut -d: -f5)" == '7' ]]; then
 sed -i 's|WorkingDirectory=/etc/openvpn/server|WorkingDirectory=/etc/openvpn|g' /lib/systemd/system/openvpn-server@.service
 sed -i 's|LimitNPROC|#LimitNPROC|g' /lib/systemd/system/openvpn-server@.service
 systemctl daemon-reload
 systemctl start openvpn-server@server
 systemctl start openvpn-server@server2
 systemctl enable openvpn-server@server
 systemctl enable openvpn-server@server2
fi

####################################

## Setting up Stunnel for SSL Server ##
rm -rf /etc/stunnel/*
cat <<'StunnelCert'> /etc/stunnel/stunnel.pem
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAp9VMe4I7+5d4LKy8lmNd9P5S8DmzGhKrv0gSyfVDfeWuKrPi
EH2gU0LRI5suNfAz/i5NNHr/k1jq/OrHh7MwsEFz8YyCWzzVFpejDw1Rh0O33UxG
cSMV+fY2Hxjp0lfu7SvBcHW99M+4EHD4j4XQE6Mg+/nYlLpeY515nUFrVSSDbSgb
sEd2pwsBWeVf3XiS0lfo5sGTDf39MG3k6SjL380NjQDGm0GvPvN33AU3t8HI7rRA
yqEDtzjQLKjqdA4OuxkGqND3gLRnjZvY0Og8qjG6kuEifiWMov3Wbx7khARil/15
/uVWvau665UzHiLrKUxiEXKcUn+9mthdVcugpwIDAQABAoIBAEVM4ODa3NO9LqUb
yl86tpAz96Ez4g1xCjPYmdGEkZLJpQoC7uSqSuo2W88dA47IGV/qVHzIEQIRpC48
75jL193fmPVzdFwiGUbT5EOR10lIIAKjvS54M1ncXWqnydzN7F1IRP6fz4jnwHQh
gbEZqtqA8Fy7RL/c2J6/ZnkVizFDT8kDi9sLGOqxLcmWkeUin20QWMnipn0FCXc7
s+EKDcHek7CJmPuaih27it2/N1Yg/rFctKpGtH9g7kf6LagQ0FRgawM7UvQtgILo
YYtXVeh9RtgtqQCpjAHix7F94g3GgLwJ3Np25U5IHJNmcFj333sguRWeEGoQgMTu
yCv557kCgYEA36CVxYiH5HfZfAWTt0O/l+n4hiX5ZdJwOUA31YoBtP+5sriBFODA
1OkGUxEfuxhAS6Z1tn8FjY4BTE5jYhZTT1qFEk9S+0GBLD+p9hm0rTM+K4nls6N1
qDNHXZy/+O32zyYE7TonkkITyoGLX8pt+Tx0PDblRvFH0IayOZCIaC0CgYEAwCEJ
rVMYURKJsab1iA98kALt5OwFGxAZOMI263uDxZ+Gr+nIBXVChdqzwzMIU92buVTj
gV17vnRRDRjyxQgQUemcKYTJsV2IzSDPy+tdlt02ox/B4EJMZ0tBaqNz4PJedH79
58MgP9my35bcOH+91VFbJkHdUYTRUFlVwswZ/KMCgYBDAYX/AzLctUCYVb92GTmu
Vi/eWkCJTu3Lab+RH2H1ju5ga8JZtCJzaUM43peoYtLZGA6LWTIbwSIIcDB9Mn1R
+KiI3PXbTTxcOtM9Z2RoxULqns4R7neRp5PJq+8lsn/Sf+zX/CXhQCVX90sAr9IV
7RRS+ovmnuNKyyFZ+EG3HQKBgCf2t0yWPDig4oNRd0EV95L9CP7VGTrH3ncv7ryM
tJwm0p1Ew5ZfDbdKBppTwyeusPWb8ra1+0dianmO9vCE/OAM966rMEj0a8A/UvnX
u1/mI7dKo8lCASJ7ROApn7DquTsCL05GCC8/2TUo7CXUbGgyxALxMFgEiIVuD6i1
S7KBAoGBAM/IHmr1o6TS9uv4S5K26UjMTX3uEfG3stZ+UyzghUpgWhJOBvnfdBh3
/sr1d7j6vd8I764GlSTCUWmxFYdCY299Rf2S6Nz0anz9uBfKTCU8ifib+i5zFP3G
yyBgK4msNkEFP5ysjSvEqr7Ww9rzoVzrW71K4Bha1QSxqquuAXJ1
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIEPTCCAyWgAwIBAgIJAM6kghcTGRu2MA0GCSqGSIb3DQEBBQUAMIG0MQswCQYD
VQQGEwJQSDEXMBUGA1UECAwOQ0FHQVlBTiBWQUxMRVkxEzARBgNVBAcMClRVR1VF
R0FSQU8xFjAUBgNVBAoMDVRFQU1OT0NUVVJOQUwxFjAUBgNVBAsMDVRFQU1OT0NU
VVJOQUwxFjAUBgNVBAMMDVRFQU1OT0NUVVJOQUwxLzAtBgkqhkiG9w0BCQEWIG1p
Y2hhZWxhbmdlbG9ydXNpYW5hOTRAZ21haWwuY29tMB4XDTE5MDMyNjAyMDkzN1oX
DTIyMDMyNTAyMDkzN1owgbQxCzAJBgNVBAYTAlBIMRcwFQYDVQQIDA5DQUdBWUFO
IFZBTExFWTETMBEGA1UEBwwKVFVHVUVHQVJBTzEWMBQGA1UECgwNVEVBTU5PQ1RV
Uk5BTDEWMBQGA1UECwwNVEVBTU5PQ1RVUk5BTDEWMBQGA1UEAwwNVEVBTU5PQ1RV
Uk5BTDEvMC0GCSqGSIb3DQEJARYgbWljaGFlbGFuZ2Vsb3J1c2lhbmE5NEBnbWFp
bC5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCn1Ux7gjv7l3gs
rLyWY130/lLwObMaEqu/SBLJ9UN95a4qs+IQfaBTQtEjmy418DP+Lk00ev+TWOr8
6seHszCwQXPxjIJbPNUWl6MPDVGHQ7fdTEZxIxX59jYfGOnSV+7tK8Fwdb30z7gQ
cPiPhdAToyD7+diUul5jnXmdQWtVJINtKBuwR3anCwFZ5V/deJLSV+jmwZMN/f0w
beTpKMvfzQ2NAMabQa8+83fcBTe3wcjutEDKoQO3ONAsqOp0Dg67GQao0PeAtGeN
m9jQ6DyqMbqS4SJ+JYyi/dZvHuSEBGKX/Xn+5Va9q7rrlTMeIuspTGIRcpxSf72a
2F1Vy6CnAgMBAAGjUDBOMB0GA1UdDgQWBBSj6g+QTpgHm1QsVw1KKwLaBCTz6TAf
BgNVHSMEGDAWgBSj6g+QTpgHm1QsVw1KKwLaBCTz6TAMBgNVHRMEBTADAQH/MA0G
CSqGSIb3DQEBBQUAA4IBAQCNVD+EHrt1bQ/L4XhIByKMZPWtTHga5S9qnaV+Za++
zoaDBmovrUvfmVcvHJTpMOhglS6w3TmXSg5FPJccZSbYJ/sV4f99A5NisrzqTl2L
xI+jpCHI0/kFWDRVC6eRl1H+B+N5gJPMAYxcD+W6hLy/hgVcPLUfu7Z5ttKsTR5Q
1aHwhisgt7+k4KoitpOuqrc693wJB4Nm9zXj7gRnsrigPpnVbq0SO/QcDgzOuTfJ
wnrJMXg5YiVGt1e4NtjFBgRKAEsA56u5ieZKDTgs3dqbSy5WN6BQbOpSlCPN2uGs
sEog45Sku2VVal3Q8ulP7OoFsj4t3j/uzGtneQC2WLCQ
-----END CERTIFICATE-----
StunnelCert

cat <<'Stunnel1'> /etc/stunnel/stunnel.conf
cert = /etc/stunnel/stunnel.pem
client = no
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[ssh]
accept = 0.0.0.0:SSL_viaOpenSSH
connect = 127.0.0.1:SSH_Extra_Port

[openvpn]
accept = 0.0.0.0:OpenVPN_SSL_Port
connect = 127.0.0.1:OpenVPN_TCP_Port

[squid]
accept = 0.0.0.0:8989
connect = 127.0.0.1:Squid_Proxy_1
Stunnel1

sed -i "s|SSL_viaOpenSSH|$SSL_viaOpenSSH|g" /etc/stunnel/stunnel.conf

sed -i "s|SSH_Extra_Port|$SSH_Extra_Port|g" /etc/stunnel/stunnel.conf

sed -i "s|OpenVPN_SSL_Port|$OpenVPN_SSL_Port|g" /etc/stunnel/stunnel.conf

sed -i "s|OpenVPN_TCP_Port|$OpenVPN_TCP_Port|g" /etc/stunnel/stunnel.conf

sed -i "s|Squid_Proxy_1|$Squid_Proxy_1|g" /etc/stunnel/stunnel.conf

cat <<'Stunnel2' > /etc/rc.d/init.d/stunnel
#!/bin/bash
#
# Init Script to run stunnel in daemon mode at boot time.
#

#====================================================================
# Run level information:
#
# chkconfig: 2345 99 99
# description: Secure Tunnel
# processname: stunnel
#
# Run "/sbin/chkconfig --add stunnel" to add the Run levels.
# This will setup the symlinks and set the process to run at boot.
#====================================================================

#====================================================================
# Paths and variables and system checks.

# Source function library
. /etc/rc.d/init.d/functions

# Check that networking is up.
#
[ ${NETWORKING} ="yes" ] || exit 0

# Path to the executable.
#
SEXE=/usr/bin/stunnel

# Path to the configuration file.
#
CONF=/etc/stunnel/stunnel.conf

# Check the configuration file exists.
#
if [ ! -f $CONF ] ; then
echo "The configuration file cannot be found!"
exit 0
fi

# Path to the lock file.
#
LOCK_FILE=/var/lock/subsys/stunnel

#====================================================================

# Run controls:

prog=$"stunnel"

RETVAL=0

# Start stunnel as daemon.
#
start() {
if [ -f $LOCK_FILE ]; then
echo "stunnel is already running!"
exit 0
else
echo -n $"Starting $prog: "
$SEXE $CONF
fi

RETVAL=$?
[ $RETVAL -eq 0 ] && success
echo
[ $RETVAL -eq 0 ] && touch $LOCK_FILE
return $RETVAL
}

# Stop stunnel.
#
stop() {
if [ ! -f $LOCK_FILE ]; then
echo "stunnel is not running!"
exit 0

else

echo -n $"Shutting down $prog: "
killproc stunnel
RETVAL=$?
[ $RETVAL -eq 0 ]
rm -f $LOCK_FILE
echo
return $RETVAL

fi
}

# See how we were called.
case "$1" in
start)
start
;;
stop)
stop
;;
restart)
stop
start
;;
condrestart)
if [ -f $LOCK_FILE ]; then
stop
start
RETVAL=$?
fi
;;
status)
status stunnel
RETVAL=$?
;;
*)
echo $"Usage: $0 {start|stop|restart|condrestart|status}"
RETVAL=1
esac

exit $RETVAL

#--- End of file ---
Stunnel2

chmod +x /etc/rc.d/init.d/stunnel
chkconfig --add stunnel &> /dev/null
chkconfig stunnel on &> /dev/null
service stunnel start &> /dev/null

echo 'Please wait, configuring Squid Proxy Server..'
rm -f /etc/squid/squid.*
cat <<'SquidProxy' > /etc/squid/squid.conf
acl VPN dst IP-ADDRESS/32
http_access allow VPN
http_access deny all
http_port 0.0.0.0:Squid_Proxy_1
http_port 0.0.0.0:Squid_Proxy_2
acl bonv src 0.0.0.0/0.0.0.0
no_cache deny bonv
dns_nameservers 1.1.1.1 1.0.0.1
visible_hostname localhost
SquidProxy

sed -i "s|IP-ADDRESS|$MYIP|g" /etc/squid/squid.conf

sed -i "s|Squid_Proxy_1|$Squid_Proxy_1|g" /etc/squid/squid.conf

sed -i "s|Squid_Proxy_2|$Squid_Proxy_2|g" /etc/squid/squid.conf

chkconfig --add squid &> /dev/null
chkconfig squid on &> /dev/null
service squid restart &> /dev/null


echo -e "* *\t* * *\troot\tsudo php -q /etc/$Filename_alias.cron.php" > "/etc/cron.d/$Filename_alias.cron"
echo -e "* *\t* * *\troot\tsudo bash /etc/openvpn/active.sh" >> "/etc/cron.d/$Filename_alias.cron"
echo -e "* *\t* * *\troot\tsudo bash /etc/openvpn/inactive.sh" >> "/etc/cron.d/$Filename_alias.cron"

echo -e "* *\t* * *\troot\tsudo php -q /etc/$Filename_alias.l2tp.php" > "/etc/cron.d/$Filename_alias.l2tp"
echo -e "* *\t* * *\troot\tsudo bash /etc/openvpn/l2tpactive.sh" >> "/etc/cron.d/$Filename_alias.l2tp"
echo -e "* *\t* * *\troot\tsudo bash /etc/openvpn/l2tpinactive.sh" >> "/etc/cron.d/$Filename_alias.l2tp"

echo -e "0 4\t* * *\troot\t/sbin/shutdown -r +5" > "/etc/cron.d/autoreboot"

cat <<'MyBonv' > "/etc/$Filename_alias.iptables2"
#!/bin/bash
if [[ "$( iptables -L FORWARD | grep -c '10.121.0.0')" -eq 0 ]]; then
 bash /etc/Filename_alias.iptables
fi
MyBonv

sed -i "s|Filename_alias|$Filename_alias|g" "/etc/$Filename_alias.iptables2"

echo -e "* *\t* * *\troot\tsudo bash "/etc/$Filename_alias.iptables2"" >> "/etc/cron.d/$Filename_alias.cron"

service crond restart &> /dev/null

sed -i '/sudo service.*/d' /etc/rc.d/rc.local
echo -e "sudo service openvpn restart\nsudo service squid restart\nsudo service stunnel restart\n" >> /etc/rc.d/rc.local

sed -i "s|VPN_Owner|$VPN_Owner|g" /etc/openvpn/*.conf
sed -i "s|VPN_Name|$VPN_Name|g" /etc/openvpn/*.conf
sed -i "s|VPN_Owner|$VPN_Owner|g" "/etc/$Filename_alias.iptables"
sed -i "s|VPN_Name|$VPN_Name|g" "/etc/$Filename_alias.iptables"
sed -i "s|VPN_Owner|$VPN_Owner|g" /etc/ssh/sshd_config
sed -i "s|VPN_Name|$VPN_Name|g" /etc/ssh/sshd_config
rm -f /tmp/bonv_config

cat <<'Ovpn01' > "/var/www/html/$Filename_alias.tcp.ovpn"
## VPN_Name SERVER_TYPE Server
## Config by VPN_Owner
client
dev tun
proto tcp
remote IP-ADDRESS OpenVPN_TCP_Port
remote-cert-tls server
connect-retry infinite
resolv-retry infinite
persist-remote-ip
persist-tun
nobind
rcvbuf 0
sndbuf 0
nobind
tun-mtu 1500
mssfix 1460
comp-lzo
mute-replay-warnings
auth-user-pass
auth-nocache
setenv CLIENT_CERT 0
http-proxy IP-ADDRESS Squid_Proxy_1
http-proxy-option CUSTOM-HEADER Host play.googleapis.com
http-proxy-option CUSTOM-HEADER X-Forwarded-For play.googleapis.com
Ovpn01

sed -i "s|VPN_Name|$VPN_Name|g" "/var/www/html/$Filename_alias.tcp.ovpn"
sed -i "s|VPN_Owner|$VPN_Owner|g" "/var/www/html/$Filename_alias.tcp.ovpn"
sed -i "s|IP-ADDRESS|$(ip_address)|g" "/var/www/html/$Filename_alias.tcp.ovpn"
sed -i "s|OpenVPN_TCP_Port|$OpenVPN_TCP_Port|g" "/var/www/html/$Filename_alias.tcp.ovpn"
sed -i "s|Squid_Proxy_1|$Squid_Proxy_1|g" "/var/www/html/$Filename_alias.tcp.ovpn"
echo -e "<ca>\n$(cat /etc/openvpn/ca.crt)\n</ca>" >> "/var/www/html/$Filename_alias.tcp.ovpn"


cat <<'Ovpn02' > "/var/www/html/$Filename_alias.udp.ovpn"
## VPN_Name SERVER_TYPE Server
## Config by VPN_Owner
client
dev tun
proto udp
remote IP-ADDRESS OpenVPN_UDP_Port
float
fast-io
remote-cert-tls server
connect-retry infinite
resolv-retry infinite
persist-remote-ip
persist-tun
nobind
rcvbuf 0
sndbuf 0
nobind
tun-mtu 1500
mssfix 1460
comp-lzo
mute-replay-warnings
auth-user-pass
auth-nocache
setenv CLIENT_CERT 0
Ovpn02

sed -i "s|VPN_Name|$VPN_Name|g" "/var/www/html/$Filename_alias.udp.ovpn"
sed -i "s|VPN_Owner|$VPN_Owner|g" "/var/www/html/$Filename_alias.udp.ovpn"
sed -i "s|IP-ADDRESS|$(ip_address)|g" "/var/www/html/$Filename_alias.udp.ovpn"
sed -i "s|OpenVPN_UDP_Port|$OpenVPN_UDP_Port|g" "/var/www/html/$Filename_alias.udp.ovpn"
echo -e "<ca>\n$(cat /etc/openvpn/ca.crt)\n</ca>" >> "/var/www/html/$Filename_alias.udp.ovpn"

case $opts in
 1)
 sed -i "s|SERVER_TYPE|Premium|g" "/var/www/html/$Filename_alias.udp.ovpn"
 sed -i "s|SERVER_TYPE|Premium|g" "/var/www/html/$Filename_alias.tcp.ovpn"
 ;;
 2)
 sed -i "s|SERVER_TYPE|VIP|g" "/var/www/html/$Filename_alias.udp.ovpn"
 sed -i "s|SERVER_TYPE|VIP|g" "/var/www/html/$Filename_alias.tcp.ovpn"
 ;;
 3)
 sed -i "s|SERVER_TYPE|Private|g" "/var/www/html/$Filename_alias.udp.ovpn"
 sed -i "s|SERVER_TYPE|Private|g" "/var/www/html/$Filename_alias.tcp.ovpn"
 ;;
esac

#installing badvpn
cd
wget http://www.cmake.org/files/v2.8/cmake-2.8.12.tar.gz
tar xvzf cmake*.tar.gz
cd cmake*
yum -y install gcc*
./bootstrap --prefix=/usr
yum install lib*
yum update
gmake
gmake install
mkdir badvpn-build
cd badvpn-build
wget https://storage.googleapis.com/google-code-archive-downloads/v2/code.google.com/badvpn/badvpn-1.999.128.tar.bz2
tar xf badvpn-1.999.128.tar.bz2
cd bad*
cmake -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1
make install
badvpn-udpgw --listen-addr 127.0.0.1:7300 > /dev/null &

#installing ohp
wget https://github.com/lfasmpao/open-http-puncher/releases/download/0.1/ohpserver-linux32.zip
unzip ohpserver-linux32.zip
chmod 755 ohpserver
sudo mv ohpserver /usr/local/bin/

#adding ohpssh
cat <<'ohpssh' > /etc/systemd/system/ohpserver.service
[Unit]
Description=Daemonize OpenHTTP Puncher Server
Wants=network.target
After=network.target

[Service]
ExecStart=/usr/local/bin/ohpserver -port SSH_viaOHP -proxy 127.0.0.1:Squid_Proxy_2 -tunnel IP-ADDRESS:SSH_Extra_Port
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
ohpssh

sed -i "s|SSH_viaOHP|$SSH_viaOHP|g" "/etc/systemd/system/ohpserver.service"
sed -i "s|Squid_Proxy_2|$Squid_Proxy_2|g" "/etc/systemd/system/ohpserver.service"
sed -i "s|IP-ADDRESS|$MYIP|g" "/etc/systemd/system/ohpserver.service"
sed -i "s|SSH_Extra_Port|$SSH_Extra_Port|g" "/etc/systemd/system/ohpserver.service"

#adding ohpovpn
cat <<'ohpovpn' > /etc/systemd/system/ohpovpn.service
[Unit]
Description=Daemonize OpenHTTP Puncher Server
Wants=network.target
After=network.target

[Service]
ExecStart=/usr/local/bin/ohpserver -port OVPN_viaOHP -proxy 127.0.0.1:Squid_Proxy_2 -tunnel IP-ADDRESS:OpenVPN_TCP_Port
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
ohpovpn

sed -i "s|OVPN_viaOHP|$OVPN_viaOHP|g" "/etc/systemd/system/ohpovpn.service"
sed -i "s|Squid_Proxy_2|$Squid_Proxy_2|g" "/etc/systemd/system/ohpovpn.service"
sed -i "s|IP-ADDRESS|$MYIP|g" "/etc/systemd/system/ohpovpn.service"
sed -i "s|OpenVPN_TCP_Port|$OpenVPN_TCP_Port|g" "/etc/systemd/system/ohpovpn.service"

#adding autorecon
cat <<'ohpssh2' > /etc/systemd/system/ohplenz.service
[Unit]
Description=Daemonize OpenHTTP Puncher Autorecon
Wants=network.target
After=network.target

[Service]
ExecStart=/usr/local/bin/ohpserver -port SSH_viaAuto -proxy 127.0.0.1:Squid_Proxy_2 -tunnel IP-ADDRESS:SSH_Extra_Port
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
ohpssh2

sed -i "s|SSH_viaAuto|$SSH_viaAuto|g" "/etc/systemd/system/ohplenz.service"
sed -i "s|Squid_Proxy_2|$Squid_Proxy_2|g" "/etc/systemd/system/ohplenz.service"
sed -i "s|IP-ADDRESS|$MYIP|g" "/etc/systemd/system/ohplenz.service"
sed -i "s|SSH_Extra_Port|$SSH_Extra_Port|g" "/etc/systemd/system/ohplenz.service"

sudo systemctl daemon-reload
sudo systemctl start ohplenz
sudo systemctl enable ohplenz
sudo systemctl start ohpserver
sudo systemctl enable ohpserver
sudo systemctl start ohpovpn
sudo systemctl enable ohpovpn

#creating autorecon script
cat <<'autorecon' > /home/lenz
sudo systemctl restart ohplenz
sleep 60
sudo systemctl restart ohplenz

autorecon

#adding autorecon cron
cat <<'autorecon2' > /etc/cron.d/autorecon
*/2 *   * * *   root    bash /home/lenz
autorecon2

cat <<'Startupbonv' > /etc/profile.d/bonv.sh
clear
echo -e "\n VPN_Name Server"
echo -e " Server ISP: $(curl -4s http://ipinfo.io/org)"
echo -e " Server IP Address: $(curl -4s http://ipinfo.io/ip)"
echo -e " Server Location: $(curl -4s http://ipinfo.io/country)"
echo -e " For commands and assistance, ask VPN_Owner\n"
Startupbonv
chmod a+x /etc/profile.d/bonv.sh
sed -i "s|VPN_Name|$VPN_Name|g" /etc/profile.d/bonv.sh
sed -i "s|VPN_Owner|$VPN_Owner|g" /etc/profile.d/bonv.sh

# enabling httpd
sudo systemctl start httpd
sudo systemctl enable httpd
chmod 755 /var/www/html/stat/tcp.txt
chmod 755 /var/www/html/stat/udp.txt

echo -e "\n SSH Server: 22, $SSH_Extra_Port\n SSH via OHP: $SSH_viaOHP\n SSH via OHP(Autorecon): $SSH_viaAuto\n SSL Server: $SSL_viaOpenSSH\n OpenVPN Server (TCP): $OpenVPN_TCP_Port\n OpenVPN Server (UDP): $OpenVPN_UDP_Port\n OpenVPN Server (via SSL): $OpenVPN_SSL_Port\n OpenVPN Server (via OHP): $OVPN_viaOHP\n Squid Proxy Server: $Squid_Proxy_1, $Squid_Proxy_2\n Squid Proxy Server Version: $(squid -v | grep -i 'Cache:' | cut -d" " -f4)\n Sample OpenVPN TCP Config: http://$(curl -4s http://ipinfo.io/ip)/$Filename_alias.tcp.ovpn\n Sample OpenVPN UDP Config: http://$(curl -4s http://ipinfo.io/ip)/$Filename_alias.udp.ovpn\n Script by: $VPN_Owner\n" > "/root/$Filename_alias.log"

clear
clear
SBanner

echo -e "\e[1;32m VPN Server Installation Complete\e[0m\n \e[38;5;226mYou may now use your VPN services in the following ports\e[0m\e[97m:\e[0m\n  SSH Server: 22, $SSH_Extra_Port\n SSH via OHP: $SSH_viaOHP\n SSH via OHP(Autorecon): $SSH_viaAuto\n SSL Server: $SSL_viaOpenSSH\n OpenVPN Server (TCP): $OpenVPN_TCP_Port\n OpenVPN Server (UDP): $OpenVPN_UDP_Port\n OpenVPN Server (via SSL): $OpenVPN_SSL_Port\n OpenVPN Server (via OHP): $OVPN_viaOHP\n Squid Proxy Server: $Squid_Proxy_1, $Squid_Proxy_2\n Squid Proxy Server Version: $(squid -v | grep -i 'Cache:' | cut -d" " -f4)\n  Sample OpenVPN TCP Config: http://$(curl -4s http://ipinfo.io/ip)/$Filename_alias.tcp.ovpn\n  Sample OpenVPN UDP Config: http://$(curl -4s http://ipinfo.io/ip)/$Filename_alias.udp.ovpn\n\n  Script by: \e[1;38;5;208m$VPN_Owner\e[0m"

rm -f lenz_centos.sh*
rm -f /tmp/lenz_centos.sh*
exit 1