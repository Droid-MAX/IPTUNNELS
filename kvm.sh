#!/usr/bin/env bash


red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

cur_dir=$(pwd)

[[ $EUID -ne 0 ]] && echo -e "${red}Error:${plain} This script must be run as root!" && exit 1

[[ -d "/proc/vz" ]] && echo -e "${red}Error:${plain} Your VPS is based on OpenVZ, which is not supported." && exit 1

if [ -f /etc/redhat-release ]; then
    release="centos"
elif cat /etc/issue | grep -Eqi "debian"; then
    release="debian"
elif cat /etc/issue | grep -Eqi "ubuntu"; then
    release="ubuntu"
elif cat /etc/issue | grep -Eqi "centos|red hat|redhat"; then
    release="centos"
elif cat /proc/version | grep -Eqi "debian"; then
    release="debian"
elif cat /proc/version | grep -Eqi "ubuntu"; then
    release="ubuntu"
elif cat /proc/version | grep -Eqi "centos|red hat|redhat"; then
    release="centos"
else
    release=""
fi

export DEBIAN_FRONTEND=noninteractive
OS=`uname -m`;
MYIP=$(curl -4 icanhazip.com)
if [ $MYIP = "" ]; then
   MYIP=`ifconfig | grep 'inet addr:' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | cut -d: -f2 | awk '{ print $1}' | head -1`;
fi
MYIP2="s/xxxxxxxxx/$MYIP/g";
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
service ssh restart


remove_unused_package_disableipv6(){
	apt-get -y update --fix-missing
	apt-get -y --purge remove sendmail*;
	apt-get -y --purge remove bind9*;
	apt-get -y purge sendmail*
	apt-get -y remove sendmail*
	echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
	sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local
}

install_package_dependency(){
	apt-get -y install wget curl monit git nano stunnel4 zlib1g-dev zlib1g vnstat apache2 bmon iftop htop nmap axel nano traceroute dnsutils bc nethogs less screen psmisc apt-file whois ptunnel ngrep mtr git unzip rsyslog debsums rkhunter fail2ban cmake make gcc libc6-dev dropbear apache2-utils squid3 --no-install-recommends gettext build-essential autoconf libtool libpcre3-dev asciidoc xmlto libev-dev libc-ares-dev automake haveged
	apt-file update
}

change_dns_resolver(){
	wget -O /etc/issue.net "https://github.com/malikshi/IPTUNNELS/raw/master/config/issue.net"
	echo "nameserver 1.1.1.1" >> /etc/resolv.conf
	echo "nameserver 1.0.0.1" >> /etc/resolv.conf
	sed -i '$ i\echo "nameserver 1.1.1.1" >> /etc/resolv.conf' /etc/rc.local
	sed -i '$ i\echo "nameserver 1.0.0.1" >> /etc/resolv.conf' /etc/rc.local
}

install_shadowsocks(){
	apt-get install software-properties-common -y
	add-apt-repository ppa:max-c-lv/shadowsocks-libev -y
	apt-get update -y
	apt-get install shadowsocks-libev -y
}

install_cloak(){
	archs=amd64
	url=$(wget -O - -o /dev/null https://api.github.com/repos/cbeuw/Cloak/releases/latest | grep "/ck-server-linux-$archs-" | grep -P 'https(.*)[^"]' -o)
	wget -O ck-server $url
	chmod +x ck-server
	sudo mv ck-server /usr/local/bin
}

generate_credentials(){
	[ -z "$cloak" ] && cloak=y
	if [ "${cloak}" == "y" ] || [ "${cloak}" == "Y" ]; then
		ckauid=$(ck-server -u)
		[ -z "$admuid" ] && admuid=$ckauid
		IFS=, read ckpub ckpv <<< $(ck-server -k)
		[ -z "$publi" ] && publi=$ckpub
		[ -z "$privat" ] && privat=$ckpv
	fi
}

install_prepare_cloak(){
	[ -z "$cloak" ] && cloak=y
	if [ "${cloak}" == "y" ] || [ "${cloak}" == "Y" ]; then
		echo -e "Please enter a redirection IP for Cloak (leave blank to set it to 203.104.129.195:443 of www.line.me):"
		[ -z "$ckwebaddr" ] && ckwebaddr="203.104.129.195:443"

		echo -e "Where do you want to put the userinfo.db? (default $HOME)"
		[ -z "$ckdbp" ] && ckdbp=$HOME
	fi
}

shadowsocks_conf(){
	rm /etc/shadowsocks-libev/config.json
	
	cat >/etc/shadowsocks-libev/config.json << EOF
{
    "server":"0.0.0.0",
    "server_port":53794,
    "password":"GLOBALSSH",
    "timeout":600,
    "method":"chacha20-ietf-poly1305",
	"fast_open":true,
	"nameserver":"1.1.1.1",
	"reuse_port":true,
	"no_delay":true,
	"mode":"tcp_and_udp",
    "plugin":"ck-server",
    "plugin_opts":"WebServerAddr=${ckwebaddr};PrivateKey=${privat};AdminUID=${admuid};DatabasePath=${ckdbp}/userinfo.db;BackupDirPath=${ckdbp};loglevel=none"
}
EOF

	cat >/lib/systemd/system/shadowsocks.service << END8
[Unit]
Description=Shadowsocks-libev Server Service
After=network.target
[Service]
ExecStart=/usr/bin/ss-server -c /etc/shadowsocks-libev/config.json -u
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
[Install]
WantedBy=multi-user.target
END8
systemctl enable shadowsocks.service
wget -O /etc/init.d/shadowsocks "https://github.com/malikshi/IPTUNNELS/raw/master/config/shadowsocks"
chmod +x /etc/init.d/shadowsocks
}

install_ovpn(){
	homeDir="/root"
	curl -O https://raw.githubusercontent.com/Angristan/openvpn-install/master/openvpn-install.sh
	chmod +x openvpn-install.sh
	export APPROVE_INSTALL=y
	export APPROVE_IP=y
	export IPV6_SUPPORT=n
	export PORT_CHOICE=1
	export PROTOCOL_CHOICE=2
	export DNS=3
	export COMPRESSION_ENABLED=n
	export CUSTOMIZE_ENC=n
	export CLIENT=client
	export PASS=1
	./openvpn-install.sh
	cd /etc/openvpn/
	wget -O /etc/openvpn/openvpn-auth-pam.so https://github.com/malikshi/IPTUNNELS/raw/master/package/openvpn-auth-pam.so
	echo "plugin /etc/openvpn/openvpn-auth-pam.so /etc/pam.d/login" >> /etc/openvpn/server.conf
	echo "verify-client-cert none" >> /etc/openvpn/server.conf
	echo "username-as-common-name" >> /etc/openvpn/server.conf
	echo "duplicate-cn" >> /etc/openvpn/server.conf
	echo "max-clients 10000" >> /etc/openvpn/server.conf
	echo "max-routes-per-client 1000" >> /etc/openvpn/server.conf
	echo "mssfix 1200" >> /etc/openvpn/server.conf
	echo "sndbuf 2000000" >> /etc/openvpn/server.conf
	echo "rcvbuf 2000000" >> /etc/openvpn/server.conf
	echo "txqueuelen 4000" >> /etc/openvpn/server.conf
	echo "replay-window 2000" >> /etc/openvpn/server.conf
	sed -i 's|user|#user|' /etc/openvpn/server.conf
	sed -i 's|group|#group|' /etc/openvpn/server.conf
	sed -i 's|user|#user|' /etc/openvpn/server.conf
	cp server.conf server-udp.conf
	sed -i 's|1194|587|' /etc/openvpn/server-udp.conf
	sed -i 's|tcp|udp|' /etc/openvpn/server-udp.conf
	sed -i 's|10.8.0.0|10.9.0.0|' /etc/openvpn/server-udp.conf
	sed -i 's|#AUTOSTART="all"|AUTOSTART="all"|' /etc/default/openvpn
	service openvpn restart
	rm client.ovpn
	echo 'auth-user-pass
mssfix 1200
sndbuf 2000000
rcvbuf 2000000' >> /etc/openvpn/client-template.txt
	cp /etc/openvpn/client-template.txt "$homeDir/client.ovpn"
	# Determine if we use tls-auth or tls-crypt
	if grep -qs "^tls-crypt" /etc/openvpn/server.conf; then
		TLS_SIG="1"
	elif grep -qs "^tls-auth" /etc/openvpn/server.conf; then
		TLS_SIG="2"
	fi
	{
		echo "<ca>"
		cat "/etc/openvpn/easy-rsa/pki/ca.crt"
		echo "</ca>"

		case $TLS_SIG in
			1)
				echo "<tls-crypt>"
				cat /etc/openvpn/tls-crypt.key
				echo "</tls-crypt>"
			;;
			2)
				echo "key-direction 1"
				echo "<tls-auth>"
				cat /etc/openvpn/tls-auth.key
				echo "</tls-auth>"
			;;
		esac
	} >> "$homeDir/client.ovpn"
	cd
	cp client.ovpn clientudp.ovpn
	sed -i 's|tcp-client|udp|' /root/clientudp.ovpn
	sed -i 's|1194|587|' /root/clientudp.ovpn
	cp /root/client.ovpn /var/www/html/tcp-$MYIP.ovpn
	cp /root/clientudp.ovpn /var/www/html/udp-$MYIP.ovpn
}

install_screenfetch(){
	wget -O /usr/bin/screenfetch "https://github.com/malikshi/IPTUNNELS/raw/master/config/screenfetch"
	chmod +x /usr/bin/screenfetch
	echo "clear" >> .profile
	echo "screenfetch" >> .profile
}

config_systemctl(){
	echo 1 > /proc/sys/net/ipv4/ip_forward
	echo '* soft nofile 51200' >> /etc/security/limits.conf
	echo '* hard nofile 51200' >> /etc/security/limits.conf
	ulimit -n 51200
	sed -i 's|#net.ipv4.ip_forward=1|net.ipv4.ip_forward=1|' /etc/sysctl.conf
	sed -i 's|net.ipv4.ip_forward=0|net.ipv4.ip_forward=1|' /etc/sysctl.conf
	fallocate -l 2G /swapfile
	chmod 600 /swapfile
	mkswap /swapfile
	swapon /swapfile
	echo '/swapfile none swap sw 0 0' >> /etc/fstab
	sysctl vm.swappiness=40
	sysctl vm.vfs_cache_pressure=50
	swapon -s
	echo 'vm.vfs_cache_pressure = 50
vm.swappiness= 40
fs.file-max = 51200
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.netdev_max_backlog = 250000
net.core.somaxconn = 4096
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.ip_local_port_range = 10000 65000
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_max_tw_buckets = 5000
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mem = 25600 51200 102400
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_mtu_probing = 1' >> /etc/sysctl.conf
	sysctl --system
	sysctl -p
	sysctl -p /etc/sysctl.d/local.conf
}

install_badvpn(){
	cd
	wget https://github.com/ambrop72/badvpn/archive/1.999.130.tar.gz
	tar xf 1.999.130.tar.gz
	mkdir badvpn-build
	cd badvpn-build
	cmake ~/badvpn-1.999.130 -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1 -DBUILD_TUN2SOCKS=1
	make install
	sed -i '$ i\/usr/local/bin/badvpn-udpgw --listen-addr 127.0.0.1:7300' /etc/rc.local
	clear
	cd
}

install_ssh_banner(){
	cd
	echo 'Port 143' >>/etc/ssh/sshd_config
	echo 'MaxAuthTries 2' >>/etc/ssh/sshd_config
	echo 'Banner /etc/issue.net' >>/etc/ssh/sshd_config
	clear
}

install_dropbear(){
	cd
	wget -O /etc/default/dropbear "https://github.com/malikshi/IPTUNNELS/raw/master/config/dropbear"
	echo "/bin/false" >> /etc/shells
	echo "/usr/sbin/nologin" >> /etc/shells
	sed -i 's/obscure/minlen=5/g' /etc/pam.d/common-password
	service ssh restart
	service dropbear restart
	clear
	wget https://matt.ucc.asn.au/dropbear/dropbear-2018.76.tar.bz2
	bzip2 -cd dropbear-2018.76.tar.bz2 | tar xvf -
	cd dropbear-2018.76
	./configure
	make && make install
	mv /usr/sbin/dropbear /usr/sbin/dropbear.old
	ln /usr/local/sbin/dropbear /usr/sbin/dropbear
	cd && rm -rf dropbear-2018.76 && rm -rf dropbear-2018.76.tar.bz2
	service dropbear restart
	clear
}

install_stunnel4(){
	sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
	wget -O /etc/stunnel/stunnel.conf "https://github.com/malikshi/IPTUNNELS/raw/master/config/stunnel.conf"
	sed -i $MYIP2 /etc/stunnel/stunnel.conf
	#setting cert
	country=SG
	state=MAPLETREE
	locality=Bussiness
	organization=GLOBALSSH
	organizationalunit=READYSSH
	commonname=server
	email=admin@iptunnels.com
	openssl genrsa -out key.pem 2048
	openssl req -new -x509 -key key.pem -out cert.pem -days 1095 \
	-subj "/C=$country/ST=$state/L=$locality/O=$organization/OU=$organizationalunit/CN=$commonname/emailAddress=$email"
	cat key.pem cert.pem >> /etc/stunnel/stunnel.pem
	/etc/init.d/stunnel4 restart
	clear
}

install_failban(){
	cd
	service fail2ban restart
	cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
	service fail2ban restart
}

install_squid3(){
	touch /etc/squid/passwd
	/bin/rm -f /etc/squid/squid.conf
	/usr/bin/touch /etc/squid/blacklist.acl
	/usr/bin/wget --no-check-certificate -O /etc/squid/squid.conf https://github.com/malikshi/IPTUNNELS/raw/master/config/squid.conf
	service squid restart
	update-rc.d squid defaults
	#create user default 
	/usr/bin/htpasswd -b -c /etc/squid/passwd GLOBALSSH READYSSH
	service squid restart
	clear
}

config_firewall(){
	NIC=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
	iptables -I INPUT -p tcp --dport 8080 -j ACCEPT
	iptables -I INPUT -p tcp --dport 3128 -j ACCEPT
	iptables -I FORWARD -s 10.9.0.0/24 -j ACCEPT
	iptables -I INPUT -p udp --dport 587 -j ACCEPT
	iptables -t nat -I POSTROUTING -s 10.9.0.0/24 -o $NIC -j MASQUERADE
	iptables-save
	clear
	apt-get -y install iptables-persistent
	netfilter-persistent save
}

config_autostartup(){
	sed -i '$ i\screen -AmdS limit /root/limit.sh' /etc/rc.local
	sed -i '$ i\screen -AmdS ban /root/ban.sh' /etc/rc.local
	sed -i '$ i\service fail2ban restart' /etc/rc.local
	sed -i '$ i\service dropbear restart' /etc/rc.local
	sed -i '$ i\service squid restart' /etc/rc.local
	sed -i '$ i\service webmin restart' /etc/rc.local
	sed -i '$ i\/etc/init.d/stunnel4 restart' /etc/rc.local
	echo "0 0 * * * root /usr/local/bin/user-expire" > /etc/cron.d/user-expire
	echo "0 0 * * * root /usr/local/bin/deltrash" > /etc/cron.d/deltrash
	echo "0 0 * * * root /usr/local/bin/killtrash" > /etc/cron.d/killtrash
	echo "0 0 * * * root /usr/local/bin/expiredtrash" > /etc/cron.d/expiredtrash
}

install_webmin(){
	cd
	echo 'deb http://download.webmin.com/download/repository sarge contrib' >>/etc/apt/sources.list
	echo 'deb http://webmin.mirror.somersettechsolutions.co.uk/repository sarge contrib' >>/etc/apt/sources.list
	wget http://www.webmin.com/jcameron-key.asc
	apt-key add jcameron-key.asc
	apt-get -y update && apt-get -y install webmin
	clear
}

install_automaticdeleteaccount(){
#automatic deleting
cat > /usr/local/bin/deltrash <<END1
#!/bin/bash
nowsecs=$( date +%s )

while read account
do
    username=$( echo $account | cut -d: -f1  )
    expiredays=$( echo $account | cut -d: -f2 )
    expiresecs=$(( $expiredays * 86400 ))
    if [ $expiresecs -le $nowsecs ]
    then
        echo "$username has expired deleting"
        userdel -r "$username"
    fi
done < <( cut -d: -f1,8 /etc/shadow | sed /:$/d )
END1

#automatic killing
cat > /usr/local/bin/killtrash <<END2
while :
  do
  ./userexpired.sh
  sleep 36000
  done
END2


#automatic check trash
cat > /usr/local/bin/expiredtrash <<END3
#!/bin/bash
echo "" > /root/infouser.txt
echo "" > /root/expireduser.txt
echo "" > /root/alluser.txt

cat /etc/shadow | cut -d: -f1,8 | sed /:$/d > /tmp/expirelist.txt
totalaccounts=`cat /tmp/expirelist.txt | wc -l`
for((i=1; i<=$totalaccounts; i++ ))
       do
       tuserval=`head -n $i /tmp/expirelist.txt | tail -n 1`
       username=`echo $tuserval | cut -f1 -d:`
       userexp=`echo $tuserval | cut -f2 -d:`
       userexpireinseconds=$(( $userexp * 86400 ))
       tglexp=`date -d @$userexpireinseconds`             
       tgl=`echo $tglexp |awk -F" " '{print $3}'`
       while [ ${#tgl} -lt 2 ]
       do
           tgl="0"$tgl
       done
       while [ ${#username} -lt 15 ]
       do
           username=$username" " 
       done
       bulantahun=`echo $tglexp |awk -F" " '{print $2,$6}'`
       echo " User : $username Expire tanggal : $tgl $bulantahun" >> /root/alluser.txt
       todaystime=`date +%s`
       if [ $userexpireinseconds -ge $todaystime ] ;
           then
           timeto7days=$(( $todaystime + 604800 ))
                if [ $userexpireinseconds -le $timeto7days ];
                then                     
                     echo " User : $username Expire tanggal : $tgl $bulantahun" >> /root/infouser.txt
                fi
       else
       echo " User : $username Expire tanggal : $tgl $bulantahun" >> /root/expireduser.txt
       passwd -l $username
       fi
done
END3
	chmod +x /usr/local/bin/deltrash
	chmod +x /usr/local/bin/killtrash
	chmod +x /usr/local/bin/expiredtrash
	clear
}

install_premiumscript(){
	cd /usr/local/bin
	wget -O premium-script.tar.gz "https://github.com/malikshi/IPTUNNELS/raw/master/package/premium-script.tar.gz"
	tar -xvf premium-script.tar.gz
	rm -f premium-script.tar.gz
	cp /usr/local/bin/premium-script /usr/local/bin/menu
	cat > /root/ban.sh <<END4
#!/bin/bash
#/usr/local/bin/user-ban
END4

	cat > /root/limit.sh <<END5
#!/bin/bash
#/usr/local/bin/user-limit
END5

	chmod +x /usr/local/bin/trial
	chmod +x /usr/local/bin/user-add
	chmod +x /usr/local/bin/user-aktif
	chmod +x /usr/local/bin/user-ban
	chmod +x /usr/local/bin/user-delete
	chmod +x /usr/local/bin/user-detail
	chmod +x /usr/local/bin/user-expire
	chmod +x /usr/local/bin/user-limit
	chmod +x /usr/local/bin/user-lock
	chmod +x /usr/local/bin/user-login
	chmod +x /usr/local/bin/user-unban
	chmod +x /usr/local/bin/user-unlock
	chmod +x /usr/local/bin/user-password
	chmod +x /usr/local/bin/user-log
	chmod +x /usr/local/bin/user-add-pptp
	chmod +x /usr/local/bin/user-delete-pptp
	chmod +x /usr/local/bin/alluser-pptp
	chmod +x /usr/local/bin/user-login-pptp
	chmod +x /usr/local/bin/user-expire-pptp
	chmod +x /usr/local/bin/user-detail-pptp
	chmod +x /usr/local/bin/bench-network
	chmod +x /usr/local/bin/speedtest
	chmod +x /usr/local/bin/ram
	chmod +x /usr/local/bin/log-limit
	chmod +x /usr/local/bin/log-ban
	chmod +x /usr/local/bin/listpassword
	chmod +x /usr/local/bin/pengumuman
	chmod +x /usr/local/bin/user-generate
	chmod +x /usr/local/bin/user-list
	chmod +x /usr/local/bin/diagnosa
	chmod +x /usr/local/bin/premium-script
	chmod +x /usr/local/bin/user-delete-expired
	chmod +x /usr/local/bin/auto-reboot
	chmod +x /usr/local/bin/log-install
	chmod +x /usr/local/bin/menu
	chmod +x /usr/local/bin/user-auto-limit
	chmod +x /usr/local/bin/user-auto-limit-script
	chmod +x /usr/local/bin/edit-port
	chmod +x /usr/local/bin/edit-port-squid
	chmod +x /usr/local/bin/edit-port-openvpn
	chmod +x /usr/local/bin/edit-port-openssh
	chmod +x /usr/local/bin/edit-port-dropbear
	chmod +x /usr/local/bin/autokill
	chmod +x /root/limit.sh
	chmod +x /root/ban.sh
	screen -AmdS limit /root/limit.sh
	screen -AmdS ban /root/ban.sh
	clear
	cd
}

config_apache2(){
	sed -i 's|Listen 80|Listen 81|' /etc/apache2/ports.conf
	sed -i 's|80|81|' /etc/apache2/sites-enabled/000-default.conf
	systemctl restart apache2
	cd
}

install_bbr(){
	curl -sSL https://github.com/malikshi/IPTUNNELS/raw/master/package/bbr.sh | bash
}

Install_monit_shadowsocks(){
	wget -O /etc/monit/monitrc "https://github.com/malikshi/IPTUNNELS/raw/master/config/monitrc"
	monit reload all
	systemctl enable monit
}
log_file(){
	clear
	echo " "  | tee -a log-install.txt
	echo "Instalasi telah selesai! Mohon baca dan simpan penjelasan setup server!"  | tee -a log-install.txt
	echo " "
	echo "--------------------------- Penjelasan Setup Server ----------------------------"  | tee -a log-install.txt
	echo "            Modified by https://www.facebook.com/ibnumalik.al                   "  | tee -a log-install.txt
	echo "--------------------------------------------------------------------------------"  | tee -a log-install.txt
	echo ""  | tee -a log-install.txt
	echo "Informasi Server"  | tee -a log-install.txt
	echo "Download Client tcp OVPN: http://$MYIP:81/tcp-$MYIP.ovpn"
	echo "Download Client tcp OVPN: http://$MYIP:81/udp-$MYIP.ovpn"
	echo "   - Timezone    : Asia/Jakarta (GMT +7)"  | tee -a log-install.txt
	echo "   - Fail2Ban    : [on]"  | tee -a log-install.txt
	echo "   - IPtables    : [off]"  | tee -a log-install.txt
	echo "   - Auto-Reboot : [on]"  | tee -a log-install.txt
	echo "   - IPv6        : [off]"  | tee -a log-install.txt
	echo ""  | tee -a log-install.txt
	echo "Informasi Aplikasi & Port"  | tee -a log-install.txt
	echo "   - OpenVPN     : TCP 1194 UDP 587 SSL 1443"  | tee -a log-install.txt
	echo "   - OpenSSH     : 22, 143"  | tee -a log-install.txt
	echo "   - OpenSSH-SSL : 444"  | tee -a log-install.txt
	echo "   - Dropbear    : 80, 54793"  | tee -a log-install.txt
	echo "   - Dropbear-SSL: 443"  | tee -a log-install.txt
	echo "   - Squid Proxy : 8080, 3128 (public u/p= GLOBALSSH/READYSSH)"  | tee -a log-install.txt
	echo "   - Squid-SSL   : 8000 (public u/p= GLOBALSSH/READYSSH)"  | tee -a log-install.txt
	echo "   - Badvpn      : 7300"  | tee -a log-install.txt
	echo ""  | tee -a log-install.txt
	echo -e "Congratulations, ${green}shadowsocks-libev${plain} server install completed!"  | tee -a log-install.txt
	echo -e "Your Server IP        : ${red} $MYIP ${plain}"  | tee -a log-install.txt
	echo -e "Your Server Port      : ${red} 53794 ${plain}"  | tee -a log-install.txt
	echo -e "Your Password         : ${red} GLOBALSSH ${plain}"  | tee -a log-install.txt
	echo -e "Your Encryption Method: ${red} chacha20-ietf-poly1305 ${plain}"  | tee -a log-install.txt
	echo -e "Your Cloak's Public Key: ${red} ${publi} ${plain}"  | tee -a log-install.txt
	echo -e "Your Cloak's Private Key: ${red} ${privat} ${plain}"  | tee -a log-install.txt
	echo -e "Your Cloak's AdminUID: ${red} ${admuid} ${plain}"  | tee -a log-install.txt
	echo -e "Download Plugin Cloak PC : https://api.github.com/repos/cbeuw/Cloak/releases/latest"  | tee -a log-install.txt
	echo -e "Download Plugin Cloak Android: https://github.com/cbeuw/Cloak-android/releases"  | tee -a log-install.txt
	echo "Informasi Tools Dalam Server"  | tee -a log-install.txt
	echo "   - htop"  | tee -a log-install.txt
	echo "   - iftop"  | tee -a log-install.txt
	echo "   - mtr"  | tee -a log-install.txt
	echo "   - nethogs"  | tee -a log-install.txt
	echo "   - screenfetch"  | tee -a log-install.txt
	echo ""  | tee -a log-install.txt
	echo "Informasi Premium Script"  | tee -a log-install.txt
	echo "   Perintah untuk menampilkan daftar perintah: menu"  | tee -a log-install.txt
	echo ""  | tee -a log-install.txt
	echo "   Penjelasan script dan setup VPS"| tee -a log-install.txt
	echo ""  | tee -a log-install.txt
	echo "Informasi Penting"  | tee -a log-install.txt
	echo "   - Webmin                  : http://$MYIP:10000/"  | tee -a log-install.txt
	echo "   - Log Instalasi           : cat /root/log-install.txt"  | tee -a log-install.txt
	echo "     NB: User & Password Webmin adalah sama dengan user & password root"  | tee -a log-install.txt
	echo ""  | tee -a log-install.txt
	echo "            Modified by https://www.facebook.com/ibnumalik.al                 "  | tee -a log-install.txt
	cp /root/log-install.txt /var/www/html/
}
exit_all(){
	exit 0;
}

install_all(){
remove_unused_package_disableipv6
install_package_dependency
install_bbr
change_dns_resolver
config_apache2
install_shadowsocks
install_cloak
generate_credentials
install_prepare_cloak
shadowsocks_conf
Install_monit_shadowsocks
install_ovpn
install_screenfetch
config_systemctl
install_badvpn
install_ssh_banner
install_dropbear
install_stunnel4
install_failban
install_squid3
config_firewall
config_autostartup
install_webmin
install_automaticdeleteaccount
install_premiumscript
log_file
reboot
echo "AFTER REBOOT ENJOY YOUR FREEDOM"
}

# Initialization step
action=$1
[ -z $1 ] && action=install
case "$action" in
    install|exit)
        ${action}_all
        ;;
    *)
        echo "Arguments error! [${action}]"
        echo "Usage: `basename $0` [install|exit]"
        ;;
esac
