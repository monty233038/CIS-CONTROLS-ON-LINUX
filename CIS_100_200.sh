#!/bin/bash
apt-get update
echo -e "y" | apt-get install openbsd-inetd
dpkg -s openbsd-inetd
if [ $? -eq 0 ]
then    
    echo -e "\e[1;31m Ensure CHARGEN is not enabled \e[0m"
    grep -R "^chargen" /etc/inetd.* 
            if [ $? -eq 0 ]
            then
                    sed -i '/chargen/d' /etc/inetd.conf  /etc/inetd.d/*
            fi

    echo -e "\e[1;31m Ensure DAYTIME is not enabled \e[0m"
    grep -R "^daytime" /etc/inetd.* 
            if [ $? -eq 0 ]
            then
                    sed -i '/daytime/d' /etc/inetd.conf  /etc/inetd.d/*
            fi
	    
    echo -e "\e[1;31m Ensure ECHO client is not installed \e[0m"
    grep -R "^echo" /etc/inetd.* 
            if [ $? -eq 0 ]
            then
                    sed -i '/echo/d' /etc/inetd.conf  /etc/inetd.d/*
            fi
    echo -e "\e[1;31m Ensure DISCARD client is not installed \e[0m"
    grep -R "^discard" /etc/inetd.* 
            if [ $? -eq 0 ]
            then
                    sed -i '/discard/d' /etc/inetd.conf  /etc/inetd.d/*
            fi
    echo -e "\e[1;31m Ensure TIME is not enabled \e[0m"
    grep -R "^time" /etc/inetd.* 
            if [ $? -eq 0 ]
            then
                    sed -i '/time/d' /etc/inetd.conf  /etc/inetd.d/*
            fi
    echo -e "\e[1;31m Ensure SHELL is not enabled \e[0m"
    grep -R "^shell" /etc/inetd.* 
            if [ $? -eq 0 ]
            then
                    sed -i '/shell/d' /etc/inetd.conf  /etc/inetd.d/*
            fi
    echo -e "\e[1;31m Ensure LOGIN  is not enabled \e[0m"
    grep -R "^login" /etc/inetd.* 
            if [ $? -eq 0 ]
            then
                    sed -i '/login/d' /etc/inetd.conf  /etc/inetd.d/*
            fi
    echo -e "\e[1;31m Ensure EXEC  is not enabled \e[0m"
    grep -R "^exec" /etc/inetd.* 
            if [ $? -eq 0 ]
            then
                    sed -i '/exec/d' /etc/inetd.conf  /etc/inetd.d/*
            fi
   echo -e "\e[1;31m Ensure TALK  is not enabled \e[0m"	    
    grep -R "^talk" /etc/inetd.* 
            if [ $? -eq 0 ]
            then
                    sed -i '/talk/d' /etc/inetd.conf  /etc/inetd.d/*
            fi
    echo -e "\e[1;31m Ensure NTALK  is not enabled \e[0m"	    
    grep -R "^ntalk" /etc/inetd.* 
            if [ $? -eq 0 ]
            then
                    sed -i '/ntalk/d' /etc/inetd.conf  /etc/inetd.d/*
            fi
    echo -e "\e[1;31m Ensure TELNET  is not enabled \e[0m"
    grep -R "^telnet" /etc/inetd.* 
            if [ $? -eq 0 ]
            then
                    sed -i '/telnet/d' /etc/inetd.conf  /etc/inetd.d/*
            fi
    echo -e "\e[1;31m Ensure TFTPD  is not enabled \e[0m"	    
    grep -R "^tftp" /etc/inetd.* 
            if [ $? -eq 0 ]
            then
                    sed -i '/tftp/d' /etc/inetd.conf  /etc/inetd.d/*
            fi
fi
      
#dpkg -s xinetd
#if [$? -eq 0 ]
#then
#	awk '/chargen/{ n=NR+2 } NR==n{ $0="        disable         = yes" }1'   /etc/xinetd.conf /etc/xinetd.d/*
#fi

echo -e "\e[1;31m Ensure XINETD client is not enabled \e[0m"
a=$(systemctl is-enabled xinetd)
if [[ "$a" == "enabled" ]]
then
	systemctl disable xinetd
fi

echo -e "\e[1;31m Ensure NTP client is not installed \e[0m"
dpkg -s ntp
if [ $? -ne 0 ]
then
	echo -e "y" | apt-get install ntp
fi

echo -e "\e[1;31m Ensure CHRONY client is not installed \e[0m"
dpkg -s chrony
if [ $? -ne 0 ]
then
	echo -e "y" | apt-get install chrony
fi

echo -e "\e[1;31m  Ensure ntp is configured \e[0m"
grep "^restrict" /etc/ntp.conf
if [ $? -ne 0 ]
then
  echo "restrict -4 default kod nomodify notrap nopeer noquery" >> /etc/ntp.conf
  echo "restrict -6 default kod nomodify notrap nopeer noquery" >> /etc/ntp.conf
fi	

egrep "^(server|pool)" /etc/ntp.conf
if [ $? -ne 0 ]
then
	echo "server 0.in.pool.ntp.org" /etc/ntp.conf
	echo "server 1.in.pool.ntp.org" /etc/chrony/chrony.conf
fi

grep "RUNASUSER=ntp" /etc/init.d/ntp
if [ $? -ne 0 ]
then
	echo "RUNASUSER=ntp"  /etc/init.d/ntp 
fi

echo -e "\e[1;31m  Ensure chrony is configured \e[0m"
grep "^(server|pool)" /etc/chrony/chrony.conf
if [ $? -ne 0 ]
then
	echo "server 0.in.pool.ntp.org" /etc/chrony/chrony.conf
	echo "server 1.in.pool.ntp.org" /etc/chrony/chrony.conf
fi

echo -e "\e[1;31m Ensure xserver-xorg client is not installed \e[0m"
dpkg -l xserver-xorg*
if [ $? -eq 0 ]
then
  apt-get remove xserver-xorg*
fi

echo -e "\e[1;31m Ensure avahi-daemon service is not enabled \e[0m"
a=$( systemctl is-enabled avahi-daemon)
if [[ "$a" == "enabled" ]]
then
  systemctl disable avahi-daemon
fi

echo -e "\e[1;31m Ensure CUPS service is not enabled \e[0m"
a=$( systemctl is-enabled cups)
if [[ "$a" == "enabled" ]]
then
  systemctl disable cups
fi

echo -e "\e[1;31m Ensure ISC-DHCP-SERVER service is not enabled \e[0m"
a=$( systemctl is-enabled  isc-dhcp-server)
if [[ "$a" == "enabled" ]]
then
  systemctl disable  isc-dhcp-server
fi

echo -e "\e[1;31m Ensure ISC-DHCP-SERVER6 service is not enabled \e[0m"
a=$( systemctl is-enabled  isc-dhcp-server6)
if [[ "$a" == "enabled" ]]
then
  systemctl disable  isc-dhcp-server6
fi

echo -e "\e[1;31m Ensure SLAPD service is not enabled \e[0m"
a=$( systemctl is-enabled  slapd)
if [[ "$a" == "enabled" ]]
then
  systemctl disable  slapd
fi

echo -e "\e[1;31m Ensure NFS-SERVER  is not enabled \e[0m"
a=$( systemctl is-enabled  nfs-server)
if [[ "$a" == "enabled" ]]
then
  systemctl disable  nfs-server
fi

echo -e "\e[1;31m Ensure RPCBIND service is not enabled \e[0m"
a=$( systemctl is-enabled  rpcbind)
if [[ "$a" == "enabled" ]]
then
  systemctl disable  rpcbind
fi

echo -e "\e[1;31m Ensure BIND9 service is not enabled \e[0m"
a=$( systemctl is-enabled  bind9)
if [[ "$a" == "enabled" ]]
then
  systemctl disable  bind9
fi

echo -e "\e[1;31m Ensure VSFTPD service is not enabled \e[0m"
a=$( systemctl is-enabled  vsftpd)
if [[ "$a" == "enabled" ]]
then
  systemctl disable  vsftpd
fi

echo -e "\e[1;31m Ensure APACHE2 service is not enabled \e[0m"
a=$( systemctl is-enabled  apache2)
if [[ "$a" == "enabled" ]]
then
  systemctl disable  apache2
fi


echo -e "\e[1;31m Ensure DOVECOT service is not enabled \e[0m"
a=$( systemctl is-enabled  dovecot)
if [[ "$a" == "enabled" ]]
then
  systemctl disable  dovecot
fi

echo -e "\e[1;31m Ensure SMBD service is not enabled \e[0m"
a=$( systemctl is-enabled  smbd)
if [[ "$a" == "enabled" ]]
then
  systemctl disable  smbd
fi

echo -e "\e[1;31m Ensure SQUID service is not enabled \e[0m"
a=$( systemctl is-enabled  squid)
if [[ "$a" == "enabled" ]]
then
  systemctl disable  squid
fi

echo -e "\e[1;31m Ensure snmpd service is not enabled \e[0m"
a=$( systemctl is-enabled  snmpd)
if [[ "$a" == "enabled" ]]
then
  systemctl disable  snmpd
fi

echo -e "\e[1;31m  Ensure mail transfer agent is configured for local-only mode  \e[0m"
netstat -an | grep LIST | grep ":25[[:space:]]"
sed -i '/inet_interfaces/d' /etc/postfix/main.cf
echo "inet_interfaces = loopback-only" >> /etc/postfix/main.cf
systemctl restart postfix

echo -e "\e[1;31m Ensure rsync service is not enabled \e[0m"
a=$( systemctl is-enabled  rsync)
if [[ "$a" == "enabled" ]]
then
  systemctl disable  rsync
fi

echo -e "\e[1;31m Ensure nis service is not enabled \e[0m"
a=$( systemctl is-enabled  nis)
if [[ "$a" == "enabled" ]]
then
  systemctl disable  nis
fi

echo -e "\e[1;31m Ensure NIS client is not installed \e[0m"
dpkg -s nis
if [ $? -eq 0 ]
then
  apt-get remove nis
fi

echo -e "\e[1;31m Ensure RSH-CLIENT client is not installed \e[0m"
dpkg -s rsh-client
if [ $? -eq 0 ]
then
  apt-get remove rsh-client
fi

echo -e "\e[1;31m Ensure RSH-REDONE-CLIENT client is not installed \e[0m"
dpkg -s rsh-redone-client
if [ $? -eq 0 ]
then
  apt-get remove rsh-redone-client
fi

echo -e "\e[1;31m Ensure TALK client is not installed \e[0m"
dpkg -s talk
if [ $? -eq 0 ]
then
  apt-get remove talk
fi

echo -e "\e[1;31m Ensure TELNET client is not installed \e[0m"
dpkg -s telnet
if [ $? -eq 0 ]
then
  apt-get remove telnet
fi

echo -e "\e[1;31m Ensure LDAP client is not installed \e[0m"
dpkg -s ldap-utils
if [ $? -eq 0 ]
then
  echo -e "y" | apt-get remove ldap-utils
fi

echo -e "\e[1;31m Ensure IP forwarding is disabled \e[0m"
sed -i '/net.ipv4.ip_forward/d'  /etc/sysctl.conf /etc/sysctl.d/*
echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf /etc/sysctl.d/*
sysctl -w net.ipv4.ip_forward=0
sysctl -w net.ipv4.route.flush=1

echo -e "\e[1;31m Ensure packet redirect sending is disabled \e[0m"
sed -i '/net.ipv4.conf.all.send_redirects/d'  /etc/sysctl.conf /etc/sysctl.d/*
echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf /etc/sysctl.d/*
sed -i '/net.ipv4.conf.default.send_redirects/d'  /etc/sysctl.conf /etc/sysctl.d/*
echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf /etc/sysctl.d/*
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0
sysctl -w net.ipv4.route.flush=1

echo -e "\e[1;31m Ensure source routed packets are not accepted \e[0m"
sed -i '/net.ipv4.conf.all.accept_source_route/d'  /etc/sysctl.conf /etc/sysctl.d/*
echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf /etc/sysctl.d/*
sed -i '/net.ipv4.conf.default.accept_source_route/d'  /etc/sysctl.conf /etc/sysctl.d/*
echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf /etc/sysctl.d/*
sysctl -w net.ipv4.conf.all.accept_source_route=0
sysctl -w net.ipv4.conf.default.accept_source_route=0
sysctl -w net.ipv4.route.flush=1

echo -e "\e[1;31m Ensure ICMP redirects are not accepted  \e[0m"
sed -i '/net.ipv4.conf.all.accept_redirects/d'  /etc/sysctl.conf /etc/sysctl.d/*
echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf /etc/sysctl.d/*
sed -i '/net.ipv4.conf.default.accept_redirects/d'  /etc/sysctl.conf /etc/sysctl.d/*
echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf /etc/sysctl.d/*
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0
sysctl -w net.ipv4.route.flush=1

echo -e "\e[1;31m Ensure secure ICMP redirects are not accepted \e[0m"
sed -i '/net.ipv4.conf.all.secure_redirects/d'  /etc/sysctl.conf /etc/sysctl.d/*
echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.conf /etc/sysctl.d/*
sed -i '/net.ipv4.conf.default.secure_redirects/d'  /etc/sysctl.conf /etc/sysctl.d/*
echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.conf /etc/sysctl.d/*
sysctl -w net.ipv4.conf.all.secure_redirects=0
sysctl -w net.ipv4.conf.default.secure_redirects=0
sysctl -w net.ipv4.route.flush=1

echo -e "\e[1;31m Ensure suspicious packets are logged \e[0m"
sed -i '/net.ipv4.conf.all.log_martians/d'  /etc/sysctl.conf /etc/sysctl.d/*
echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.conf /etc/sysctl.d/*
sed -i '/net.ipv4.conf.default.log_martians /d'  /etc/sysctl.conf /etc/sysctl.d/*
echo "net.ipv4.conf.default.log_martians  = 1" >> /etc/sysctl.conf /etc/sysctl.d/*
sysctl -w net.ipv4.conf.all.log_martians=1
sysctl -w net.ipv4.conf.default.log_martians=1
sysctl -w net.ipv4.route.flush=1

echo -e "\e[1;31m Ensure broadcast ICMP requests are ignored \e[0m"
sed -i '/net.ipv4.icmp_echo_ignore_broadcasts/d'  /etc/sysctl.conf /etc/sysctl.d/*
echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf /etc/sysctl.d/*
sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
sysctl -w net.ipv4.route.flush=1

echo -e "\e[1;31m Ensure bogus ICMP responses are ignored \e[0m"
sed -i '/net.ipv4.icmp_ignore_bogus_error_responses/d'  /etc/sysctl.conf /etc/sysctl.d/*
echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.conf /etc/sysctl.d/*
sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
sysctl -w net.ipv4.route.flush=1

echo -e "\e[1;31m Ensure Reverse Path Filtering is enabled \e[0m"
sed -i '/net.ipv4.conf.all.rp_filter/d'  /etc/sysctl.conf /etc/sysctl.d/*
echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf /etc/sysctl.d/*
sed -i '/net.ipv4.conf.default.rp_filter/d'  /etc/sysctl.conf /etc/sysctl.d/*
echo "net.ipv4.conf.default.rp_filters = 1" >> /etc/sysctl.conf /etc/sysctl.d/*
sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -w net.ipv4.conf.default.rp_filter=1
sysctl -w net.ipv4.route.flush=1

echo -e "\e[1;31m Ensure TCP SYN Cookies is enabled \e[0m"
sed -i '/net.ipv4.tcp_syncookies/d'  /etc/sysctl.conf /etc/sysctl.d/*
echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf /etc/sysctl.d/*
sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv4.route.flush=1

echo -e "\e[1;31m Ensure IPv6 router advertisements are not accepted \e[0m"
sed -i '/nnet.ipv6.conf.all.accept_ra/d'  /etc/sysctl.conf /etc/sysctl.d/*
echo "net.ipv6.conf.all.accept_ra  = 0" >> /etc/sysctl.conf /etc/sysctl.d/*
sed -i '/net.ipv6.conf.default.accept_ra/d'  /etc/sysctl.conf /etc/sysctl.d/*
echo "net.ipv6.conf.default.accept_ra = 0" >> /etc/sysctl.conf /etc/sysctl.d/*

echo -e "\e[1;31m Ensure IPv6 redirects are not accepted \e[0m"
sed -i '/net.ipv6.conf.all.accept_redirects/d'  /etc/sysctl.conf /etc/sysctl.d/*
echo "net.ipv6.conf.all.accept_redirects  = 0" >> /etc/sysctl.conf /etc/sysctl.d/*
sed -i '/net.ipv6.conf.default.accept_redirects/d'  /etc/sysctl.conf /etc/sysctl.d/*
echo "net.ipv6.conf.default.accept_redirects = 0" >> /etc/sysctl.conf /etc/sysctl.d/*
sysctl -w net.ipv6.conf.all.accept_redirects=0
sysctl -w net.ipv6.conf.default.accept_redirects=0
sysctl -w net.ipv6.route.flush=1
  
echo -e "\e[1;31m   Ensure TCP Wrappers is installed \e[0m"
dpkg -s tcpd
if [ $? -ne 0 ]
then
   echo -e "y" | apt-get install tcpd
fi

a=$(default_if=$(ip route list | awk '/^default/ {print $5}'))
b=$(ip -o -f inet addr show $default_if | awk '{print $4}')

echo -e "\e[1;31m  Ensure /etc/hosts.allow is configured  \e[0m"
echo "ALL: $(echo $b)" > /etc/hosts.allow

echo -e "\e[1;31m  Ensure /etc/hosts.deny is configured  \e[0m"
echo "ALL: ALL" >> /etc/hosts.deny

echo -e "\e[1;31m Ensure permissions on /etc/hosts.allow are configured \e[0m"
chown root:root /etc/hosts.allow
chmod 644 /etc/hosts.allow

echo -e "\e[1;31m Ensure permissions on /etc/hosts.deny are configured \e[0m"
chown root:root /etc/hosts.deny
chmod 644 /etc/hosts.deny

echo -e "\e[1;31m Ensure RDS is disabled \e[0m"
modprobe -n -v rds
if [ $? -eq 0 ]
then
  lsmod | grep rds
  if [ $? -ne 0 ]
  then
    echo "install rds /bin/true" > /etc/modprobe.d/rds.conf
  fi
fi

echo -e "\e[1;31m Ensure tipc is disabled \e[0m"
modprobe -n -v tipc
if [ $? -eq 0 ]
then
  lsmod | grep tipc
  if [ $? -ne 0 ]
  then
    echo "install tipc /bin/true" > /etc/modprobe.d/tipc.conf
  fi
fi

echo -e "\e[1;31m Ensure sctp is disabled \e[0m"
modprobe -n -v sctp
if [ $? -eq 0 ]
then
  lsmod | grep sctp
  if [ $? -ne 0 ]
  then
    echo "install sctp /bin/true" > /etc/modprobe.d/sctp.conf
  fi
fi

echo -e "\e[1;31m Ensure dccp is disabled \e[0m"
modprobe -n -v dccp
if [ $? -eq 0 ]
then
  lsmod | grep dccp
  if [ $? -ne 0 ]
  then
    echo "install dccp /bin/true" > /etc/modprobe.d/dccp.conf
  fi
fi


























