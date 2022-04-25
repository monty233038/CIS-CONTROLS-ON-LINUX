#!/bin/bash
dpkg -s openbsd-inetd
if [ $? -eq 0 ]
then    
    grep -R "^chargen" /etc/inetd.* 
            if [ $? -eq 0 ]
            then
                    sed -i '/daytime/d' /etc/inetd.conf  /etc/inetd.d/*
            fi
    grep -R "^chargen" /etc/inetd.* 
            if [ $? -eq 0 ]
            then
                    sed -i '/daytime/d' /etc/inetd.conf  /etc/inetd.d/*
            fi

    grep -R "^discard" /etc/inetd.* 
            if [ $? -eq 0 ]
            then
                    sed -i '/discard/d' /etc/inetd.conf  /etc/inetd.d/*
            fi

    grep -R "^time" /etc/inetd.* 
            if [ $? -eq 0 ]
            then
                    sed -i '/time/d' /etc/inetd.conf  /etc/inetd.d/*
            fi

    grep -R "^shell" /etc/inetd.* 
            if [ $? -eq 0 ]
            then
                    sed -i '/shell/d' /etc/inetd.conf  /etc/inetd.d/*
            fi

    grep -R "^time" /login/inetd.* 
            if [ $? -eq 0 ]
            then
                    sed -i '/login/d' /etc/inetd.conf  /etc/inetd.d/*
            fi

    grep -R "^exec" /etc/inetd.* 
            if [ $? -eq 0 ]
            then
                    sed -i '/exec/d' /etc/inetd.conf  /etc/inetd.d/*
            fi
    grep -R "^talk" /etc/inetd.* 
            if [ $? -eq 0 ]
            then
                    sed -i '/talk/d' /etc/inetd.conf  /etc/inetd.d/*
            fi
    grep -R "^ntalk" /etc/inetd.* 
            if [ $? -eq 0 ]
            then
                    sed -i '/ntalk/d' /etc/inetd.conf  /etc/inetd.d/*
            fi

    grep -R "^telnet" /etc/inetd.* 
            if [ $? -eq 0 ]
            then
                    sed -i '/telnet/d' /etc/inetd.conf  /etc/inetd.d/*
            fi
    grep -R "^tftp" /etc/inetd.* 
            if [ $? -eq 0 ]
            then
                    sed -i '/tftp/d' /etc/inetd.conf  /etc/inetd.d/*
            fi
      
#dpkg -s xinetd
#if [$? -eq 0 ]
#then
#	awk '/chargen/{ n=NR+2 } NR==n{ $0="        disable         = yes" }1'   /etc/xinetd.conf /etc/xinetd.d/*
#fi

a=$(systemctl is-enabled xinetd)
if [[ "$a" == "enabled" ]]
then
	systemctl disable xinetd
fi

dpkg -s ntp
if [ $? -ne 0 ]
then
	apt-get install ntp
fi

dpkg -s chrony
if [ $? -ne 0 ]
then
	apt-get install chrony
fi

grep "^restrict" /etc/ntp.conf
if [ $? -ne 0 ]
then
  echo "restrict -4 default kod nomodify notrap nopeer noquery" >> /etc/ntp.conf
  echo "restrict -6 default kod nomodify notrap nopeer noquery" >> /etc/ntp.conf
fi	
		
egrep "^(server|pool)" /etc/ntp.conf
if [ $? -ne 0 ]
then
	echo "server 0.in.pool.ntp.orgr" /etc/ntp.conf	
fi

grep "RUNASUSER=ntp" /etc/init.d/ntp
if [ $? -ne 0 ]
then
	echo "RUNASUSER=ntp"  /etc/init.d/ntp 
fi

dpkg -l xserver-xorg*
if [ $? -eq 0 ]
then
  apt-get remove xserver-xorg*
fi

a=$( systemctl is-enabled avahi-daemon)
if [[ "$a" == "enabled" ]]
then
  systemctl disable avahi-daemon
fi

a=$( systemctl is-enabled cups)
if [[ "$a" == "enabled" ]]
then
  systemctl disable cups
fi

a=$( systemctl is-enabled  isc-dhcp-server)
if [[ "$a" == "enabled" ]]
then
  systemctl disable  isc-dhcp-server
fi

a=$( systemctl is-enabled  isc-dhcp-server)
if [[ "$a" == "enabled" ]]
then
  systemctl disable  isc-dhcp-server
fi

a=$( systemctl is-enabled  slapd)
if [[ "$a" == "enabled" ]]
then
  systemctl disable  slapd
fi

a=$( systemctl is-enabled  slapd)
if [[ "$a" == "enabled" ]]
then
  systemctl disable  slapd
fi

a=$( systemctl is-enabled  nfs-server)
if [[ "$a" == "enabled" ]]
then
  systemctl disable  nfs-server
fi

a=$( systemctl is-enabled  rpcbind)
if [[ "$a" == "enabled" ]]
then
  systemctl disable  rpcbind
fi

a=$( systemctl is-enabled  bind9)
if [[ "$a" == "enabled" ]]
then
  systemctl disable  bind9
fi

a=$( systemctl is-enabled  vsftpd)
if [[ "$a" == "enabled" ]]
then
  systemctl disable  vsftpd
fi

a=$( systemctl is-enabled  apache2)
if [[ "$a" == "enabled" ]]
then
  systemctl disable  apache2
fi

a=$( systemctl is-enabled  dovecot)
if [[ "$a" == "enabled" ]]
then
  systemctl disable  dovecot
fi

a=$( systemctl is-enabled  smbd)
if [[ "$a" == "enabled" ]]
then
  systemctl disable  smbd
fi

a=$( systemctl is-enabled  squid)
if [[ "$a" == "enabled" ]]
then
  systemctl disable  suid
fi

a=$( systemctl is-enabled  snmpd)
if [[ "$a" == "enabled" ]]
then
  systemctl disable  snmpd
fi

a=$( systemctl is-enabled  snmpd)
if [[ "$a" == "enabled" ]]
then
  systemctl disable  snmpd
fi

netstat -an | grep LIST | grep ":25[[:space:]]"
sed -i '/inet_interfaces/d' /etc/postfix/main.cf
echo "inet_interfaces = loopback-only" >> /etc/postfix/main.cf
systemctl restart postfix

a=$( systemctl is-enabled  rsync)
if [[ "$a" == "enabled" ]]
then
  systemctl disable  rsync
fi

a=$( systemctl is-enabled  nis)
if [[ "$a" == "enabled" ]]
then
  systemctl disable  nis
fi

dpkg -s nis
if [ $? -eq 0 ]
then
  apt-get remove nis
fi

dpkg -s rsh-client
if [ $? -eq 0 ]
then
  apt-get remove rsh-client
fi

dpkg -s rsh-redone-client
if [ $? -eq 0 ]
then
  apt-get remove rsh-redone-client
fi


dpkg -s talk
if [ $? -eq 0 ]
then
  apt-get remove talk
fi


dpkg -s telnet
if [ $? -eq 0 ]
then
  apt-get remove telnet
fi


dpkg -s ldap-utils
if [ $? -eq 0 ]
then
  apt-get remove ldap-utils
fi


sed -i '/net.ipv4.ip_forward/d'  /etc/sysctl.conf /etc/sysctl.d/*
echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf /etc/sysctl.d/*
sysctl -w net.ipv4.ip_forward=0
sysctl -w net.ipv4.route.flush=1

sed -i '/net.ipv4.conf.all.send_redirects/d'  /etc/sysctl.conf /etc/sysctl.d/*
echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf /etc/sysctl.d/*
sed -i '/net.ipv4.conf.default.send_redirects/d'  /etc/sysctl.conf /etc/sysctl.d/*
echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf /etc/sysctl.d/*
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0
sysctl -w net.ipv4.route.flush=1


sed -i '/net.ipv4.conf.all.accept_source_route/d'  /etc/sysctl.conf /etc/sysctl.d/*
echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf /etc/sysctl.d/*
sed -i '/net.ipv4.conf.default.accept_source_route/d'  /etc/sysctl.conf /etc/sysctl.d/*
echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf /etc/sysctl.d/*
sysctl -w net.ipv4.conf.all.accept_source_route=0
sysctl -w net.ipv4.conf.default.accept_source_route=0
sysctl -w net.ipv4.route.flush=1

sed -i '/net.ipv4.conf.all.accept_redirects/d'  /etc/sysctl.conf /etc/sysctl.d/*
echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf /etc/sysctl.d/*
sed -i '/net.ipv4.conf.default.accept_redirects/d'  /etc/sysctl.conf /etc/sysctl.d/*
echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf /etc/sysctl.d/*
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0
sysctl -w net.ipv4.route.flush=1

sed -i '/net.ipv4.conf.all.secure_redirects/d'  /etc/sysctl.conf /etc/sysctl.d/*
echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.conf /etc/sysctl.d/*
sed -i '/net.ipv4.conf.default.secure_redirects/d'  /etc/sysctl.conf /etc/sysctl.d/*
echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.conf /etc/sysctl.d/*
sysctl -w net.ipv4.conf.all.secure_redirects=0
sysctl -w net.ipv4.conf.default.secure_redirects=0
sysctl -w net.ipv4.route.flush=1

sed -i '/net.ipv4.conf.all.log_martians/d'  /etc/sysctl.conf /etc/sysctl.d/*
echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.conf /etc/sysctl.d/*
sed -i '/net.ipv4.conf.default.log_martians /d'  /etc/sysctl.conf /etc/sysctl.d/*
echo "net.ipv4.conf.default.log_martians  = 1" >> /etc/sysctl.conf /etc/sysctl.d/*
sysctl -w net.ipv4.conf.all.log_martians=1
sysctl -w net.ipv4.conf.default.log_martians=1
sysctl -w net.ipv4.route.flush=1


sed -i '/net.ipv4.icmp_echo_ignore_broadcasts/d'  /etc/sysctl.conf /etc/sysctl.d/*
echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf /etc/sysctl.d/*
sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
sysctl -w net.ipv4.route.flush=1


sed -i '/net.ipv4.icmp_ignore_bogus_error_responses/d'  /etc/sysctl.conf /etc/sysctl.d/*
echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.conf /etc/sysctl.d/*
sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
sysctl -w net.ipv4.route.flush=1


sed -i '/net.ipv4.conf.all.rp_filter/d'  /etc/sysctl.conf /etc/sysctl.d/*
echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf /etc/sysctl.d/*
sed -i '/net.ipv4.conf.default.rp_filter/d'  /etc/sysctl.conf /etc/sysctl.d/*
echo "net.ipv4.conf.default.rp_filters = 1" >> /etc/sysctl.conf /etc/sysctl.d/*
sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -w net.ipv4.conf.default.rp_filter=1
sysctl -w net.ipv4.route.flush=1

sed -i '/net.ipv4.tcp_syncookies/d'  /etc/sysctl.conf /etc/sysctl.d/*
echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf /etc/sysctl.d/*
sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv4.route.flush=1

sed -i '/net.ipv6.conf.all.accept_ra /d'  /etc/sysctl.conf /etc/sysctl.d/*
echo "net.ipv6.conf.all.accept_ra  = 0" >> /etc/sysctl.conf /etc/sysctl.d/*
sed -i '/net.ipv4.conf.default.rp_filter/d'  /etc/sysctl.conf /etc/sysctl.d/*
echo "net.ipv4.conf.default.rp_filters = 1" >> /etc/sysctl.conf /etc/sysctl.d/*

dpkg -s tcpd
if [ $? -ne 0 ]
then
  apt-get install tcpd
fi

echo "ALL: 192.168.1.0/255.255.255.0" > /etc/hosts.allow
echo "ALL: ALL" >> /etc/hosts.deny
chown root:root /etc/hosts.allow
chmod 644 /etc/hosts.allow
chown root:root /etc/hosts.deny
chmod 644 /etc/hosts.deny

modprobe -n -v rds
if [ $? -eq 0 ]
then
  lsmod | grep rds
  if [ $? -ne 0 ]
  then
    echo "install rds /bin/true" > /etc/modprobe.d/rds.conf
  fi
fi

modprobe -n -v tipc
if [ $? -eq 0 ]
then
  lsmod | grep tipc
  if [ $? -ne 0 ]
  then
    echo "install tipc /bin/true" > /etc/modprobe.d/tipc.conf
  fi
fi

modprobe -n -v sctp
if [ $? -eq 0 ]
then
  lsmod | grep sctp
  if [ $? -ne 0 ]
  then
    echo "install sctp /bin/true" > /etc/modprobe.d/sctp.conf
  fi
fi

modprobe -n -v dccp
if [ $? -eq 0 ]
then
  lsmod | grep dccp
  if [ $? -ne 0 ]
  then
    echo "install dccp /bin/true" > /etc/modprobe.d/dccp.conf
  fi
fi


























