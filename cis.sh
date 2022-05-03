!#/bin/bash

mod(){
	modprobe -n -v $1
	if [ $? -eq 0 ]
	then
		lsmod  | grep $1
		if [ $? -ne 0 ]
		then
			echo "install $1 /bin/true" > /etc/modprobe/$1.conf
			rmmod $1
		fi
	fi
}
mod ufw
mod cramfs
mod jffs2
mod hfs
mod hfsplus
mod udf
mod freevxfs

echo -e "\e[1;31m creating physical volume and volume group \e[0m"
pvcreate /dev/sdb
vgcreate vol /dev/sdb
sleep 3
echo -e "\e[1;31m physical volume and volume group created successfully \e[0m"
echo -e "\e[1;31m Ensure separate mount point exist for /tmp \e[0m"
mount | grep /tmp
if [ $? -eq 0 ]
then

	lvcreate -L 500 -n tmp vol
	mkfs.ext4 /dev/vol/tmp
	umount /tmp
	mkdir /a
	mount /dev/vol/tmp /a
	rsync -a /tmp/ /a
	echo "/dev/vol/tmp	/tmp	ext4	rw,nosuid,nodev,noexec,relatime		1	2" >> /etc/fstab
	mount -a
	umount /a
	rm -r /a
else

	
	lvcreate -L 500 -n tmp vol
	mkfs.ext4 /dev/vol/tmp
	mkdir /a
	mount /dev/vol/tmp /a
	rsync -a /tmp/ /a
	echo "/dev/vol/tmp	/tmp	ext4	rw,nosuid,nodev,noexec,relatime		1	2" >> /etc/fstab
	mount -a
	umount /a
	rm -r /a
fi
sleep 5
echo -e "\e[1;31m separate mount point for /tmp created successfully \e[0m"

echo -e "\e[1;31m Ensure nodev option set on /tmp partition \e[0m"
mount | grep /tmp | grep nodev
if [ $? -ne 0 ]
then
	awk'$1~"/dev/vol/tmp"{$4="nodev,"$4}'1 OFS="\t" /etc/fstab
	mount -o remount,nodev /tmp
fi

echo -e "\e[1;31m Ensure nosuid option set on /tmp partition \e[0m"
mount | grep /tmp | grep nosuid
if [ $? -ne 0 ]
then
	awk'$1~"/dev/vol/tmp"{$4="nosuid,"$4}'1 OFS="\t" /etc/fstab
	mount -o remount,nosuid /tmp
fi


echo -e "\e[1;31m Ensure separate mount point exist for /var \e[0m"
sleep 5
mount | grep /var
if [ $? -eq 0 ]
then
	
	lvcreate -L 5000 -n var vol
	mkfs.ext4 /dev/vol/var
	umount /var
	mkdir /a
	mount /dev/vol/var /a
	rsync -a /var/ /a
	echo "/dev/vol/var	/var	ext4	rw,relatime,data=ordered		1	2" >> /etc/fstab
	mount -a
	umount /a
	rm -r /a
	
else

	lvcreate -L 5000 -n var vol
	mkfs.ext4 /dev/vol/var
	mkdir /a
	mount /dev/vol/var /a
	rsync -a /var/ /a
	echo "/dev/vol/var	/var	ext4	rw,relatime,data=ordered		1	2" >> /etc/fstab
	mount -a
	umount /a
	rm -r /a
fi



echo -e "\e[1;31m Ensure separate mount point exist for /var/tmp \e[0m"
sleep 5
mount | grep /var/tmp
if [ $? -eq 0 ]
then
	lvcreate -L 500 -n var-tmp vol
	mkfs.ext4 /dev/vol/var-tmp
	mkdir /a
	umount /var/tmp
	mount /dev/vol/var-tmp /a
	rsync -a /var/tmp /a
	echo "/dev/vol/var-tmp	/var/tmp	ext4	rw,nosuid,nodev,noexec,relatime		1	2" >> /etc/fstab
	mount -a
	umount /a
	rm -r /a
else

	lvcreate -L 500 -n var-tmp vol
	mkfs.ext4 /dev/vol/var-tmp
	mkdir /a
	mount /dev/vol/var-tmp /a
	rsync -a /var/tmp /a
	echo "/dev/vol/var-tmp	/var/tmp	ext4	rw,nosuid,nodev,noexec,relatime		1	2" >> /etc/fstab
	mount -a
	umount /a
	rm -r /a
fi


echo -e "\e[1;31m Ensure nodev option set on /var/tmp partition \e[0m"
mount | grep /var/tmp | grep nodev
if [ $? -ne 0 ]
then
	awk'$1~"/dev/vol/var-tmp"{$4="nodev,"$4}'1 OFS="\t" /etc/fstab
	mount -o remount,nodev /var/tmp
fi

echo -e "\e[1;31m Ensure nosuid option set on /var/tmp partition \e[0m"
mount | grep /var/tmp | grep nosuid
if [ $? -ne 0 ]
then
	awk'$1~"/dev/vol/var-tmp"{$4="nosuid,"$4}'1 OFS="\t" /etc/fstab
	mount -o remount,nosuid /var/tmp
fi


echo -e "\e[1;31m Ensure noexec option set on /var/tmp partition \e[0m"
mount | grep /var/tmp | grep noexec
if [ $? -ne 0 ]
then
	awk'$1~"/dev/vol/var-tmp"{$4="noexec,"$4}'1 OFS="\t" /etc/fstab
	mount -o remount,noexec /var/tmp
fi

echo -e "\e[1;31m Ensure separate mount point exist for /var/log \e[0m"
sleep 5
mount | grep /var/log
if [ $? -eq 0 ]
then

	lvcreate -L 500 -n var-log vol
	mkfs.ext4 /dev/vol/var-log
	umount /var/log
	mkdir /a
	mount /dev/vol/var-log /a
	rsync -a /var/log /a
	echo "/dev/vol/var-log	/var/log	ext4	rw,relatime,data=ordered		1	2" >> /etc/fstab
	mount -a
	umount /a
	rm -r /a
	
else

	
	lvcreate -L 500 -n var-log vol
	mkfs.ext4 /dev/vol/var-log
	mkdir /a
	mount /dev/vol/var-log /a
	rsync -a /var/log /a
	echo "/dev/vol/var-log	/var/log	ext4	rw,relatime,data=ordered		1	2" >> /etc/fstab
	mount -a
	umount /a
	rm -r /a
fi



echo -e "\e[1;31m Ensure separate mount point exist for /var/log/audit \e[0m"
sleep 5
mount | grep /var/log/audit
if [ $? -eq 0 ]
then
	lvcreate -L 500 -n var-log-audit  vol
	mkfs.ext4 /dev/vol/var-log-audit
	umount /var/log/audit
	mkdir /a
	mount /dev/vol/var-log-audit /a
	rsync -a /var/log/audit /a
	echo "/dev/vol/var-log-audit	/var/log/audit		ext4	rw,relatime,data=ordered	1	2" >> /etc/fstab
	mount -a
	umount /a
	rm -r /a
else
	lvcreate -L 500 -n var-log-audit  vol
	mkfs.ext4 /dev/vol/var-log-audit
	mkdir /a
	mount /dev/vol/var-log-audit /a
	rsync -a /var/log/audit /a
	echo "/dev/vol/var-log-audit	/var/log/audit		ext4	rw,relatime,data=ordered	1	2" >> /etc/fstab
	mount -a
	umount /a
	rm -r /a
fi



echo -e "\e[1;31m Ensure separate mount point exist for /home \e[0m"
mount | grep /home
if [ $? -eq 0 ]
then

	lvcreate -L 500 -n home  vol
	mkfs.ext4 /dev/vol/home
	umount /home
	mkdir /a
	mount /dev/vol/home /a
	rsync -a /home/ /a
	echo "/dev/vol/home	/home		ext4	rw,nodev,relatime,data=ordered	1	2" >> /etc/fstab
	mount -a
	umount /a
	rm -r /a
else
	lvcreate -L 500 -n home  vol
	mkfs.ext4 /dev/vol/home
	mkdir /a
	mount /dev/vol/home /a
	rsync -a /home/ /a
	echo "/dev/vol/home	/home		ext4	rw,nodev,relatime,data=ordered	1	2" >> /etc/fstab
	mount -a
	umount /a
	rm -r /a
fi


echo -e "\e[1;31m Ensure nodev option set on /home partition \e[0m"
mount | grep /home | grep nodev
if [ $? -ne 0 ]
then
	awk'$1~"/dev/vol/home"{$4="nodev,"$4}'1 OFS="\t" /etc/fstab
	mount -o remount,nodev /home
fi

echo -e "\e[1;31m Ensure nodev option set on /dev/shm partition \e[0m"
mount | grep /dev/shm | grep nodev
if [ $? -ne 0 ]
then
	mount -o remount,nodev /dev/shm
fi

echo -e "\e[1;31m Ensure nosuid option set on /dev/shm partition \e[0m"
mount | grep /dev/shm | grep nosuid
if [ $? -ne 0 ]
then
	mount -o remount,nosuid /dev/shm
fi

echo -e "\e[1;31m Ensure noexec option set on /dev/shm partition \e[0m"
mount | grep /dev/shm | grep noexec
if [ $? -ne 0 ]
then
	mount -o remount,noexec /dev/shm
fi


echo -e "\e[1;31m Ensure sticky bit is set on all world-writable directories \e[0m"
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t

echo -e "\e[1;31m Disable Automounting \e[0m"
dpkg -s autofs
if [ $? -eq 0 ]
then
	ser_stat=$(systemctl is-enabled autofs)
	if [ "$ser_stat" == "enabled" ]
	then
		systemctl disable autofs
	fi
fi	
sleep 5
echo -e "\e[1;31m Ensure AIDE is installed \e[0m"
dpkg -s aide
#if [ $? -ne 0 ]
#then
#	echo -e "y" | apt-get install aide aide-common
#	aideinit
#fi
sleep 5

echo -e "\e[1;31m Ensure filesystem integrity is regularly checked \e[0m"            
crontab -l | { cat; echo "0 5 * * * /usr/bin/aide.wrapper --config /etc/aide/aide.conf"; } | crontab

echo -e "\e[1;31m Ensure permissions on bootloader config are configured \e[0m"
chown root:root /boot/grub/grub.cfg
chmod og-rwx /boot/grub/grub.cfg


echo -e "\e[1;31m Ensure bootloader password is set \e[0m"
grep "^set superusers" /boot/grub/grub.cfg
if [ $? -ne 0 ] 
then
	grep "^password" /boot/grub/grub.cfg
	if [ $? -ne 0 ]
	then
		echo -e "password\npassword" | grub-mkpasswd-pbkdf2 > pass1
		tail -n 1 pass1 > pass2
		sed -i 's/PBKDF2 hash of your password is//g' pass2
		echo 'set superusers="root"' >> /etc/grub.d/00_header
		echo "set password_pbkdf2 root $(cat pass2)" >> /etc/grub.d/00_header
		rm pass1 pass2
		update-grub
	fi
fi


echo -e "\e[1;31m Ensure authentication required for single user mode \e[0m"
grep "^root:[*\!]:" /etc/shadow
if [ $? -ne 0 ]
then
	echo -e "password\npassword" | passwd root

fi

echo  -e "\e[1;31m Ensure core dumps are restricted \e[0m"
echo "* hard core 0" >>  /etc/security/limits.conf

grep "fs\.suid_dumpable" /etc/sysctl.conf /etc/sysctl.d/*
if [ $? -ne 0 ]
then
	echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf
	sysctl -w fs.suid_dumpable=0
fi

grep "kernel\.randomize_va_space" /etc/sysctl.conf /etc/sysctl.d/*
if [ $? -ne 0 ]
then
	echo "kernel.randomize_va_space = 2" >>  /etc/sysctl.conf
	sysctl -w kernel.randomize_va_space=2
fi

echo -e "\e[1;31m Ensure prelink is disabled \e[0m"
dpkg -s prelink
if [ $? -eq 0 ]
then
	prelink -ua
	apt-get remove prelink
fi

echo -e "\e[1;31m checking whether apparmor is installed or not \e[0m"
dpkg -s apparmor
if [ $? -ne 0 ]
then
	echo -e "Y" | apt-get install apparmor 

fi

dpkg -s apparmor-utils
if [ $? -ne 0 ]
then 
	echo -e "y" | apt-get install apparmor-utils

fi

echo -e "\e[1;31m Ensure AppArmor is not disabled in bootloader configuration \e[0m" 
grep "apparmor=0" /boot/grub/grub.cfg
if [ $? -eq 0 ]
then
	sed '/apparmor=0/d' /etc/default/grub
	update-grub
fi

echo -e "\e[1;31m Ensure all AppArmor Profiles are enforcing \e[0m"
a=$(apparmor_status | grep profiles | grep complain | awk '{print $1;}')
if [ ! "$a" == "0" ]
then
	aa-enforce /etc/apparmor.d/* 
fi


echo -e "\e[1;31m Ensure local login warning banner is configured properly \e[0m"
cat /etc/issue
egrep '(\\v|\\r|\\m|\\s)' /etc/issue
if [ $? -eq 0 ]
then
	sed -i 's/\\r//g;s/\\s//g;s/\\v//g;s/\\m//g' /etc/issue
fi
echo "Authorized uses only. All activity may be monitored and reported." >> /etc/issue

echo -e "\e[1;31m Ensure local login warning banner is configured properly \e[0m"
cat /etc/issue.net
egrep '(\\v|\\r|\\m|\\s)' /etc/issue.net
if [ $? -eq 0 ]
then
	sed -i 's/\\r//g;s/\\s//g;s/\\v//g;s/\\m//g' /etc/issue
fi
echo "Authorized uses only. All activity may be monitored and reported." >> /etc/issue.net

echo -e "\e[1;31m Ensure permissions on /etc/issue are configured \e[0m"
chown root:root /etc/issue
chmod 644 /etc/issue

echo -e "\e[1;31m Ensure permissions on /etc/issue.net are configured \e[0m"
chown root:root /etc/issue.net
chmod 644 /etc/issue.net





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





#!/bin/bash
apt-get update
echo -e "\e[1;31m Ensure iptables is installed \e[0m"
dpkg -s iptables
if [ $? -ne 0 ]
then
  apt-get install iptables
fi

echo -e "\e[1;31m Ensure default deny firewall policy \e[0m"
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP

echo -e "\e[1;31m Ensure loopback traffic is configured \e[0m"
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT -s 127.0.0.0/8 -j DROP

echo  -e "\e[1;31m Ensure outbound and established connections are configured \e[0m"
iptables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
iptables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
iptables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT

echo -e "\e[1;31m Ensure firewall rules exist for all open ports \e[0m"
netstat -tulnp | awk 'FNR > 2 {print $4}' | cut -d ':' -f 2  > ports
sed -i '/^$/d' ports
while read p; do
        iptables -L -v -n | grep $p
        if [ $? -ne 0 ]
        then
                iptables -A INPUT -p tcp --dport $p -m state --state NEW -jACCEPT
        fi
done <ports

echo -e "\e[1;31m Ensure Auditd service is installed and enabled \e[0m"
echo -e "y" | apt-get install auditd
a=$(systemctl is-enabled auditd)
if [[ ! "$a" -eq "enabled" ]]
then
  systemctl enable auditd
fi

echo -e "\e[1;31m Ensure audit log storage size is configured \e[0m"
sed -i '/max_log_file = 8/d' /etc/audit/auditd.conf 
echo "max_log_file = 20" >> /etc/audit/auditd.conf 

echo -e "\e[1;31m Ensure system is disabled when audit logs are full \e[0m"
sed -i '/pace_left_action =/d' /etc/audit/auditd.conf 
echo "space_left_action = email" >> /etc/audit/auditd.conf
sed -i '/action_mail_acct =/d' /etc/audit/auditd.conf 
echo "action_mail_acct = root" >> /etc/audit/auditd.conf
sed -i '/admin_space_left_action =/d' /etc/audit/auditd.conf 
echo "admin_space_left_action = halt" >> /etc/audit/auditd.conf

echo -e "\e[1;31m Ensure audit logs are not automatically deleted \e[0m"
sed -i '/max_log_file_action =/d' /etc/audit/auditd.conf
echo "max_log_file_action = keep_logs" >> /etc/audit/auditd.conf

echo -e "\e[1;31m Ensure auditing for processes that start prior to auditd is enabled \e[0m"
grep "audit=1" /etc/default/grub
if [ $? -ne 0 ]
then
  echo "GRUB_CMDLINE_LINUX="audit=1"" >>  /etc/default/grub
  update-grub
fi

echo -e "\e[1;31m Ensure events that modify date and time information are collected \e[0m"
grep time-change /etc/audit/audit.rules
if [ $? -ne 0 ]
then
  echo "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change" >> /etc/audit/audit.rules
  echo "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k timechange" >> /etc/audit/audit.rules
  echo "-a always,exit -F arch=b64 -S clock_settime -k time-change" >> /etc/audit/audit.rules
  echo "-a always,exit -F arch=b32 -S clock_settime -k time-change" >> /etc/audit/audit.rules
  echo "-w /etc/localtime -p wa -k time-change" >> /etc/audit/audit.rules
fi

echo -e "\e[1;31m Ensure events that modify user/group information are collected \e[0m"
grep identity /etc/audit/audit.rules
if [ $? -ne 0 ]
then
  echo "-w /etc/group -p wa -k identity" >>  /etc/audit/audit.rules
  echo "-w /etc/passwd -p wa -k identity" >>  /etc/audit/audit.rules
  echo "-w /etc/gshadow -p wa -k identity" >>  /etc/audit/audit.rules
  echo "-w /etc/shadow -p wa -k identity" >>  /etc/audit/audit.rules
  echo "-w /etc/security/opasswd -p wa -k identity"  >> /etc/audit/audit.rules
fi

echo -e "\e[1;31m Ensure events that modify the system network environment are collected \e[0m"
grep system-locale /etc/audit/audit.rules
if [ $? -ne 0 ]
then
  echo "a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale" >> /etc/audit/audit.rules
  echo "-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale" >> /etc/audit/audit.rules
  echo "-w /etc/issue -p wa -k system-locale" >> /etc/audit/audit.rules
  echo "-w /etc/issue.net -p wa -k system-locale" >> /etc/audit/audit.rules
  echo "-w /etc/hosts -p wa -k system-locale" >>  /etc/audit/audit.rules
  echo "-w /etc/network -p wa -k system-locale" >>  /etc/audit/audit.rules
fi

echo -e "\e[1;31m Ensure events that modify the system Mandatory Access Controls are collected \e[0m"
grep MAC-policy /etc/audit/audit.rules
if [ $? -ne 0 ]
then
  echo "-w /etc/apparmor/ -p wa -k MAC-policy" >>  /etc/audit/audit.rules
  echo "-w /etc/apparmor.d/ -p wa -k MAC-policy" >>  /etc/audit/audit.rules
fi

echo -e "\e[1;31m Ensure login and logout events are collected \e[0m"
grep logins /etc/audit/audit.rules
if [ $? -ne 0 ]
then
  echo "-w /var/log/faillog -p wa -k logins" >>  /etc/audit/audit.rules
  echo "-w /var/log/lastlog -p wa -k logins" >>  /etc/audit/audit.rules
  echo "-w /var/log/tallylog -p wa -k logins" >>  /etc/audit/audit.rules
fi

echo -e "\e[1;31m Ensure session initiation information is collected \e[0m"
grep session /etc/audit/audit.rules
if [ $? -ne 0 ]
then
  echo "-w /var/run/utmp -p wa -k session" >>  /etc/audit/audit.rules
fi

grep logins /etc/audit/audit.rules
if [ $? -ne 0 ]
then
  echo "-w /var/log/wtmp -p wa -k logins" >>  /etc/audit/audit.rules
  echo "-w /var/log/btmp -p wa -k logins" >>  /etc/audit/audit.rules
fi

echo -e "\e[1;31m Ensure discretionary access control permission modification events are collected \e[0m"
grep perm_mod /etc/audit/audit.rules
if [ $? -ne 0 ]
then
  echo "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" >>  /etc/audit/audit.rules
  echo "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" >>  /etc/audit/audit.rules
  echo "-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" >>  /etc/audit/audit.rules
  echo "-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" >>  /etc/audit/audit.rules
  echo "-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >>  /etc/audit/audit.rules
  echo "-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >>  /etc/audit/audit.rules
fi
 
echo -e "\e[1;31m Ensure unsuccessful unauthorized file access attempts are collected \e[0m"
grep access /etc/audit/audit.rules
if [ $? -ne 0 ]
then
  echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >>  /etc/audit/audit.rules
  echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >>  /etc/audit/audit.rules
  echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >>  /etc/audit/audit.rules
  echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >>  /etc/audit/audit.rules
fi

echo -e "\e[1;31m Ensure successful file system mounts are collected \e[0m"
grep mounts /etc/audit/audit.rules
if [ $? -ne 0 ]
then
  echo "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >>  /etc/audit/audit.rules
  echo "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >>  /etc/audit/audit.rules
fi

echo -e "\e[1;31m Ensure file deletion events by users are collected \e[0m"
grep delete /etc/audit/audit.rules
if [ $? -ne 0 ]
then
  echo "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >>  /etc/audit/audit.rules
  echo "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >>  /etc/audit/audit.rules
fi

echo -e "\e[1;31m Ensure changes to system administration scope (sudoers) is collected \e[0m"
grep scope /etc/audit/audit.rules
if [ $? -ne 0 ]
then
  echo "-w /etc/sudoers -p wa -k scope" >>  /etc/audit/audit.rules
  echo "-w /etc/sudoers.d/ -p wa -k scope" >>  /etc/audit/audit.rules
fi

echo -e "\e[1;31m Ensure system administrator actions (sudolog) are collected \e[0m"
grep actions /etc/audit/audit.rules
if [ $? -ne 0 ]
then
  echo "-w /var/log/sudo.log -p wa -k actions" >>  /etc/audit/audit.rules
fi

echo -e "\e[1;31m Ensure kernel module loading and unloading is collected \e[0m"
grep modules /etc/audit/audit.rules
if [ $? -ne 0 ]
then
  echo "w /sbin/insmod -p x -k modules" >>  /etc/audit/audit.rules
  echo "-w /sbin/rmmod -p x -k modules" >>  /etc/audit/audit.rules
  echo "-w /sbin/modprobe -p x -k modules" >>  /etc/audit/audit.rules
  echo "-a always,exit -F arch=b64 -S init_module -S delete_module -k modules" >>  /etc/audit/audit.rules
fi

echo -e "\e[1;31m Ensure the audit configuration is immutable \e[0m" 
grep "-e 2"  /etc/audit/audit.rules
if [ $? -ne 0 ]
then
  echo "-e 2" >> /etc/audit/audit.rules
fi
echo -e "\e[1;31m Reloading Auditd service \e[0m"
systemctl reload auditd

echo -e "\e[1;31m ENsure rsyslog and syslog-ng is installed \e[0m"
dpkg -s rsyslog
if [ $? -ne 0 ]
then
  echo -e "y" | apt-get install rsyslog
fi

dpkg -s syslog-ng
if [ $? -ne 0 ]
then
  echo -e "y" | apt-get install syslog-ng syslog-ng-core
fi

echo -e "\e[1;31m Ensure rsyslog Service is enabled  \e[0m"
a=$(systemctl is-enabled rsyslog)
if [[ ! "$a" == "enabled" ]]
then
  systemctl enable rsyslog
fi

echo -e "\e[1;31m Ensure rsyslog default file permissions configured \e[0m"
grep ^\$FileCreateMode /etc/rsyslog.conf /etc/rsyslog.d/*.conf | grep 0640
if [ $? -ne 0 ]
then 
  sed -i '/$FileCreateMode/d' /etc/rsyslog.conf 
  echo "$FileCreateMode 0640" >> /etc/rsyslog.conf
fi

echo -e "\e[1;31m Ensure rsyslog is configured to send logs to a remote log host \e[0m"
grep "^*.*[^I][^I]*@" /etc/rsyslog.conf /etc/rsyslog.d/*.conf
if [ $? -ne 0 ]
then
  # THis is s demo server in actual we will replace this will with real domain
  echo "*.* @@loghost.example.com" >> /etc/rsyslog.conf /etc/rsyslog.d/*.conf
  pkill -HUP rsyslogd
fi

echo -e "\e[1;31m Ensure syslog-ng service is enabled \e[0m"
a=$(systemctl is-enabled syslog-ng)
if [[ ! "$a" == "enabled" ]]
then
  update-rc.d syslog-ng enable
fi

echo -e "\e[1;31m Ensure syslog-ng default file permissions configured \e[0m"
grep ^options /etc/syslog-ng/syslog-ng.conf | grep 0640
if [ $? -ne 0 ]
then
  sed -i '/options/d' /etc/syslog-ng/syslog-ng.conf
  echo "options { chain_hostnames(off); flush_lines(0); perm(0640); stats_freq(3600); threaded(yes); };" >>  /etc/syslog-ng/syslog-ng.conf
fi

echo -e "\e[1;31m Ensure permissions on all logfiles are configured \e[0m"
chmod -R g-wx,o-rwx /var/log/*

echo -e "\e[1;31m Ensure cron daemon is enabled \e[0m"
a=$(systemctl is-enabled cron)
if [[ ! "$a" == "enabled" ]]
then
  systemctl enable cron
fi

echo -e "\e[1;31m Ensure permissions on /etc/crontab are configured \e[0m"
chown root:root /etc/crontab
chmod og-rwx /etc/crontab
  
echo -e "\e[1;31m Ensure permissions on /etc/cron.hourly are configured \e[0m"
chown root:root /etc/cron.hourly
chmod og-rwx /etc/cron.hourly

echo -e "\e[1;31m Ensure permissions on /etc/cron.daily are configured \e[0m"
chown root:root /etc/cron.daily
chmod og-rwx /etc/cron.daily
  
echo -e "\e[1;31m Ensure permissions on /etc/cron.weekly are configured \e[0m"
chown root:root /etc/cron.weekly
chmod og-rwx /etc/cron.weekly

echo -e "\e[1;31m Ensure permissions on /etc/cron.monthly are configured \e[0m"
chown root:root /etc/cron.monthly
chmod og-rwx /etc/cron.monthly

echo -e "\e[1;31m Ensure permissions on /etc/cron.d are configured \e[0m"
chown root:root /etc/cron.d
chmod og-rwx /etc/cron.d

echo -e "\e[1;31m Ensure at/cron is restricted to authorized users  \e[0m"
stat /etc/cron.deny
if [ $? -eq 0 ]
then
  rm /etc/cron.deny
  rm /etc/at.deny
fi

stat /etc/cron.allow
if [ $? -ne 0 ]
then
  echo "creating cron allow file"
  touch /etc/cron.allow
  touch /etc/at.allow
  chmod og-rwx /etc/cron.allow
  chmod og-rwx /etc/at.allow
  chown root:root /etc/cron.allow 
  chown root:root /etc/at.allow
fi



echo -e "\e[1;31m Ensure sshd daemon is intalled \e[0m"
dpkg -s openssh-server
if [ $? -ne 0 ]
then
  echo -e "y" | openssh-server
fi

echo -e "\e[1;31m Ensure permissions on /etc/ssh/sshd_config are configured \e[0m"
chown root:root /etc/ssh/sshd_config
chmod og-rwx /etc/ssh/sshd_config

echo -e "\e[1;31m Ensure SSH Protocol is set to 2 \e[0m"
a=$(grep "^Protocol" /etc/ssh/sshd_config | awk '{ print $2 }')
if [[ ! "$a" == "2" || -z "$a" ]]
then
        sed -i '/Protocol/d' /etc/ssh/sshd_config 
        echo "Protocol 2" >> /etc/ssh/sshd_config
fi

echo -e "\e[1;31m Ensure SSH LogLevel is set to INFO \e[0m"
a=$(grep "^LogLevel" /etc/ssh/sshd_config | awk '{ print $2 }')
if [[ ! "$a" == "INFO" || -z "$a" ]]
then
        sed -i '/LogLevel/d' /etc/ssh/sshd_config 
        echo "LogLevel INFO" >> /etc/ssh/sshd_config
fi


echo -e "\e[1;31m Ensure SSH X11 forwarding is disabled \e[0m"
a=$(grep "^X11Forwarding" /etc/ssh/sshd_config | awk '{ print $2 }')
if [[ ! "$a" == "no" || -z "$a" ]]
then
        sed -i '/X11Forwarding/d' /etc/ssh/sshd_config 
        echo "X11Forwarding no" >> /etc/ssh/sshd_config
fi

echo -e "\e[1;31m Ensure SSH MaxAuthTries is set to 4 or less \e[0m"
a=$(grep "^MaxAuthTries" /etc/ssh/sshd_config | awk '{ print $2 }')
if [[ ! "$a" == "4" || -z "$a" ]]
then
        sed -i '/MaxAuthTries/d' /etc/ssh/sshd_config 
        echo "MaxAuthTries 4" >> /etc/ssh/sshd_config
fi

echo -e "\e[1;31m Ensure SSH IgnoreRhosts is enabled \e[0m"
a=$(grep "^IgnoreRhosts" /etc/ssh/sshd_config | awk '{ print $2 }')
if [[ ! "$a" == "yes" || -z "$a" ]]
then
        sed -i '/IgnoreRhosts/d' /etc/ssh/sshd_config 
        echo "IgnoreRhosts yes" >> /etc/ssh/sshd_config
fi

echo -e "\e[1;31m Ensure SSH HostbasedAuthentication is disabled \e[0m"
a=$(grep "^HostbasedAuthentication" /etc/ssh/sshd_config | awk '{ print $2 }')
if [[ ! "$a" == "no" || -z "$a" ]]
then
        sed -i '/HostbasedAuthentication/d' /etc/ssh/sshd_config 
        echo "HostbasedAuthentication no" >> /etc/ssh/sshd_config
fi

echo -e "\e[1;31m Ensure SSH root login is disabled \e[0m"
a=$(grep "^PermitRootLogin" /etc/ssh/sshd_config | awk '{ print $2 }')
if [[ ! "$a" == "no" || -z "$a" ]]
then
        sed -i '/PermitRootLogin/d' /etc/ssh/sshd_config 
        echo "PermitRootLogin no" >> /etc/ssh/sshd_config
fi

echo -e "\e[1;31m Ensure SSH PermitEmptyPasswords is disabled  \e[0m"
a=$(grep "^PermitEmptyPasswords" /etc/ssh/sshd_config | awk '{ print $2 }')
if [[ ! "$a" == "no" || -z "$a" ]]
then
        sed -i '/PermitEmptyPasswords/d' /etc/ssh/sshd_config 
        echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config
fi

echo -e "\e[1;31m Ensure SSH PermitUserEnvironment is disabled \e[0m"
a=$(grep "^PermitUserEnvironment" /etc/ssh/sshd_config | awk '{ print $2 }')
if [[ ! "$a" == "no" || -z "$a" ]]
then
        sed -i '/PermitUserEnvironment/d' /etc/ssh/sshd_config 
        echo "PermitUserEnvironment no" >> /etc/ssh/sshd_config
fi

echo -e "\e[1;31m Ensure only approved MAC algorithms are used \e[0m"
sed -i '/MACs/d'  /etc/ssh/sshd_config
echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com" >> /etc/ssh/sshd_config

echo -e "\e[1;31m Ensure SSH Idle Timeout Interval is configured \e[0m"
a=$(grep "^ClientAliveInterval" /etc/ssh/sshd_config | awk '{ print $2 }')
if [[ $a -gt 300 || -z "$a" ]]
then
        sed -i '/ClientAliveInterval/d' /etc/ssh/sshd_config 
        echo "ClientAliveInterval 300" >> /etc/ssh/sshd_config
fi

a=$(grep "^ClientAliveCountMax" /etc/ssh/sshd_config | awk '{ print $2 }')
if [[ $a -gt 3  || -z "$a" ]]
then
        sed -i '/ClientAliveCountMax/d' /etc/ssh/sshd_config 
        echo "ClientAliveCountMax 0" >> /etc/ssh/sshd_config
fi

echo -e "\e[1;31m Ensure SSH LoginGraceTime is set to one minute or less \e[0m"
a=$(grep "^LoginGraceTime" /etc/ssh/sshd_config | awk '{ print $2 }')
if [[ $a -gt 60 || -z "$a" ]]
then
        sed -i '/LoginGraceTime/d' /etc/ssh/sshd_config 
        echo "LoginGraceTime 60" >> /etc/ssh/sshd_config
fi

echo -e "\e[1;31m Ensure SSH access is limited \e[0m"
grep "^AllowUsers" /etc/ssh/sshd_config
a=$?
grep "^AllowGroups" /etc/ssh/sshd_config
b=$?
grep "^DenyUsers" /etc/ssh/sshd_config
c=$?
grep "^DenyGroups" /etc/ssh/sshd_config
d=$?
if [[ $a -eq 1 && $b -eq 1 && $c -eq 1 && $d -eq 1 ]]
then
        echo "AllowUsers ubuntu" >> /etc/ssh/sshd_config
        echo "AllowGroups ubuntu" >> /etc/ssh/sshd_config
fi

echo -e "\e[1;31m Ensure SSH warning banner is configured  \e[0m"
grep "^Banner" /etc/ssh/sshd_config
if [ $? -ne 0 ]
then
  echo "Banner /etc/issue.net" >>  /etc/ssh/sshd_config
fi

echo -e "\e[1;31m Reloading SSHD service  \e[0m"
systemctl reload sshd

echo -e "\e[1;31m Ensure password creation requirements are configured \e[0m"
echo -e "y" | apt-get install libpam-pwquality
sed -i '/pam_pwquality.so/d' /etc/pam.d/common-password
echo "password requisite pam_pwquality.so retry=3" >> /etc/pam.d/common-password
sed -i '/minlen =/d' /etc/security/pwquality.conf
sed -i '/dcredit =/d' /etc/security/pwquality.conf
sed -i '/ucredit =/d' /etc/security/pwquality.conf
sed -i '/ocredit =/d' /etc/security/pwquality.conf
sed -i '/lcredit =/d' /etc/security/pwquality.conf
echo "minlen = 14" >> /etc/security/pwquality.conf
echo "dcredit = -1" >> /etc/security/pwquality.conf
echo "ucredit = -1" >> /etc/security/pwquality.conf
echo "lcredit = -1" >> /etc/security/pwquality.conf
echo "ocredit = -1" >>  /etc/security/pwquality.conf

echo -e "\e[1;31m Ensure lockout for failed password attempts is configured \e[0m"
a=$(grep "pam_tally2" /etc/pam.d/common-auth | cut -c58)
if [ "$a" != "5" ]
then
        sed -i '/pam_tally2/d' /etc/pam.d/common-auth 
        echo "auth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900" >> /etc/pam.d/common-auth
fi

echo -e "\e[1;31m Ensure password reuse is limited  \e[0m"
a=$(egrep '^password\s+required\s+pam_pwhistory.so' /etc/pam.d/common-password | cut -c45)
if [ "$a" != "5" ]
then
        sed -i '/password\s+required\s+pam_pwhistory.so/d' /etc/pam.d/common-auth 
        echo "password required pam_pwhistory.so remember=5" >> /etc/pam.d/common-auth
fi

echo -e "\e[1;31m Ensure password hashing algorithm is SHA-512 \e[0m"
egrep '^password\s+(\S+\s+)+pam_unix\.so\s+(\S+\s+)*sha512' /etc/pam.d/common-password 
if [ $? -ne 0 ]
then
  echo "password [success=1 default=ignore] pam_unix.so sha512" >> /etc/pam.d/common-password 
fi
 
echo -e "\e[1;31m Ensure password expiration is 365 days or less \e[0m"
sed -i '/PASS_MAX_DAYS/d' /etc/login.defs
echo "PASS_MAX_DAYS 90" >> /etc/login.defs

for user in $(cat /etc/passwd | cut -d: -f1)
do
         chage --maxdays 90 $user
done

echo -e "\e[1;31m Ensure minimum days between password changes is 7 or more \e[0m"
sed -i '/PASS_MIN_DAYS/d' /etc/login.defs
echo "PASS_MIN_DAYS  7" >> /etc/login.defs 
for user in $(cat /etc/passwd | cut -d: -f1)
do
         chage --mindays 7 $user
done

echo -e "\e[1;31m Ensure password expiration warning days is 7 or more \e[0m"
sed -i '/PASS_WARN_AGE/d' /etc/login.defs
echo "PASS_WARN_AGE 7" >> /etc/login.defs 
for user in $(cat /etc/passwd | cut -d: -f1)
do
         chage --warndays  7 $user
done

echo -e "\e[1;31m Ensure inactive password lock is 30 days or less  \e[0m"
a=$(useradd -D | grep INACTIVE | cut -d= -f2)
if [[ $a -gt 30 || $a -eq -1 ]]
then
  useradd -D -f 30
fi

for user in $(cat /etc/passwd | cut -d: -f1)
do
          chage --inactive 30 $user
done

echo -e "\e[1;31m Ensure system accounts are non-login \e[0m"
for user in `awk -F: '($3 < 1000) {print $1 }' /etc/passwd`; do
 if [ $user != "root" ]; then
 usermod -L $user
  if [ $user != "sync" ] && [ $user != "shutdown" ] && [ $user != "halt" ];
  then
    usermod -s /usr/sbin/nologin $user
  fi
 fi
done


echo -e "\e[1;31m Ensure default group for the root account is GID 0 \e[0m"
a=$(grep "^root:" /etc/passwd | cut -f4 -d:)
if [ $a -ne 0 ]
then
  usermod -g 0 root
fi

echo -e "\e[1;31m Ensure default user umask is 027 or more restrictive \e[0m"
sed -i '/umask/d'  /etc/bash.bashrc /etc/profile /etc/profile.d/*.sh 
echo "umask 027" >> /etc/bash.bashrc /etc/profile /etc/profile.d/*.sh

echo -e "\e[1;31m Ensure default user shell timeout is 900 seconds or less \e[0m"
grep "^TMOUT" /etc/bash.bashrc
if [ $? -ne 0 ]
then
  echo "TMOUT=600" >> /etc/bash.bashrc
fi

grep "^TMOUT" /etc/profile /etc/profile.d/*.sh
if [ $? -ne 0 ]
then
  echo "TMOUT=600" >> /etc/profile /etc/profile.d/*.sh
fi

echo -e "\e[1;31m Ensure access to the su command is restricted \e[0m"
echo "auth required pam_wheel.so" >> /etc/pam.d/su
echo "sudo:x:10:root,ubuntu" >> /etc/group

echo -e "\e[1;31m Ensure permissions on /etc/passwd are configured \e[0m"
chown root:root /etc/passwd
chmod 644 /etc/passwd

echo -e "\e[1;31m Ensure permissions on /etc/shadow are configured \e[0m"
chown root:shadow /etc/shadow
chmod o-rwx,g-wx /etc/shadow

echo -e "\e[1;31m Ensure permissions on /etc/group are configured \e[0m"
chown root:root /etc/group
chmod 644 /etc/group

echo -e "\e[1;31m Ensure permissions on /etc/gshadow are configured \e[0m"
chown root:shadow /etc/gshadow
chmod o-rwx,g-rw /etc/gshadow

echo -e "\e[1;31m Ensure permissions on /etc/passwd- are configured \e[0m"
chown root:root /etc/passwd-
chmod u-x,go-wx /etc/passwd

echo -e "\e[1;31m Ensure permissions on /etc/shadow- are configured \e[0m"
chown root:shadow /etc/shadow-
chmod o-rwx,g-rw /etc/shadow-

echo -e "\e[1;31m Ensure permissions on /etc/group- are configured \e[0m"
chown root:root /etc/group-
chmod u-x,go-wx /etc/group

echo -e "\e[1;31m Ensure permissions on /etc/gshadow- are configured \e[0m"
chown root:shadow /etc/gshadow-
chmod o-rwx,g-rw /etc/gshadow-

echo -e "\e[1;31m Ensure no world writable files exist \e[0m"
for file in $(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -0002) 
do
  chmod o-w $file
done

echo -e "\e[1;31m Ensure no unowned files or directories exist \e[0m" 
for file in $(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser) 
do
  chown root:root $file
done

echo -e "\e[1;31m Ensure no ungrouped files or directories exist \e[0m"
for file in $(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nogroup)
do
  chown root:root $file
done

echo -e "\e[1;31m Ensure password fields are not empty \e[0m"
for user in $(cat /etc/shadow | awk -F: '($2 == "!" ) { print $1 }')
do
  passwd -l $user
done

echo -e "\e[1;31m Ensure no legacy "+" entries exist in /etc/passwd \e[0m"
grep '^\+:' /etc/passwd
if [ $? -eq 0 ]
then
  userdel '+'
fi

echo -e "\e[1;31m Ensure no legacy "+" entries exist in /etc/shadow \e[0m"
grep '^\+:' /etc/shadow
if [ $? -eq 0 ]
then
  userdel '+'
fi

echo -e "\e[1;31m Ensure no legacy "+" entries exist in /etc/group \e[0m"
grep '^\+:' /etc/group
if [ $? -eq 0 ]
then
  userdel '+'
fi

echo -e "\e[1;31m Ensure root is the only UID 0 account \e[0m"
for name in $(cat /etc/passwd | awk -F: '($3 == 0) { print $1 }')
do
  if [[ "$name" != "root" ]]
  then
    userdel $name
  fi
done

echo -e "\e[1;31m Ensure all users home directories exist \e[0m"
cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 != "/usr/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do 
if [ ! -d "$dir" ]; then mkdir $dir
chown $user:$user $dir
usermod -d $user
fi
done

echo -e "\e[1;31m Ensure users home directories permissions are 750 or more restrictive \e[0m"
for dir in $(cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 != "/usr/sbin/nologin" && $7 != "/bin/false") { print $6 }')
do
        dirperm=`ls -ld $dir | cut -f1 -d" "`
        if [ `echo $dirperm | cut -c6` != "-" ]
        then
                chmod g-w $dir
        fi
        if [ `echo $dirperm | cut -c8` != "-" ]
        then
                chmod o-r $dir
        fi
        if [ `echo $dirperm | cut -c9` != "-" ]
        then
                chmod o-w $dir
        fi
        if [ `echo $dirperm | cut -c10` != "-" ]
        then
                chmod o-x $dir
        fi
done

echo -e "\e[1;31m Ensure users own their home directories \e[0m"
cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 != "/usr/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do
if [ ! -d "$dir" ]; then echo "The home directory ($dir) of user $user does not exist."
else
        owner=$(stat -L -c "%U" "$dir")
        if [ "$owner" != "$user" ]
        then
                chown $user $dir
        fi
fi
done

echo -e "\e[1;31m Ensure users dot files are not group or world writable \e[0m"
cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do
if [ ! -d "$dir" ]; then echo "The home directory ($dir) of user $user does not exist."
else
        for file in $dir/.[A-Za-z0-9]*
        do
                if [ ! -h "$file" -a -f "$file" ]
                then
                        fileperm=`ls -ld $dir/$file | cut -f1 -d" "`
                        if [ "$(echo $fileperm | cut -c6)" != "-" ]
                        then
                                chmod g-w $file
                        fi
                        if [ "$(echo $fileperm | cut -c9)" != "-" ]
                        then
                                chmod o-w $file
                        fi
                fi
        done
fi
done    


echo -e "\e[1;31m Ensure no users have .forward files \e[0m"
cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do
if [ ! -d "$dir" ]; then echo "The home directory ($dir) of user $user does not exist."
else
        if [ ! -h "$dir/.forward" -a -f "$dir/.forward" ]; then
                rm $dir/.forward
        fi
fi
done

echo -e "\e[1;31m Ensure no users have .netrc files  \e[0m"
cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do
if [ ! -d "$dir" ]; then echo "The home directory ($dir) of user $user does not exist."
else
        if [ ! -h "$dir/.netrc" -a -f "$dir/.netrc" ]; then
                rm $dir/.netrc
        fi
fi
done

echo -e "\e[1;31m Ensure users .netrc Files are not group or world accessible \e[0m" 
cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do
if [ ! -d "$dir" ]; then echo "The home directory ($dir) of user $user does not exist."
else
        for file in $dir/.netrc; do
                if [ ! -h "$file" -a -f "$file" ]; then
                        fileperm=`ls -ld $file | cut -f1 -d" "`
                        if [ `echo $fileperm | cut -c5` != "-" ]; then
                                chmod g-w $file
                        fi
                        if [ `echo $fileperm | cut -c6` != "-" ]; then
                                chmod g-r $file
                        fi
                        if [ `echo $fileperm | cut -c7` != "-" ]; then
                                chmod g-x $file
                        fi
                        if [ `echo $fileperm | cut -c8` != "-" ]; then
                                chmod o-r $file
                        fi
                        if [ `echo $fileperm | cut -c9` != "-" ]; then
                                chmod o-w $file
                        fi
                        if [ `echo $fileperm | cut -c10` != "-" ]; then
                                chmod o-x $file
                        fi
                fi
        done
fi
done 

echo -e "\e[1;31m Ensure no users have .rhosts files  \e[0m"
cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do
if [ ! -d "$dir" ]; then echo "The home directory ($dir) of user $user does not exist."
else
        for file in $dir/.rhosts; do
          if [ ! -h "$file" -a -f "$file" ]; then
            rm $dir/.rhosts
          fi
        done
fi
done

echo -e "\e[1;31m Ensure all groups in /etc/passwd exist in /etc/group \e[0m"
for i in $(cut -s -d: -f4 /etc/passwd | sort -u ) 
do
 grep -q -P "^.*?:[^:]*:$i:" /etc/group
 if [ $? -ne 0 ]; then
         groupadd $(cat /etc/passwd | awk  -F: '($4 == $i) { print $1 }')
 fi
done

echo -e "\e[1;31m Ensure no duplicate UIDs exist \e[0m"
cat /etc/passwd | cut -f3 -d":" | sort -n | uniq -c | while read x ; do
[ -z "${x}" ] && break
set - $x
if [ $1 -gt 1 ]; then
users=`awk -F: '($3 == n) { print $1 }' n=$2 /etc/passwd | xargs`
userdel $(echo $users | awk '{ print $2 }')
fi
done

echo -e "\e[1;31m Ensure no duplicate GIDs exist \e[0m"
cat /etc/group | cut -f3 -d":" | sort -n | uniq -c | while read x ; do
 [ -z "${x}" ] && break
 set - $x
 if [ $1 -gt 1 ]; then
 groups=`awk -F: '($3 == n) { print $1 }' n=$2 /etc/group | xargs`
 groupdel $( echo $groups | awk '{ print $2 }')
 fi
done

echo -e "\e[1;31m Ensure shadow group is empty \e[0m"
shadow_gid=$(grep ^shadow /etc/group | awk -F: '{ print $3 }')
user=$(awk -F: '($4 == "42") { print $1 }' /etc/passwd)
if [[ ! -z $user ]]
then
  deluser  $user shadow
fi
# END OF SCRIPT 



