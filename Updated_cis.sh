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
pvcreate /dev/xvdb
vgcreate vol /dev/xvdb
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
if [ $? -ne 0 ]
then
	apt-get install aide aide-common
	aideinit
fi
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





