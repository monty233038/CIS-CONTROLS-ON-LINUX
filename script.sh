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

pvcreate /var/xvdf
vgcreate vol /var/xvdf

mount | grep /tmp
if [ $? -eq 0 ]
then
	umount /tmp
	rm -rf /tmp
	mkdir /tmp
	chmod 777 /tmp
	lvcreate -L 500 -n tmp vol
	mkfs.ext4 /dev/vol/tmp
	echo "/dev/vol/tmp	/tmp	ext4	rw,nosuid,nodev,noexec,relatime		1	2" >> /etc/fstab
	mount -a
else

	rm -rf /tmp
	mkdir /tmp
	chmod 777 /tmp
	lvcreate -L 500 -n tmp vol
	mkfs.ext4 /dev/vol/tmp
	echo "/dev/vol/tmp	/tmp	ext4	rw,nosuid,nodev,noexec,relatime		1	2" >> /etc/fstab
	mount -a
fi

mount | grep /tmp | grep nodev
if [ $? -ne 0 ]
then
	awk'$1~"/dev/vol/tmp"{$4="nodev,"$4}'1 OFS="\t" /etc/fstab
	mount -o remount,nodev /tmp
fi


mount | grep /tmp | grep nosuid
if [ $? -ne 0 ]
then
	awk'$1~"/dev/vol/tmp"{$4="nosuid,"$4}'1 OFS="\t" /etc/fstab
	mount -o remount,nosuid /tmp
fi



#mount | grep /var
#if [ $? -eq 0 ]
#then
#	umount /var
#	rm -rf /var
#	mkdir /var
#	chmod 777 /var
#	lvcreate -L 500 -n var vol
#	mkfs.ext4 /dev/vol/var
#	echo "/dev/vol/var	/var	ext4	rw,relatime,data=ordered		1	2" >> /etc/fstab
#	mount -a
#else
#
#	rm -rf /var
#	mkdir /var
#	chmod 777 /var
#	lvcreate -L 500 -n var vol
#	mkfs.ext4 /dev/vol/var
#	echo "/dev/vol/var	/var	ext4	rw,relatime,data=ordered		1	2" >> /etc/fstab
#	mount -a
#fi



mount | grep /var/tmp
if [ $? -eq 0 ]
then
	umount /var/tmp
	rm -rf /var/tmp
	mkdir /var/tmp
	chmod 777 /var/tmp
	lvcreate -L 500 -n var-tmp vol
	mkfs.ext4 /dev/vol/var-tmp
	echo "/dev/vol/var-tmp	/var/tmp	ext4	rw,nosuid,nodev,noexec,relatime		1	2" >> /etc/fstab
	mount -a
else

	rm -rf /var/tmp
	mkdir /var/tmp
	chmod 777 /var/tmp
	lvcreate -L 500 -n var-tmp vol
	mkfs.ext4 /dev/vol/var-tmp
	echo "/dev/vol/var-tmp	/var/tmp	ext4	rw,nosuid,nodev,noexec,relatime		1	2" >> /etc/fstab
	mount -a
fi



mount | grep /var/tmp | grep nodev
if [ $? -ne 0 ]
then
	awk'$1~"/dev/vol/var-tmp"{$4="nodev,"$4}'1 OFS="\t" /etc/fstab
	mount -o remount,nodev /var/tmp
fi


mount | grep /var/tmp | grep nosuid
if [ $? -ne 0 ]
then
	awk'$1~"/dev/vol/var-tmp"{$4="nosuid,"$4}'1 OFS="\t" /etc/fstab
	mount -o remount,nosuid /var/tmp
fi



mount | grep /var/tmp | grep noexec
if [ $? -ne 0 ]
then
	awk'$1~"/dev/vol/var-tmp"{$4="noexec,"$4}'1 OFS="\t" /etc/fstab
	mount -o remount,noexec /var/tmp
fi



mount | grep /var/log
if [ $? -eq 0 ]
then
	umount /var/log
	rm -rf /var/log
	mkdir /var/log
	chmod 777 /var/log
	lvcreate -L 500 -n var-log vol
	mkfs.ext4 /dev/vol/var-log
	echo "/dev/vol/var-log	/var/log	ext4	rw,relatime,data=ordered		1	2" >> /etc/fstab
	mount -a
else

	rm -rf /var/log
	mkdir /var/log
	chmod 777 /var/log
	lvcreate -L 500 -n var-log vol
	mkfs.ext4 /dev/vol/var-log
	echo "/dev/vol/var-log	/var/log	ext4	rw,relatime,data=ordered		1	2" >> /etc/fstab
	mount -a
fi




mount | grep /var/log/audit
if [ $? -eq 0 ]
then
	umount /var/log/audit
	rm -rf /var/log/audit
	mkdir /var/log/audit
	chmod 777 /var/log/audit
	lvcreate -L 500 -n var-log-audit  vol
	mkfs.ext4 /dev/vol/var-log-audit
	echo "/dev/vol/var-log-audit	/var/log/audit		ext4	rw,relatime,data=ordered	1	2" >> /etc/fstab
	mount -a
else

	rm -rf /var/log/audit
	mkdir /var/log/audit
	chmod 777 /var/log/audit
	lvcreate -L 500 -n var-log-audit vol
	mkfs.ext4 /dev/vol/var-log-audit
	echo "/dev/vol/var-log-audit	/var/log/audit		ext4	rw,relatime,data=ordered	1	2" >> /etc/fstab
	mount -a
fi




mount | grep /home
if [ $? -eq 0 ]
then
	umount /home
	rm -rf /home
	mkdir /home
	chmod 777 /home
	lvcreate -L 500 -n home  vol
	mkfs.ext4 /dev/vol/home
	echo "/dev/vol/home	/home		ext4	rw,nodev,relatime,data=ordered	1	2" >> /etc/fstab
	mount -a
else

	rm -rf /home
	mkdir /home
	chmod 777 /home
	lvcreate -L 500 -n home vol
	mkfs.ext4 /dev/vol/home
	echo "/dev/vol/home	/home		ext4	rw,nodev,relatime,data=ordered	1	2" >> /etc/fstab
	mount -a
fi



mount | grep /home | grep nodev
if [ $? -ne 0 ]
then
	awk'$1~"/dev/vol/home"{$4="nodev,"$4}'1 OFS="\t" /etc/fstab
	mount -o remount,nodev /home
fi


mount | grep /dev/shm | grep nodev
if [ $? -ne 0 ]
then
	mount -o remount,nodev /dev/shm
fi


mount | grep /dev/shm | grep nosuid
if [ $? -ne 0 ]
then
	mount -o remount,nosuid /dev/shm
fi


mount | grep /dev/shm | grep noexec
if [ $? -ne 0 ]
then
	mount -o remount,noexec /dev/shm
fi


df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t


ser_stat=$(systemctl is-enabled autofs)
if [ $ser_stat == "enabled" ]
then
	systemctl disbale autofs
fi

dpkg -s aide
if [ $? -ne 0 ]
then
	apt-get install aide aide-common
	aideinit
fi


crontab -l | { cat; echo "0 5 * * * /usr/bin/aide.wrapper --config /etc/aide/aide.conf"; } | crontab


chown root:root /boot/grub/grub.cfg
chmod og-rwx /boot/grub/grub.cfg

#grep "^set superusers" /boot/grub/grub.cfg
#if [ $? -ne 0 ] 
#then
#	grep "^password" /boot/grub/grub.cfg
#	if [ $? -ne 0 ]
#	then
#		echo -e "password\npassword" | grub-mkpasswd-pbkdf2 > pass1
#		tail -n 1 pass1 > pass2
		sed -i 's/PBKDF2 hash of your password is//g' pass2
#		cat << EOF >> /etc/grub.d/00_header
#set superusers="root"
#password_pbkdf2 root $(cat pass2)
#EOF
#	fi
#fi
#update-grub

grep ^root:[*\!]: /etc/shadow
if [ $? -ne 0 ]
then
	echo -e "password\npassword" | passwd root

fi

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

dpkg -s prelink
if [ $? -eq 0 ]
then
	prelink -ua
	apt-get remove prelink
fi

dpkg -s apparmor

if [ $? -ne 0 ]
then
	echo -e "Y" | apt-get install apparmor apparmor-utils

fi

grep "apparmor=1" /boot/grub/grub.cfg
if [ $? -ne 0 ]
then
	eccho "GRUB_CMDLINE_LINUX="apparmor=1 security=apparmor"" >> /etc/default/grub 
	update-grub
fi


a=$(apparmor_status | grep profiles | grep complain | awk '{print $1;}')
if [ ! "$a" == "0" ]
then
	aa-enforce /etc/apparmor.d/* 
fi

