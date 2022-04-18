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

echo " creating physical volume and volume group"
pvcreate /dev/xvdf
vgcreate vol /dev/xvdf
sleep 3
echo "physical volume and volume group created successfully"
]
echo "Ensure separate mount point exist for /tmp"
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
sleep 5
echo "separate mount point for /tmp created successfully"

echo "Ensure nodev option set on /tmp partition"
mount | grep /tmp | grep nodev
if [ $? -ne 0 ]
then
	awk'$1~"/dev/vol/tmp"{$4="nodev,"$4}'1 OFS="\t" /etc/fstab
	mount -o remount,nodev /tmp
fi

echo "Ensure nosuid option set on /tmp partition"
mount | grep /tmp | grep nosuid
if [ $? -ne 0 ]
then
	awk'$1~"/dev/vol/tmp"{$4="nosuid,"$4}'1 OFS="\t" /etc/fstab
	mount -o remount,nosuid /tmp
fi


echo "Ensure separate mount point exist for /var"
sleep 5
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



echo "Ensure separate mount point exist for /var/tmp"
sleep 5
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


echo "Ensure nodev option set on /var/tmp partition"
mount | grep /var/tmp | grep nodev
if [ $? -ne 0 ]
then
	awk'$1~"/dev/vol/var-tmp"{$4="nodev,"$4}'1 OFS="\t" /etc/fstab
	mount -o remount,nodev /var/tmp
fi

echo "Ensure nosuid option set on /var/tmp partition"
mount | grep /var/tmp | grep nosuid
if [ $? -ne 0 ]
then
	awk'$1~"/dev/vol/var-tmp"{$4="nosuid,"$4}'1 OFS="\t" /etc/fstab
	mount -o remount,nosuid /var/tmp
fi


echo "Ensure noexec option set on /var/tmp partition"
mount | grep /var/tmp | grep noexec
if [ $? -ne 0 ]
then
	awk'$1~"/dev/vol/var-tmp"{$4="noexec,"$4}'1 OFS="\t" /etc/fstab
	mount -o remount,noexec /var/tmp
fi

echo "Ensure separate mount point exist for /var/log"
sleep 5
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



echo "Ensure separate mount point exist for /var/log/audit"
sleep 5
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



echo "Ensure separate mount point exist for /home"
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


echo "Ensure nodev option set on /home partition"
mount | grep /home | grep nodev
if [ $? -ne 0 ]
then
	awk'$1~"/dev/vol/home"{$4="nodev,"$4}'1 OFS="\t" /etc/fstab
	mount -o remount,nodev /home
fi

echo "Ensure nodev option set on /dev/shm partition"
mount | grep /dev/shm | grep nodev
if [ $? -ne 0 ]
then
	mount -o remount,nodev /dev/shm
fi

echo "Ensure nosuid option set on /dev/shm partition"
mount | grep /dev/shm | grep nosuid
if [ $? -ne 0 ]
then
	mount -o remount,nosuid /dev/shm
fi

echo "Ensure noexec option set on /dev/shm partition"
mount | grep /dev/shm | grep noexec
if [ $? -ne 0 ]
then
	mount -o remount,noexec /dev/shm
fi


echo "Ensure sticky bit is set on all world-writable directories"
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t

echo "Disable Automounting"
ser_stat=$(systemctl is-enabled autofs)
if [ $ser_stat == "enabled" ]
then
	systemctl disbale autofs
fi

echo "Ensure AIDE is installed"
dpkg -s aide
if [ $? -ne 0 ]
then
	apt-get install aide aide-common
	aideinit
fi

echo "Ensure filesystem integrity is regularly checked"
crontab -l | { cat; echo "0 5 * * * /usr/bin/aide.wrapper --config /etc/aide/aide.conf"; } | crontab

echo "Ensure permissions on bootloader config are configured"
chown root:root /boot/grub/grub.cfg
chmod og-rwx /boot/grub/grub.cfg

echo "Ensure bootloader password is set"
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
#rm pass1 pass2
#	fi
#fi
#update-grub

echo "Ensure authentication required for single user mode"
grep ^root:[*\!]: /etc/shadow
if [ $? -ne 0 ]
then
	echo -e "password\npassword" | passwd root

fi

echo " Ensure core dumps are restricted"
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

echo "Ensure prelink is disabled"
dpkg -s prelink
if [ $? -eq 0 ]
then
	prelink -ua
	apt-get remove prelink
fi

echo "checking whether apparmor is installed or not"
dpkg -s apparmor
if [ $? -ne 0 ]
then
	echo -e "Y" | apt-get install apparmor apparmor-utils

fi

echo 'Ensure AppArmor is not disabled in bootloader configuration" 
grep "apparmor=0" /boot/grub/grub.cfg
if [ $? -eq 0 ]
then
	sed '/apparmor=0/d' /etc/default/grub
	#echo "GRUB_CMDLINE_LINUX="apparmor=1 security=apparmor"" >> /etc/default/grub 
	update-grub
fi

echo "Ensure all AppArmor Profiles are enforcing"
a=$(apparmor_status | grep profiles | grep complain | awk '{print $1;}')
if [ ! "$a" == "0" ]
then
	aa-enforce /etc/apparmor.d/* 
fi

