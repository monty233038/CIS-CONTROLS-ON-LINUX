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


