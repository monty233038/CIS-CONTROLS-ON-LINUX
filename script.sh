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
