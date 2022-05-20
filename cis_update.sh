!#/bin/bash
#Funtion to Check Mountinfg of differnet modules is disabled
mod() {
  modprobe -n -v $1
  if [ $? -eq 0 ]; then
    lsmod | grep $1
    if [ $? -ne 0 ]; then
      echo "install $1 /bin/true" >/etc/modprobe/$1.conf
      rmmod $1
    fi
  fi
}

#Funtion to Mount a partition
mount() {
  echo -e "\e[1;31m Ensure separate mount point exist for $1 \e[0m"
  mount | grep $1
  if [ $? -eq 0 ]; then
    lvcreate -L 500 -n $1 vol
    mkfs.ext4 /dev/vol/$1
    umount $1
    mkdir /a
    mount /dev/vol/$1 /a
    rsync -a $1 /a
    echo "/dev/vol/$1	$1	ext4	rw,nosuid,nodev,noexec,relatime		1	2" >>/etc/fstab
    mount -a
    umount /a
    rm -r /a

  else

    lvcreate -L 500 -n $1 vol
    mkfs.ext4 /dev/vol/$1
    mkdir $1
    echo "/dev/vol/$1	$1 	ext4	rw,nosuid,nodev,noexec,relatime		1	2" >>/etc/fstab
    mount -a
  fi
}

#Funtion to ensure options are set on partition
option_set_on_partition(){
  echo -e "\e[1;31m Ensure $1 option set on $2 partition \e[0m"
  mount | grep $2 | grep $1
  if [ $? -ne 0 ]; then
    awk'$1~"/dev/vol/home"{$4="$1,"$4}'1 OFS="\t" /etc/fstab
    mount -o remount,nodev $2
  fi
  }

#Funtion Disable Automounting
disable_automounting() {
  echo -e "\e[1;31m Disable Automounting \e[0m"
  dpkg -s autofs
  if [ $? -eq 0 ]; then
    ser_stat=$(systemctl is-enabled autofs)
    if [ "$ser_stat" == "enabled" ]; then
      systemctl disable autofs
    fi
  fi
}

#Ensure sticky bit is set on all world-writable directories
world_writable_directories() {
  echo -e "\e[1;31m Ensure sticky bit is set on all world-writable directories \e[0m"
  df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t
}

#Function to Ensure AIDE is installed
aide() {
  echo -e "\e[1;31m Ensure AIDE is installed \e[0m"
  dpkg -s aide
  if [ $? -ne 0 ]; then
    export DEBIAN_FRONTEND=noninteractive
    DEBIAN_FRONTEND=noninteractive apt-get -q -y install aide aide-common
    aideinit
  fi

}


#Funtion to Ensure filesystem integrity is regularly checked
integrity() {
  echo -e "\e[1;31m Ensure filesystem integrity is regularly checked \e[0m"
  crontab -l | {
    cat
    echo "0 5 * * * /usr/bin/aide.wrapper --config /etc/aide/aide.conf"
  } | crontab
}

#Funtion Ensure permissions on bootloader config are configured
bootloader_perm() {
  echo -e "\e[1;31m Ensure permissions on bootloader config are configured \e[0m"
  chown root:root /boot/grub/grub.cfg
  chmod og-rwx /boot/grub/grub.cfg
}

#Function Ensure bootloader password is set
bootloader_pass() {
  echo -e "\e[1;31m Ensure bootloader password is set \e[0m"
  grep "^set superusers" /boot/grub/grub.cfg
  if [ $? -ne 0 ]; then
    grep "^password" /boot/grub/grub.cfg
    if [ $? -ne 0 ]; then
      echo -e "password\npassword" | grub-mkpasswd-pbkdf2 >pass1
      tail -n 1 pass1 >pass2
      sed -i 's/PBKDF2 hash of your password is//g' pass2
      echo 'set superusers="root"' >>/etc/grub.d/00_header
      echo "set password_pbkdf2 root $(cat pass2)" >>/etc/grub.d/00_header
      rm pass1 pass2
      update-grub
    fi
  fi
}


#Function Ensure authentication required for single user mode
auth_single() {
  echo -e "\e[1;31m Ensure authentication required for single user mode \e[0m"
  grep "^root:[*\!]:" /etc/shadow
  if [ $? -ne 0 ]; then
    echo -e "password\npassword" | passwd root

  fi
}


#Function to Ensure core dumps are restricted
core_dumps() {
  echo -e "\e[1;31m Ensure core dumps are restricted \e[0m"
  echo "* hard core 0" >>/etc/security/limits.conf

  grep "fs\.suid_dumpable" /etc/sysctl.conf /etc/sysctl.d/*
  if [ $? -ne 0 ]; then
    echo "fs.suid_dumpable = 0" >>/etc/sysctl.conf
    sysctl -w fs.suid_dumpable=0
  fi

  grep "kernel\.randomize_va_space" /etc/sysctl.conf /etc/sysctl.d/*
  if [ $? -ne 0 ]; then
    echo "kernel.randomize_va_space = 2" >>/etc/sysctl.conf
    sysctl -w kernel.randomize_va_space=2
  fi
}

#Function to Ensure prelink is disabled
prelink() {
  echo -e "\e[1;31m Ensure prelink is disabled \e[0m"
  dpkg -s prelink
  if [ $? -eq 0 ]; then
    prelink -ua
    apt-get remove prelink
  fi
}

#checking whether apparmor is installed or not
apparmor() {
  echo -e "\e[1;31m checking whether apparmor is installed or not \e[0m"
  dpkg -s apparmor
  if [ $? -ne 0 ]; then
    echo -e "Y" | apt-get install apparmor

  fi

  dpkg -s apparmor-utils
  if [ $? -ne 0 ]; then
    echo -e "y" | apt-get install apparmor-utils

  fi

  echo -e "\e[1;31m Ensure AppArmor is not disabled in bootloader configuration \e[0m"
  grep "apparmor=0" /boot/grub/grub.cfg
  if [ $? -eq 0 ]; then
    sed '/apparmor=0/d' /etc/default/grub
    update-grub
  fi

  echo -e "\e[1;31m Ensure all AppArmor Profiles are enforcing \e[0m"
  a=$(apparmor_status | grep profiles | grep complain | awk '{print $1;}')
  if [ ! "$a" == "0" ]; then
    aa-enforce /etc/apparmor.d/*
  fi
}


#Ensure local login warning banner is configured properly
login_banner() {
  echo -e "\e[1;31m Ensure local login warning banner is configured properly \e[0m"
  cat /etc/issue
  egrep '(\\v|\\r|\\m|\\s)' /etc/issue
  if [ $? -eq 0 ]; then
    sed -i 's/\\r//g;s/\\s//g;s/\\v//g;s/\\m//g' /etc/issue
  fi
  echo "Authorized uses only. All activity may be monitored and reported." >>/etc/issue
}

#Ensure permissions on /etc/issue are configured
permission() {
  echo -e "\e[1;31m Ensure permissions on /etc/issue are configured \e[0m"
  chown root:root /etc/issue
  chmod 644 /etc/issue
}

#Funtion to disable a service by inted
service_is_not_enable_inetd(){
  echo -e "\e[1;31m Ensure $1 is not enabled \e[0m"
  grep -R "^$1" /etc/inetd.*
  if [ $? -eq 0 ]; then
    sed -i '/$1/d' /etc/inetd.conf /etc/inetd.d/*
  fi
}


#nsure client is not enabled
client_is_not_enabled(){
  echo -e "\e[1;31m Ensure $1 client is not enabled \e[0m"
  a=$(systemctl is-enabled $1)
  if [[ "$a" == "enabled" ]]; then
    systemctl disable $1
  fi
}

#Ensure client is installed
client_is_installed(){
  echo -e "\e[1;31m Ensure $1 client is  installed \e[0m"
  dpkg -s $1
  if [ $? -ne 0 ]; then
    echo -e "y" | apt-get install $1
  fi
}

#Ensure client is not installed
client_is_not_installed(){
  echo -e "\e[1;31m Ensure $1 client is not installed \e[0m"
  dpkg -s $1
  if [ $? -eq 0 ]; then
    apt-get remove $1
  fi
  }

#Function to enable a client
client_is_enabled(){
  a=$(systemctl is-enabled $1)
  if [[ ! "$a" -eq "enabled" ]]; then
    systemctl enable $1
  fi
  }

#configuring packet redirecting
ip_conf_single(){
  echo -e "\e[1;31m $1 \e[0m"
  sed -i '/$2/d' /etc/sysctl.conf /etc/sysctl.d/*
  echo "net.ipv4.ip_forward = 0" /etc/sysctl.d/* >>/etc/sysctl.conf
  sysctl -w $2=0
  sysctl -w net.ipv4.route.flush=1
  }


#configuring packet redirecting
ip_conf_single_1(){
  echo -e "\e[1;31m $1 \e[0m"
  sed -i '/$2/d' /etc/sysctl.conf /etc/sysctl.d/*
  echo "$2 = 1" /etc/sysctl.d/* >>/etc/sysctl.conf
  sysctl -w $2=1
  sysctl -w net.ipv4.route.flush=1
  }

#configuring packet redirecting
ip_conf(){
  echo -e "\e[1;31m $1 \e[0m"
  sed -i '/$2/d' /etc/sysctl.conf /etc/sysctl.d/*
  echo "$2 = 0" /etc/sysctl.d/* >>/etc/sysctl.conf
  sed -i '/$3/d' /etc/sysctl.conf /etc/sysctl.d/*
  echo "$3 = 0" /etc/sysctl.d/* >>/etc/sysctl.conf
  sysctl -w $2=0
  sysctl -w $3=0
  sysctl -w net.ipv4.route.flush=1
  }

#configuring packet redirecting
ip_conf_1(){
  echo -e "\e[1;31m $1 \e[0m"
  sed -i '/$2/d' /etc/sysctl.conf /etc/sysctl.d/*
  echo "$2 = 1" /etc/sysctl.d/* >>/etc/sysctl.conf
  sed -i '/$3/d' /etc/sysctl.conf /etc/sysctl.d/*
  echo "$3 = 1" /etc/sysctl.d/* >>/etc/sysctl.conf
  sysctl -w $2=1
  sysctl -w $3=1
  sysctl -w net.ipv4.route.flush=1
  }


# Audit configuration function
auditd(){
  echo -e "\e[1;31m $1 \e[0m"
  sed -i '/$2/d' /etc/audit/auditd.conf
  echo "$3" >>/etc/audit/auditd.conf
  }


#Function to set permission on cron files
cron_perm(){
  echo -e "\e[1;31m  Ensure permissions on $1 are configured \e[0m"
  chown root:root $1
  chmod og-rwx $1
  }


#Funtion for ssh configuraton
ssh_conf(){
  echo -e "\e[1;31m Ensure SSH $2 is set to $1 \e[0m"
  a=$(grep "^$2" /etc/ssh/sshd_config | awk '{ print $2 }')
  if [[ ! "$a" == "$1" || -z "$a" ]]; then
  sed -i '/$2/d' /etc/ssh/sshd_config
  echo "$2 $1" >>/etc/ssh/sshd_config
fi
}

#Function to check ssh timeout
ssh_timeout_interval(){
  a=$(grep "^$1" /etc/ssh/sshd_config | awk '{ print $2 }')
  if [[ $a -gt $2 || -z "$a" ]]; then
    sed -i '/$1/d' /etc/ssh/sshd_config
    echo "$1 $2" >>/etc/ssh/sshd_config
  fi
  }

#Function to check password policies
password_policy(){
  echo -e "\e[1;31m $1 \e[0m"
  sed -i '/$2/d' /etc/login.defs
  echo "$3" >>/etc/login.defs

  for user in $(cat /etc/passwd | cut -d: -f1); do
    chage $4 $user
  done
  }


#Ensure permissions on {{file}} are configured
permission_set(){
  echo -e "\e[1;31m Ensure permissions on $1 are configured \e[0m"
  chown $2 $1
  chmod $3 $1
  }

#Function for noexist
no_exist(){
   echo -e "\e[1;31m $1 \e[0m"
   for file in $(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' $2); do
    $3 $file
  done
}

#Function to check legacy
no_legacy(){
  echo -e "\e[1;31m Ensure no legacy "+" entries exist in $1 \e[0m"
  grep '^\+:' $1
  if [ $? -eq 0 ]; then
    userdel '+'
  fi

  }
#Function To check no_users_have_ specific files
ensure_no_users_have_files(){
  echo -e "\e[1;31m Ensure no users have $1 files \e[0m"
  cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do
    if [ ! -d "$dir" ]; then
      echo "The home directory ($dir) of user $user does not exist."
    else
      if [ ! -h "$dir/$1" -a -f "$dir/$1" ]; then
        rm $dir/$1
      fi
    fi
done


 }

#Function TO Ensure no duplicate exist
ensure_no_duplicate(){
  echo -e "\e[1;31m $1 \e[0m"
  cat $2 | cut -f3 -d":" | sort -n | uniq -c | while read x; do
    [ -z "${x}" ] && break
    set - $x
    if [ $1 -gt 1 ]; then
      users=$(awk -F: '($3 == n) { print $1 }' n=$2 $2 | xargs)
      userdel $(echo $users | awk '{ print $2 }')
    fi
  done

}



mod ufw
mod cramfs
mod jffs2
mod hfs
mod hfsplus
mod udf
mod freevxfs

echo -e "\e[1;31m creating physical volume and volume group \e[0m"
#creating physical volume
pvcreate /dev/sdb

#creating Volume volume
vgcreate vol /dev/sdb
sleep 3

mount /tmp

#Ensure nodev option set on /tmp partition
echo -e "\e[1;31m Ensure nodev option set on /tmp partition \e[0m"
mount | grep /tmp | grep nodev
if [ $? -ne 0 ]; then
  awk'$1~"/dev/vol/tmp"{$4="nodev,"$4}'1 OFS="\t" /etc/fstab
  mount -o remount,nodev /tmp
fi

#Ensure nosuid option set on /tmp
echo -e "\e[1;31m Ensure nosuid option set on /tmp partition \e[0m"
mount | grep /tmp | grep nosuid
if [ $? -ne 0 ]; then
  awk'$1~"/dev/vol/tmp"{$4="nosuid,"$4}'1 OFS="\t" /etc/fstab
  mount -o remount,nosuid /tmp
fi

#Ensure separate mount point exist for /var
mount /var

#Ensure separate mount point exist for /var/tmp
mount /var/tmp

#Ensure nodev option set on /var/tmp partition
echo -e "\e[1;31m Ensure nodev option set on /var/tmp partition \e[0m"
mount | grep /var/tmp | grep nodev
if [ $? -ne 0 ]; then
  awk'$1~"/dev/vol/var-tmp"{$4="nodev,"$4}'1 OFS="\t" /etc/fstab
  mount -o remount,nodev /var/tmp
fi

#Ensure nosuid option set on /var/tmp partition
echo -e "\e[1;31m Ensure nosuid option set on /var/tmp partition \e[0m"
mount | grep /var/tmp | grep nosuid
if [ $? -ne 0 ]; then
  awk'$1~"/dev/vol/var-tmp"{$4="nosuid,"$4}'1 OFS="\t" /etc/fstab
  mount -o remount,nosuid /var/tmp
fi

#Ensure noexec option set on /var/tmp partition
echo -e "\e[1;31m Ensure noexec option set on /var/tmp partition \e[0m"
mount | grep /var/tmp | grep noexec
if [ $? -ne 0 ]; then
  awk'$1~"/dev/vol/var-tmp"{$4="noexec,"$4}'1 OFS="\t" /etc/fstab
  mount -o remount,noexec /var/tmp
fi

#Ensure separate mount point exist for /var/log
mount /var/log

# Ensure separate mount point exist for /var/log/audit
mount /var/log/audit

# Ensure separate mount point exist for /home
mount /home


option_set_on_partition "nodev" "/home"
option_set_on_partition "nodev" "/dev/shm"
option_set_on_partition "nosuid" "/dev/shm"
option_set_on_partition "noexec" "/dev/shm"

world_writable_directories

disable_automounting


aide


integrity


bootloader_perm


bootloader_pass


auth_single


core_dumps


prelink


apparmor


login_banner



permission /etc/issue
permission /etc/issue.net


apt-get update
echo -e "y" | apt-get install openbsd-inetd
dpkg -s openbsd-inetd
if [ $? -eq 0 ]; then
  service_is_not_enable_inetd chargen
  service_is_not_enable_inetd daytime
  service_is_not_enable_inetd  echo
  service_is_not_enable_inetd  discard
  service_is_not_enable_inetd  time
  service_is_not_enable_inetd  shell
  service_is_not_enable_inetd  login
  service_is_not_enable_inetd  exec
  service_is_not_enable_inetd  talk
  service_is_not_enable_inetd  ntalk
  service_is_not_enable_inetd  telnet
  service_is_not_enable_inetd  tftp

#dpkg -s xinetd
#if [$? -eq 0 ]
#then
#	awk '/chargen/{ n=NR+2 } NR==n{ $0="        disable         = yes" }1'   /etc/xinetd.conf /etc/xinetd.d/*
#fi

client_is_not_enabled xinetd


client_is_installed ntp
client_is_installed chrony

#Ensure ntp is configured
echo -e "\e[1;31m  Ensure ntp is configured \e[0m"
grep "^restrict" /etc/ntp.conf
if [ $? -ne 0 ]; then
  echo "restrict -4 default kod nomodify notrap nopeer noquery" >>/etc/ntp.conf
  echo "restrict -6 default kod nomodify notrap nopeer noquery" >>/etc/ntp.conf
fi

egrep "^(server|pool)" /etc/ntp.conf
if [ $? -ne 0 ]; then
  echo "server 0.in.pool.ntp.org" /etc/ntp.conf
  echo "server 1.in.pool.ntp.org" /etc/chrony/chrony.conf
fi

grep "RUNASUSER=ntp" /etc/init.d/ntp
if [ $? -ne 0 ]; then
  echo "RUNASUSER=ntp" /etc/init.d/ntp
fi

#Ensure chrony is configured
echo -e "\e[1;31m  Ensure chrony is configured \e[0m"
grep "^(server|pool)" /etc/chrony/chrony.conf
if [ $? -ne 0 ]; then
  echo "server 0.in.pool.ntp.org" /etc/chrony/chrony.conf
  echo "server 1.in.pool.ntp.org" /etc/chrony/chrony.conf
fi

client_is_installed xserver-xorg*
client_is_not_enabled avahi-daemon
client_is_not_enabled cups
client_is_not_enabled isc-dhcp-server
client_is_not_enabled isc-dhcp-server6
client_is_not_enabled slapd
client_is_not_enabled nfs-server
client_is_not_enabled rpcbind
client_is_not_enabled bind9
client_is_not_enabled vsftpd
client_is_not_enabled apache2
client_is_not_enabled dovecot
client_is_not_enabled smbd
client_is_not_enabled suid
client_is_not_enabled snmpd
client_is_not_enabled rsync

#Ensure mail transfer agent is configured for local-only mode
echo -e "\e[1;31m  Ensure mail transfer agent is configured for local-only mode  \e[0m"
netstat -an | grep LIST | grep ":25[[:space:]]"
sed -i '/inet_interfaces/d' /etc/postfix/main.cf
echo "inet_interfaces = loopback-only" >>/etc/postfix/main.cf
systemctl restart postfix

client_is_not_enabled nis


client_is_not_installed nis
client_is_not_installed  rsh-client
client_is_not_installed rsh-redone-client
client_is_not_installed talk
client_is_not_installed telnet
client_is_not_installed ldap-utils





ip_conf "Ensure packet redirecting is enabled"  "net.ipv4.conf.all.send_redirects"  "net.ipv4.conf.default.send_redirects"
ip_conf "Ensure packet redirect sending is disabled" "net.ipv4.conf.all.send_redirects" "net.ipv4.conf.default.send_redirects"
ip_conf "Ensure source routed packets are not accepted" "net.ipv4.conf.all.accept_source_route" "net.ipv4.conf.default.accept_source_route"
ip_conf "Ensure ICMP redirects are not accepted" "et.ipv4.conf.all.accept_redirects" "net.ipv4.conf.default.accept_redirect"
ip_conf "Ensure secure ICMP redirects are not accepted" "net.ipv4.conf.all.secure_redirects" "net.ipv4.conf.default.secure_redirects"
ip_conf "Ensure suspicious packets are logged" "net.ipv4.conf.all.log_martians" "net.ipv4.conf.default.log_martians"
ip_conf_1 "Ensure Reverse Path Filtering is enabled" "net.ipv4.conf.all.rp_filter" "net.ipv4.conf.default.rp_filters"
ip_conf_1 "Ensure Reverse Path Filtering is enabled" "net.ipv4.conf.all.rp_filter" "net.ipv4.conf.default.rp_filters"
ip_conf_single_1 "Ensure TCP SYN Cookies is enabled" "net.ipv4.tcp_syncookies"
ip_conf_1 "Ensure IPv6 router advertisements are not accepted" "net.ipv6.conf.all.accept_ra" "net.ipv6.conf.default.accept_ra"
ip_conf "Ensure IPv6 redirects are not accepted" "net.ipv6.conf.all.accept_redirects" "net.ipv6.conf.default.accept_redirects"
ip_conf_single "Ensure IP forwarding is disabled" "net.ipv4.ip_forward"
ip_conf_single "Ensure broadcast ICMP requests are ignored" "net.ipv4.icmp_echo_ignore_broadcasts"
ip_conf_single "Ensure bogus ICMP responses are ignored" "net.ipv4.icmp_ignore_bogus_error_responses"


client_is_installed tcpd

a=$(default_if=$(ip route list | awk '/^default/ {print $5}'))
b=$(ip -o -f inet addr show $default_if | awk '{print $4}')

#Ensure /etc/hosts.allow is configured
echo -e "\e[1;31m  Ensure /etc/hosts.allow is configured  \e[0m"
echo "ALL: $(echo $b)" >/etc/hosts.allow

#Ensure /etc/hosts.deny is configured
echo -e "\e[1;31m Ensure /etc/hosts.deny is configured   \e[0m"
echo "ALL: ALL" >>/etc/hosts.deny

#Ensure permissions on /etc/hosts.allow are configured
echo -e "\e[1;31m Ensure permissions on /etc/hosts.allow are configured \e[0m"
chown root:root /etc/hosts.allow
chmod 644 /etc/hosts.allow

#Ensure permissions on /etc/hosts.deny are configured
echo -e "\e[1;31m Ensure permissions on /etc/hosts.deny are configured \e[0m"
chown root:root /etc/hosts.deny
chmod 644 /etc/hosts.deny

mod rds
mod tipc
mod sctp
mod dccp
client_is_installed iptables

#Ensure default deny firewall policy
echo -e "\e[1;31m Ensure default deny firewall policy \e[0m"
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP

#Ensure loopback traffic is configured
echo -e "\e[1;31m Ensure loopback traffic is configured \e[0m"
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT -s 127.0.0.0/8 -j DROP

#Ensure outbound and established connections are configured
echo -e "\e[1;31m Ensure outbound and established connections are configured \e[0m"
iptables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
iptables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
iptables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT

#Ensure firewall rules exist for all open ports
echo -e "\e[1;31m Ensure firewall rules exist for all open ports \e[0m"
netstat -tulnp | awk 'FNR > 2 {print $4}' | cut -d ':' -f 2 >ports
sed -i '/^$/d' ports
while read p; do
  iptables -L -v -n | grep $p
  if [ $? -ne 0 ]; then
    iptables -A INPUT -p tcp --dport $p -m state --state NEW -jACCEPT
  fi
done <ports



client_is_installed auditd
client_is_enabled auditd


auditd "Ensure audit log storage size is configured" "max_log_file = 8" "max_log_file = 20"
auditd "Ensure system is disabled when audit logs are full" "space_left_action =" "space_left_action = email"
auditd  "Ensure system is disabled when audit logs are full" "action_mail_acct =" "action_mail_acct = root"
auditd "Ensure system is disabled when audit logs are full" "admin_space_left_action =" "admin_space_left_action = halt"
echo -e "\e[1;31m Ensure audit log storage size is configured \e[0m"
auditd "Ensure audit logs are not automatically deleted" "max_log_file_action =" "max_log_file_action = keep_logs"

#Ensure auditing for processes that start prior to auditd is enabled
echo -e "\e[1;31m Ensure auditing for processes that start prior to auditd is enabled \e[0m"
grep "audit=1" /etc/default/grub
if [ $? -ne 0 ]; then
  echo "GRUB_CMDLINE_LINUX="audit=1"" >>/etc/default/grub
  update-grub
fi

echo -e "\e[1;31m Ensure events that modify date and time information are collected \e[0m"
grep time-change /etc/audit/audit.rules
if [ $? -ne 0 ]; then
  echo "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change" >>/etc/audit/audit.rules
  echo "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k timechange" >>/etc/audit/audit.rules
  echo "-a always,exit -F arch=b64 -S clock_settime -k time-change" >>/etc/audit/audit.rules
  echo "-a always,exit -F arch=b32 -S clock_settime -k time-change" >>/etc/audit/audit.rules
  echo "-w /etc/localtime -p wa -k time-change" >>/etc/audit/audit.rules
fi

#Ensure events that modify user/group information are collected
echo -e "\e[1;31m Ensure events that modify user/group information are collected \e[0m"
grep identity /etc/audit/audit.rules
if [ $? -ne 0 ]; then
  echo "-w /etc/group -p wa -k identity" >>/etc/audit/audit.rules
  echo "-w /etc/passwd -p wa -k identity" >>/etc/audit/audit.rules
  echo "-w /etc/gshadow -p wa -k identity" >>/etc/audit/audit.rules
  echo "-w /etc/shadow -p wa -k identity" >>/etc/audit/audit.rules
  echo "-w /etc/security/opasswd -p wa -k identity" >>/etc/audit/audit.rules
fi

#Ensure events that modify the system network environment are collected
echo -e "\e[1;31m Ensure events that modify the system network environment are collected \e[0m"
grep system-locale /etc/audit/audit.rules
if [ $? -ne 0 ]; then
  echo "a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale" >>/etc/audit/audit.rules
  echo "-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale" >>/etc/audit/audit.rules
  echo "-w /etc/issue -p wa -k system-locale" >>/etc/audit/audit.rules
  echo "-w /etc/issue.net -p wa -k system-locale" >>/etc/audit/audit.rules
  echo "-w /etc/hosts -p wa -k system-locale" >>/etc/audit/audit.rules
  echo "-w /etc/network -p wa -k system-locale" >>/etc/audit/audit.rules
fi

#Ensure events that modify the system Mandatory Access Controls are collected
echo -e "\e[1;31m Ensure events that modify the system Mandatory Access Controls are collected \e[0m"
grep MAC-policy /etc/audit/audit.rules
if [ $? -ne 0 ]; then
  echo "-w /etc/apparmor/ -p wa -k MAC-policy" >>/etc/audit/audit.rules
  echo "-w /etc/apparmor.d/ -p wa -k MAC-policy" >>/etc/audit/audit.rules
fi

#Ensure login and logout events are collected
echo -e "\e[1;31m Ensure login and logout events are collected \e[0m"
grep logins /etc/audit/audit.rules
if [ $? -ne 0 ]; then
  echo "-w /var/log/faillog -p wa -k logins" >>/etc/audit/audit.rules
  echo "-w /var/log/lastlog -p wa -k logins" >>/etc/audit/audit.rules
  echo "-w /var/log/tallylog -p wa -k logins" >>/etc/audit/audit.rules
fi

#Ensure session initiation information is collected
echo -e "\e[1;31m Ensure session initiation information is collected \e[0m"
grep session /etc/audit/audit.rules
if [ $? -ne 0 ]; then
  echo "-w /var/run/utmp -p wa -k session" >>/etc/audit/audit.rules
fi

grep logins /etc/audit/audit.rules
if [ $? -ne 0 ]; then
  echo "-w /var/log/wtmp -p wa -k logins" >>/etc/audit/audit.rules
  echo "-w /var/log/btmp -p wa -k logins" >>/etc/audit/audit.rules
fi

#Ensure discretionary access control permission modification events are collected
echo -e "\e[1;31m Ensure discretionary access control permission modification events are collected \e[0m"
grep perm_mod /etc/audit/audit.rules
if [ $? -ne 0 ]; then
  echo "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" >>/etc/audit/audit.rules
  echo "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" >>/etc/audit/audit.rules
  echo "-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" >>/etc/audit/audit.rules
  echo "-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" >>/etc/audit/audit.rules
  echo "-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >>/etc/audit/audit.rules
  echo "-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >>/etc/audit/audit.rules
fi

#Ensure unsuccessful unauthorized file access attempts are collected
echo -e "\e[1;31m Ensure unsuccessful unauthorized file access attempts are collected \e[0m"
grep access /etc/audit/audit.rules
if [ $? -ne 0 ]; then
  echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >>/etc/audit/audit.rules
  echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >>/etc/audit/audit.rules
  echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >>/etc/audit/audit.rules
  echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >>/etc/audit/audit.rules
fi

# Ensure successful file system mounts are collected
echo -e "\e[1;31m Ensure successful file system mounts are collected \e[0m"
grep mounts /etc/audit/audit.rules
if [ $? -ne 0 ]; then
  echo "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >>/etc/audit/audit.rules
  echo "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >>/etc/audit/audit.rules
fi

#Ensure file deletion events by users are collected
echo -e "\e[1;31m Ensure file deletion events by users are collected \e[0m"
grep delete /etc/audit/audit.rules
if [ $? -ne 0 ]; then
  echo "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >>/etc/audit/audit.rules
  echo "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >>/etc/audit/audit.rules
fi

#Ensure changes to system administration scope (sudoers) is collected
echo -e "\e[1;31m Ensure changes to system administration scope (sudoers) is collected \e[0m"
grep scope /etc/audit/audit.rules
if [ $? -ne 0 ]; then
  echo "-w /etc/sudoers -p wa -k scope" >>/etc/audit/audit.rules
  echo "-w /etc/sudoers.d/ -p wa -k scope" >>/etc/audit/audit.rules
fi

#Ensure system administrator actions (sudolog) are collected
echo -e "\e[1;31m Ensure system administrator actions (sudolog) are collected \e[0m"
grep actions /etc/audit/audit.rules
if [ $? -ne 0 ]; then
  echo "-w /var/log/sudo.log -p wa -k actions" >>/etc/audit/audit.rules
fi

#Ensure kernel module loading and unloading is collected
echo -e "\e[1;31m Ensure kernel module loading and unloading is collected \e[0m"
grep modules /etc/audit/audit.rules
if [ $? -ne 0 ]; then
  echo "w /sbin/insmod -p x -k modules" >>/etc/audit/audit.rules
  echo "-w /sbin/rmmod -p x -k modules" >>/etc/audit/audit.rules
  echo "-w /sbin/modprobe -p x -k modules" >>/etc/audit/audit.rules
  echo "-a always,exit -F arch=b64 -S init_module -S delete_module -k modules" >>/etc/audit/audit.rules
fi

#Ensure the audit configuration is immutable
echo -e "\e[1;31m Ensure the audit configuration is immutable \e[0m"
grep "-e 2" /etc/audit/audit.rules
if [ $? -ne 0 ]; then
  echo "-e 2" >>/etc/audit/audit.rules
fi

#Reloading Auditd service
echo -e "\e[1;31m Reloading Auditd service \e[0m"
systemctl reload auditd

#ENsure rsyslog and syslog-ng is installed
client_is_installed rsyslog
client_is_installed syslog-ng
client_is_installed yslog-ng-core
client_is_enabled rsyslog

#Ensure rsyslog default file permissions configured
echo -e "\e[1;31m Ensure rsyslog default file permissions configured \e[0m"
grep ^\$FileCreateMode /etc/rsyslog.conf /etc/rsyslog.d/*.conf | grep 0640
if [ $? -ne 0 ]; then
  sed -i '/$FileCreateMode/d' /etc/rsyslog.conf
  echo "$FileCreateMode 0640" >>/etc/rsyslog.conf
fi

#Ensure rsyslog is configured to send logs to a remote log host
echo -e "\e[1;31m Ensure rsyslog is configured to send logs to a remote log host \e[0m"
grep "^*.*[^I][^I]*@" /etc/rsyslog.conf /etc/rsyslog.d/*.conf
if [ $? -ne 0 ]; then
  # THis is s demo server in actual we will replace this will with real domain
  echo "*.* @@loghost.example.com" /etc/rsyslog.d/*.conf >>/etc/rsyslog.conf
  pkill -HUP rsyslogd
fi

client_is_enabled syslog-ng

#Ensure syslog-ng default file permissions configured
echo -e "\e[1;31m Ensure syslog-ng default file permissions configured \e[0m"
grep ^options /etc/syslog-ng/syslog-ng.conf | grep 0640
if [ $? -ne 0 ]; then
  sed -i '/options/d' /etc/syslog-ng/syslog-ng.conf
  echo "options { chain_hostnames(off); flush_lines(0); perm(0640); stats_freq(3600); threaded(yes); };" >>/etc/syslog-ng/syslog-ng.conf
fi

#Ensure permissions on all logfiles are configured
echo -e "\e[1;31m Ensure permissions on all logfiles are configured \e[0m"
chmod -R g-wx,o-rwx /var/log/*

client_is_enabled cron
cron_perm /etc/crontab
cron_perm /etc/cron.hourly
cron_perm /etc/cron.daily
cron_perm /etc/cron.weekly
cron_perm /etc/cron.monthly
cron_perm /etc/cron.d

#Ensure at/cron is restricted to authorized users
echo -e "\e[1;31m Ensure at/cron is restricted to authorized users  \e[0m"
stat /etc/cron.deny
if [ $? -eq 0 ]; then
  rm /etc/cron.deny
  rm /etc/at.deny
fi

stat /etc/cron.allow
if [ $? -ne 0 ]; then
  echo "creating cron allow file"
  touch /etc/cron.allow
  touch /etc/at.allow
  chmod og-rwx /etc/cron.allow
  chmod og-rwx /etc/at.allow
  chown root:root /etc/cron.allow
  chown root:root /etc/at.allow
fi

client_is_installed openssh-server
cron_perm /etc/ssh/sshd_config


ssh_conf "2" "Protocol"
ssh_conf "INFO" "LogLevel"
ssh_conf "no" "X11Forwarding"
ssh_conf "4" "MaxAuthTries"
ssh_conf "yes" "IgnoreRhosts"
ssh_conf "no" "HostbasedAuthentication"
ssh_conf "no" "PermitRootLogin"
ssh_conf "no" "PermitEmptyPasswords"
ssh_conf "no" "PermitUserEnvironment"

#Ensure only approved MAC algorithms are used
echo -e "\e[1;31m Ensure only approved MAC algorithms are used \e[0m"
sed -i '/MACs/d' /etc/ssh/sshd_config
echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com" >>/etc/ssh/sshd_config


#Ensure SSH Idle Timeout Interval is configured
echo -e "\e[1;31m Ensure SSH Idle Timeout Interval is configured \e[0m"
ssh_timeout_interval "ClientAliveInterval" "300"
ssh_timeout_interval "ClientAliveCountMax" "0"
ssh_timeout_interval "LoginGraceTime" "60"

#Ensure SSH access is limited
echo -e "\e[1;31m Ensure SSH access is limited \e[0m"
grep "^AllowUsers" /etc/ssh/sshd_config
a=$?
grep "^AllowGroups" /etc/ssh/sshd_config
b=$?
grep "^DenyUsers" /etc/ssh/sshd_config
c=$?
grep "^DenyGroups" /etc/ssh/sshd_config
d=$?
if [[ $a -eq 1 && $b -eq 1 && $c -eq 1 && $d -eq 1 ]]; then
  echo "AllowUsers ubuntu" >>/etc/ssh/sshd_config
  echo "AllowGroups ubuntu" >>/etc/ssh/sshd_config
fi

#Ensure SSH warning banner is configured
echo -e "\e[1;31m Ensure SSH warning banner is configured  \e[0m"
grep "^Banner" /etc/ssh/sshd_config
if [ $? -ne 0 ]; then
  echo "Banner /etc/issue.net" >>/etc/ssh/sshd_config
fi

# Reloading SSHD service
echo -e "\e[1;31m Reloading SSHD service  \e[0m"
systemctl reload sshd

# Ensure password creation requirements are configured
echo -e "\e[1;31m Ensure password creation requirements are configured \e[0m"
echo -e "y" | apt-get install libpam-pwquality
sed -i '/pam_pwquality.so/d' /etc/pam.d/common-password
echo "password requisite pam_pwquality.so retry=3" >>/etc/pam.d/common-password
sed -i '/minlen =/d' /etc/security/pwquality.conf
sed -i '/dcredit =/d' /etc/security/pwquality.conf
sed -i '/ucredit =/d' /etc/security/pwquality.conf
sed -i '/ocredit =/d' /etc/security/pwquality.conf
sed -i '/lcredit =/d' /etc/security/pwquality.conf
echo "minlen = 14" >>/etc/security/pwquality.conf
echo "dcredit = -1" >>/etc/security/pwquality.conf
echo "ucredit = -1" >>/etc/security/pwquality.conf
echo "lcredit = -1" >>/etc/security/pwquality.conf
echo "ocredit = -1" >>/etc/security/pwquality.conf

#Ensure lockout for failed password attempts is configured
echo -e "\e[1;31m Ensure lockout for failed password attempts is configured \e[0m"
a=$(grep "pam_tally2" /etc/pam.d/common-auth | cut -c58)
if [ "$a" != "5" ]; then
  sed -i '/pam_tally2/d' /etc/pam.d/common-auth
  echo "auth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900" >>/etc/pam.d/common-auth
fi

#Ensure password reuse is limited
echo -e "\e[1;31m Ensure password reuse is limited  \e[0m"
a=$(egrep '^password\s+required\s+pam_pwhistory.so' /etc/pam.d/common-password | cut -c45)
if [ "$a" != "5" ]; then
  sed -i '/password\s+required\s+pam_pwhistory.so/d' /etc/pam.d/common-auth
  echo "password required pam_pwhistory.so remember=5" >>/etc/pam.d/common-auth
fi

#Ensure password hashing algorithm is SHA-512
echo -e "\e[1;31m Ensure password hashing algorithm is SHA-512 \e[0m"
egrep '^password\s+(\S+\s+)+pam_unix\.so\s+(\S+\s+)*sha512' /etc/pam.d/common-password
if [ $? -ne 0 ]; then
  echo "password [success=1 default=ignore] pam_unix.so sha512" >>/etc/pam.d/common-password
fi



password_policy "Ensure password expiration is 365 days or les" "PASS_MAX_DAYS" "PASS_MAX_DAYS 90" "maxdays" "--maxdays 90"
password_policy "Ensure minimum days between password changes is 7 or more" "PASS_MIN_DAYS" "PASS_MIN_DAYS 7" "--mindays 7"
password_policy "Ensure password expiration warning days is 7 or more" "PASS_WARN_AGE" "PASS_WARN_AGE 7" "--warndays 7"

# Ensure inactive password lock is 30 days or less
echo -e "\e[1;31m Ensure inactive password lock is 30 days or less  \e[0m"
a=$(useradd -D | grep INACTIVE | cut -d= -f2)
if [[ $a -gt 30 || $a -eq -1 ]]; then
  useradd -D -f 30
fi

for user in $(cat /etc/passwd | cut -d: -f1); do
  chage --inactive 30 $user
done

#Ensure system accounts are non-login
echo -e "\e[1;31m Ensure system accounts are non-login \e[0m"
for user in $(awk -F: '($3 < 1000) {print $1 }' /etc/passwd); do
  if [ $user != "root" ]; then
    usermod -L $user
    if [ $user != "sync" ] && [ $user != "shutdown" ] && [ $user != "halt" ]; then
      usermod -s /usr/sbin/nologin $user
    fi
  fi
done

#Ensure default group for the root account is GID 0
echo -e "\e[1;31m Ensure default group for the root account is GID 0 \e[0m"
a=$(grep "^root:" /etc/passwd | cut -f4 -d:)
if [ $a -ne 0 ]; then
  usermod -g 0 root
fi

#Ensure default user umask is 027 or more restrictive
echo -e "\e[1;31m Ensure default user umask is 027 or more restrictive \e[0m"
sed -i '/umask/d' /etc/bash.bashrc /etc/profile /etc/profile.d/*.sh
echo "umask 027" /etc/profile /etc/profile.d/*.sh >>/etc/bash.bashrc

# Ensure default user shell timeout is 900 seconds or less
echo -e "\e[1;31m Ensure default user shell timeout is 900 seconds or less \e[0m"
grep "^TMOUT" /etc/bash.bashrc
if [ $? -ne 0 ]; then
  echo "TMOUT=600" >>/etc/bash.bashrc
fi

grep "^TMOUT" /etc/profile /etc/profile.d/*.sh
if [ $? -ne 0 ]; then
  echo "TMOUT=600" /etc/profile.d/*.sh >>/etc/profile
fi

#Ensure access to the su command is restricted
echo -e "\e[1;31m Ensure access to the su command is restricted \e[0m"
echo "auth required pam_wheel.so" >>/etc/pam.d/su
echo "sudo:x:10:root,ubuntu" >>/etc/group

permission_set "/etc/passwd"  "root:root" "644"
permission_set "/etc/shadow" "root:shadow" "o-rwx,g-wx"
permission_set "/etc/group" "root:root" "644"
permission_set "/etc/gshadow" "root:shadoww" "o-rwx,g-rw"
permission_set "/etc/passwd" "root:root" "u-x,go-wx"
permission_set "/etc/shadow" "root:shadow" "o-rwx,g-rw"
permission_set "/etc/group" "root:root" "u-x,go-wx"
permission_set "/etc/gshadow" "root:shadow" "o-rwx,g-rw"


no_exist "Ensure no world writable files exist" "-xdev -type f -perm -0002" "chmod o-w"
no_exist "Ensure no unowned files or directories exist" "-xdev -nouser" "chown root:root"
no_exist "Ensure no ungrouped files or directories exist" "-xdev -nogroup" "chown root:root"
echo -e "\e[1;31m Ensure no ungrouped files or directories exist \e[0m"

#Ensure password fields are not empty
echo -e "\e[1;31m Ensure password fields are not empty \e[0m"
for user in $(cat /etc/shadow | awk -F: '($2 == "!" ) { print $1 }'); do
  passwd -l $user
done


no_legacy /etc/shadow
no_legacy /etc/group

#Ensure root is the only UID 0 account
echo -e "\e[1;31m Ensure root is the only UID 0 account \e[0m"
for name in $(cat /etc/passwd | awk -F: '($3 == 0) { print $1 }'); do
  if [[ "$name" != "root" ]]; then
    userdel $name
  fi
done

#Ensure all users home directories exist
echo -e "\e[1;31m Ensure all users home directories exist \e[0m"
cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 != "/usr/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do
  if [ ! -d "$dir" ]; then
    mkdir $dir
    chown $user:$user $dir
    usermod -d $user
  fi
done

#Ensure users home directories permissions are 750 or more restrictive
echo -e "\e[1;31m Ensure users home directories permissions are 750 or more restrictive \e[0m"
for dir in $(cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 != "/usr/sbin/nologin" && $7 != "/bin/false") { print $6 }'); do
  dirperm=$(ls -ld $dir | cut -f1 -d" ")
  if [ $(echo $dirperm | cut -c6) != "-" ]; then
    chmod g-w $dir
  fi
  if [ $(echo $dirperm | cut -c8) != "-" ]; then
    chmod o-r $dir
  fi
  if [ $(echo $dirperm | cut -c9) != "-" ]; then
    chmod o-w $dir
  fi
  if [ $(echo $dirperm | cut -c10) != "-" ]; then
    chmod o-x $dir
  fi
done

# Ensure users own their home directories
echo -e "\e[1;31m Ensure users own their home directories \e[0m"
cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 != "/usr/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do
  if [ ! -d "$dir" ]; then
    echo "The home directory ($dir) of user $user does not exist."
  else
    owner=$(stat -L -c "%U" "$dir")
    if [ "$owner" != "$user" ]; then
      chown $user $dir
    fi
  fi
done

#Ensure users dot files are not group or world writable
echo -e "\e[1;31m Ensure users dot files are not group or world writable \e[0m"
cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do
  if [ ! -d "$dir" ]; then
    echo "The home directory ($dir) of user $user does not exist."
  else
    for file in $dir/.[A-Za-z0-9]*; do
      if [ ! -h "$file" -a -f "$file" ]; then
        fileperm=$(ls -ld $dir/$file | cut -f1 -d" ")
        if [ "$(echo $fileperm | cut -c6)" != "-" ]; then
          chmod g-w $file
        fi
        if [ "$(echo $fileperm | cut -c9)" != "-" ]; then
          chmod o-w $file
        fi
      fi
    done
  fi
done



ensure_no_users_have_files ".forward"
ensure_no_users_have_files ".netrc"

#Ensure users .netrc Files are not group or world accessible
echo -e "\e[1;31m Ensure users .netrc Files are not group or world accessible \e[0m"
cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do
  if [ ! -d "$dir" ]; then
    echo "The home directory ($dir) of user $user does not exist."
  else
    for file in $dir/.netrc; do
      if [ ! -h "$file" -a -f "$file" ]; then
        fileperm=$(ls -ld $file | cut -f1 -d" ")
        if [ $(echo $fileperm | cut -c5) != "-" ]; then
          chmod g-w $file
        fi
        if [ $(echo $fileperm | cut -c6) != "-" ]; then
          chmod g-r $file
        fi
        if [ $(echo $fileperm | cut -c7) != "-" ]; then
          chmod g-x $file
        fi
        if [ $(echo $fileperm | cut -c8) != "-" ]; then
          chmod o-r $file
        fi
        if [ $(echo $fileperm | cut -c9) != "-" ]; then
          chmod o-w $file
        fi
        if [ $(echo $fileperm | cut -c10) != "-" ]; then
          chmod o-x $file
        fi
      fi
    done
  fi
done


# Ensure no users have .rhosts files
echo -e "\e[1;31m Ensure no users have .rhosts files  \e[0m"
cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do
  if [ ! -d "$dir" ]; then
    echo "The home directory ($dir) of user $user does not exist."
  else
    for file in $dir/.rhosts; do
      if [ ! -h "$file" -a -f "$file" ]; then
        rm $dir/.rhosts
      fi
    done
  fi
done

#Ensure all groups in /etc/passwd exist in /etc/group
echo -e "\e[1;31m Ensure all groups in /etc/passwd exist in /etc/group \e[0m"
for i in $(cut -s -d: -f4 /etc/passwd | sort -u); do
  grep -q -P "^.*?:[^:]*:$i:" /etc/group
  if [ $? -ne 0 ]; then
    groupadd $(cat /etc/passwd | awk -F: '($4 == $i) { print $1 }')
  fi
done


ensure_no_duplicate " Ensure no duplicate UIDs exist" "/etc/passwd"
ensure_no_duplicate "Ensure no duplicate GIDs exist" "/etc/group"

#Ensure shadow group is empty
echo -e "\e[1;31m Ensure shadow group is empty \e[0m"
shadow_gid=$(grep ^shadow /etc/group | awk -F: '{ print $3 }')
user=$(awk -F: '($4 == "42") { print $1 }' /etc/passwd)
if [[ ! -z $user ]]; then
  deluser $user shadow
fi
# END OF SCRIPT
