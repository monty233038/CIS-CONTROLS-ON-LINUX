#!/bin/bash
apt-get update
echo -e "\e[1;31m Ensure iptables is installed \e[0m"
dpkg -s iptables
if [ $? -ne 0 ]
then
  apt-get install iptables

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









  
  



































































































































  
  
  
  
  
  
  
  
  

























