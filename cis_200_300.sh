#!/bin/bash
Ensure iptables is installed
dpkg -s iptables
if [ $? -ne 0 ]
then
  apt-get install iptables

Ensure default deny firewall policy
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP

Ensure loopback traffic is configured
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT -s 127.0.0.0/8 -j DROP

Ensure outbound and established connections are configured
iptables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
iptables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
iptables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT

Ensure firewall rules exist for all open ports
netstat -tulnp | awk 'FNR > 2 {print $4}' | cut -d ':' -f 2  > ports
sed -i '/^$/d' ports
while read p; do
        iptables -L -v -n | grep $p
        if [ $? -ne 0 ]
        then
                iptables -A INPUT -p tcp --dport $p -m state --state NEW -jACCEPT
        fi
done <ports

Ensure Auditd service is installed and enabled
echo -e "y" | apt-get install auditd
a=$(systemctl is-enabled auditd)
if [[ ! "$a" -eq "enabled" ]]
then
  systemctl enable auditd
fi

Ensure audit log storage size is configured
sed -i '/max_log_file = 8/d' /etc/audit/auditd.conf 
echo "max_log_file = 20" >> /etc/audit/auditd.conf 

Ensure system is disabled when audit logs are full
sed -i '/pace_left_action =/d' /etc/audit/auditd.conf 
echo "space_left_action = email" >> /etc/audit/auditd.conf
sed -i '/action_mail_acct =/d' /etc/audit/auditd.conf 
echo "action_mail_acct = root" >> /etc/audit/auditd.conf
sed -i '/admin_space_left_action =/d' /etc/audit/auditd.conf 
echo "admin_space_left_action = halt" >> /etc/audit/auditd.conf

Ensure audit logs are not automatically deleted
sed -i '/max_log_file_action =/d' /etc/audit/auditd.conf
echo "max_log_file_action = keep_logs" >> /etc/audit/auditd.conf

Ensure auditing for processes that start prior to auditd is enabled
grep "audit=1" /etc/default/grub
if [ $? -ne 0 ]
then
  echo "GRUB_CMDLINE_LINUX="audit=1"" >>  /etc/default/grub
  update-grub
fi

Ensure events that modify date and time information are collected
grep time-change /etc/audit/audit.rules
if [ $? -ne 0 ]
then
  echo "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change" >> /etc/audit/audit.rules
  echo "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k timechange" >> /etc/audit/audit.rules
  echo "-a always,exit -F arch=b64 -S clock_settime -k time-change" >> /etc/audit/audit.rules
  echo "-a always,exit -F arch=b32 -S clock_settime -k time-change" >> /etc/audit/audit.rules
  echo "-w /etc/localtime -p wa -k time-change" >> /etc/audit/audit.rules
fi

Ensure events that modify user/group information are collected
grep identity /etc/audit/audit.rules
if [ $? -ne 0 ]
then
  echo "-w /etc/group -p wa -k identity" >>  /etc/audit/audit.rules
  echo "-w /etc/passwd -p wa -k identity" >>  /etc/audit/audit.rules
  echo "-w /etc/gshadow -p wa -k identity" >>  /etc/audit/audit.rules
  echo "-w /etc/shadow -p wa -k identity" >>  /etc/audit/audit.rules
  echo "-w /etc/security/opasswd -p wa -k identity"  >> /etc/audit/audit.rules
fi

Ensure events that modify the system network environment are collected
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

Ensure events that modify the system Mandatory Access Controls are collected
grep MAC-policy /etc/audit/audit.rules
if [ $? -ne 0 ]
then
  echo "-w /etc/apparmor/ -p wa -k MAC-policy" >>  /etc/audit/audit.rules
  echo "-w /etc/apparmor.d/ -p wa -k MAC-policy" >>  /etc/audit/audit.rules
fi

Ensure login and logout events are collected
grep logins /etc/audit/audit.rules
if [ $? -ne 0 ]
then
  echo "-w /var/log/faillog -p wa -k logins" >>  /etc/audit/audit.rules
  echo "-w /var/log/lastlog -p wa -k logins" >>  /etc/audit/audit.rules
  echo "-w /var/log/tallylog -p wa -k logins" >>  /etc/audit/audit.rules
fi

Ensure session initiation information is collected
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

Ensure discretionary access control permission modification events are collected 
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
 
Ensure unsuccessful unauthorized file access attempts are collected
grep access /etc/audit/audit.rules
if [ $? -ne 0 ]
then
  echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >>  /etc/audit/audit.rules
  echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >>  /etc/audit/audit.rules
  echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >>  /etc/audit/audit.rules
  echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >>  /etc/audit/audit.rules
fi

Ensure successful file system mounts are collected
grep mounts /etc/audit/audit.rules
if [ $? -ne 0 ]
then
  echo "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >>  /etc/audit/audit.rules
  echo "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >>  /etc/audit/audit.rules
fi

Ensure file deletion events by users are collected
grep delete /etc/audit/audit.rules
if [ $? -ne 0 ]
then
  echo "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >>  /etc/audit/audit.rules
  echo "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >>  /etc/audit/audit.rules
fi

Ensure changes to system administration scope (sudoers) is collected
grep scope /etc/audit/audit.rules
if [ $? -ne 0 ]
then
  echo "-w /etc/sudoers -p wa -k scope" >>  /etc/audit/audit.rules
  echo "-w /etc/sudoers.d/ -p wa -k scope" >>  /etc/audit/audit.rules
fi

Ensure system administrator actions (sudolog) are collected
grep actions /etc/audit/audit.rules
if [ $? -ne 0 ]
then
  echo "-w /var/log/sudo.log -p wa -k actions" >>  /etc/audit/audit.rules
fi

Ensure kernel module loading and unloading is collected
grep modules /etc/audit/audit.rules
if [ $? -ne 0 ]
then
  echo "w /sbin/insmod -p x -k modules" >>  /etc/audit/audit.rules
  echo "-w /sbin/rmmod -p x -k modules" >>  /etc/audit/audit.rules
  echo "-w /sbin/modprobe -p x -k modules" >>  /etc/audit/audit.rules
  echo "-a always,exit -F arch=b64 -S init_module -S delete_module -k modules" >>  /etc/audit/audit.rules
fi

Ensure the audit configuration is immutable 
grep "-e 2"  /etc/audit/audit.rules
if [ $? -ne 0 ]
then
  echo "-e 2" >> /etc/audit/audit.rules
fi


























































































































  
  
  
  
  
  
  
  
  

























