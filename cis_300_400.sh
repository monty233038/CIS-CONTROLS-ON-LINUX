Ensure sshd daemon is installed 
echo -e "\e[1;31m Ensure sshd daemon is intalled \e[0m"
dpkg -s openssh-server
if [ $? -ne 0 ]
then
  echo -e "y" | openssh-server
fi

Ensure permissions on /etc/ssh/sshd_config are configured
chown root:root /etc/ssh/sshd_config
chmod og-rwx /etc/ssh/sshd_config

Ensure SSH Protocol is set to 2
a=$(grep "^Protocol" /etc/ssh/sshd_config | awk '{ print $2 }')
if [[ ! "$a" == "2" ]]
then
        sed -i '/Protocol/d' /etc/ssh/sshd_config 
        echo "Protocol 2" >> /etc/ssh/sshd_config
fi

Ensure SSH LogLevel is set to INFO 
a=$(grep "^LogLevel" /etc/ssh/sshd_config | awk '{ print $2 }')
if [[ ! "$a" == "INFO" ]]
then
        sed -i '/LogLevel/d' /etc/ssh/sshd_config 
        echo "LogLevel INFO" >> /etc/ssh/sshd_config
fi


Ensure SSH X11 forwarding is disabled
a=$(grep "^X11Forwarding" /etc/ssh/sshd_config | awk '{ print $2 }')
if [[ ! "$a" == "no" ]]
then
        sed -i '/X11Forwarding/d' /etc/ssh/sshd_config 
        echo "X11Forwarding no" >> /etc/ssh/sshd_config
fi

Ensure SSH MaxAuthTries is set to 4 or less
a=$(grep "^MaxAuthTries" /etc/ssh/sshd_config | awk '{ print $2 }')
if [[ ! "$a" == "4" ]]
then
        sed -i '/MaxAuthTries/d' /etc/ssh/sshd_config 
        echo "MaxAuthTries 4" >> /etc/ssh/sshd_config
fi

Ensure SSH IgnoreRhosts is enabled
a=$(grep "^IgnoreRhosts" /etc/ssh/sshd_config | awk '{ print $2 }')
if [[ ! "$a" == "yes" ]]
then
        sed -i '/IgnoreRhosts/d' /etc/ssh/sshd_config 
        echo "IgnoreRhosts yes" >> /etc/ssh/sshd_config
fi

Ensure SSH HostbasedAuthentication is disabled
a=$(grep "^HostbasedAuthentication" /etc/ssh/sshd_config | awk '{ print $2 }')
if [[ ! "$a" == "no" ]]
then
        sed -i '/HostbasedAuthentication/d' /etc/ssh/sshd_config 
        echo "HostbasedAuthentication no" >> /etc/ssh/sshd_config
fi

Ensure SSH root login is disabled
a=$(grep "^PermitRootLogin" /etc/ssh/sshd_config | awk '{ print $2 }')
if [[ ! "$a" == "no" ]]
then
        sed -i '/PermitRootLogin/d' /etc/ssh/sshd_config 
        echo "PermitRootLogin no" >> /etc/ssh/sshd_config
fi

Ensure SSH PermitEmptyPasswords is disabled 
a=$(grep "^PermitEmptyPasswords" /etc/ssh/sshd_config | awk '{ print $2 }')
if [[ ! "$a" == "no" ]]
then
        sed -i '/PermitEmptyPasswords/d' /etc/ssh/sshd_config 
        echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config
fi

Ensure SSH PermitUserEnvironment is disabled
a=$(grep "^PermitUserEnvironment" /etc/ssh/sshd_config | awk '{ print $2 }')
if [[ ! "$a" == "no" ]]
then
        sed -i '/PermitUserEnvironment/d' /etc/ssh/sshd_config 
        echo "PermitUserEnvironment no" >> /etc/ssh/sshd_config
fi

Ensure only approved MAC algorithms are used
sed -i '/MACs/d'  /etc/ssh/sshd_config
echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com" >> /etc/ssh/sshd_config

Ensure SSH Idle Timeout Interval is configured
a=$(grep "^ClientAliveInterval" /etc/ssh/sshd_config | awk '{ print $2 }')
if [ $a -gt 300 ]
then
        sed -i '/ClientAliveInterval/d' /etc/ssh/sshd_config 
        echo "ClientAliveInterval 300" >> /etc/ssh/sshd_config
fi

a=$(grep "^ClientAliveCountMax" /etc/ssh/sshd_config | awk '{ print $2 }')
if [ $a -gt 3 ]
then
        sed -i '/ClientAliveCountMax/d' /etc/ssh/sshd_config 
        echo "ClientAliveCountMax 0" >> /etc/ssh/sshd_config
fi

Ensure SSH LoginGraceTime is set to one minute or less
a=$(grep "^LoginGraceTime" /etc/ssh/sshd_config | awk '{ print $2 }')
if [ $a -gt 60 ]
then
        sed -i '/LoginGraceTime/d' /etc/ssh/sshd_config 
        echo "LoginGraceTime 60" >> /etc/ssh/sshd_config
fi

Ensure SSH access is limited
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

Ensure SSH warning banner is configured 
grep "^Banner" /etc/ssh/sshd_config
if [ $? -ne 0 ]
then
  echo "Banner /etc/issue.net" >>  /etc/ssh/sshd_config
fi

Ensure password creation requirements are configured
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

Ensure lockout for failed password attempts is configured
a=$(grep "pam_tally2" /etc/pam.d/common-auth | cut -c58)
if [ "$a" != "5" ]
then
        sed -i '/pam_tally2/d' /etc/pam.d/common-auth 
        echo "auth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900" >> /etc/pam.d/common-auth
fi

Ensure password reuse is limited 
a=$(egrep '^password\s+required\s+pam_pwhistory.so' /etc/pam.d/common-password | cut -c45)
if [ "$a" != "5" ]
then
        sed -i '/password\s+required\s+pam_pwhistory.so/d' /etc/pam.d/common-auth 
        echo "password required pam_pwhistory.so remember=5" >> /etc/pam.d/common-auth
fi

Ensure password hashing algorithm is SHA-512
egrep '^password\s+(\S+\s+)+pam_unix\.so\s+(\S+\s+)*sha512' /etc/pam.d/common-password 
if [ $? -ne 0 ]
  echo "password [success=1 default=ignore] pam_unix.so sha512" >> /etc/pam.d/common-password 
then

Ensure password expiration is 365 days or less
sed -i '/PASS_MAX_DAYS/d' /etc/login.defs
echo "PASS_MAX_DAYS 90" >> /etc/login.defs

for user in $(cat /etc/passwd | cut -d: -f1)
do
         chage --maxdays 90 $user
done

Ensure minimum days between password changes is 7 or more
sed -i '/PASS_MIN_DAYS/d' /etc/login.defs
echo "PASS_MIN_DAYS  7" >> /etc/login.defs 
for user in $(cat /etc/passwd | cut -d: -f1)
do
         chage --mindays 7 $user
done

Ensure password expiration warning days is 7 or more
sed -i '/PASS_WARN_AGE/d' /etc/login.defs
echo "PASS_WARN_AGE 7" >> /etc/login.defs 
for user in $(cat /etc/passwd | cut -d: -f1)
do
         chage --warndays  7 $user
done

Ensure inactive password lock is 30 days or less 
a=$(useradd -D | grep INACTIVE | cut -d= -f2)
if [[ $a -gt 30 || $a -eq -1 ]]
then
  useradd -D -f 30
fi
for user in $(cat /etc/passwd | cut -d: -f1)
do
          chage --inactive 30 $user
done

Ensure system accounts are non-login
for user in `awk -F: '($3 < 1000) {print $1 }' /etc/passwd`; do
 if [ $user != "root" ]; then
 usermod -L $user
  if [ $user != "sync" ] && [ $user != "shutdown" ] && [ $user != "halt" ];
  then
    usermod -s /usr/sbin/nologin $user
  fi
 fi
done


Ensure default group for the root account is GID 0
a=$(grep "^root:" /etc/passwd | cut -f4 -d:)
if [ $a -ne 0 ]
then
  usermod -g 0 root
fi

Ensure default user umask is 027 or more restrictive
sed -i '/umask/d'  /etc/bash.bashrc /etc/profile /etc/profile.d/*.sh 
echo "umask 027" >> /etc/bash.bashrc /etc/profile /etc/profile.d/*.sh

Ensure default user shell timeout is 900 seconds or less
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

Ensure access to the su command is restricted (
echo "auth required pam_wheel.so" >> /etc/pam.d/su
echo "sudo:x:10:root,ubuntu" >> /etc/group

Ensure permissions on /etc/passwd are configured
chown root:root /etc/passwd
chmod 644 /etc/passwd

Ensure permissions on /etc/shadow are configured
chown root:shadow /etc/shadow
chmod o-rwx,g-wx /etc/shadow

Ensure permissions on /etc/group are configured
chown root:root /etc/group
chmod 644 /etc/group

Ensure permissions on /etc/gshadow are configured
chown root:shadow /etc/gshadow
chmod o-rwx,g-rw /etc/gshadow

Ensure permissions on /etc/passwd- are configured
chown root:root /etc/passwd-
chmod u-x,go-wx /etc/passwd

Ensure permissions on /etc/shadow- are configured
chown root:shadow /etc/shadow-
chmod o-rwx,g-rw /etc/shadow-

Ensure permissions on /etc/group- are configured
chown root:root /etc/group-
chmod u-x,go-wx /etc/group

Ensure permissions on /etc/gshadow- are configured
chown root:shadow /etc/gshadow-
chmod o-rwx,g-rw /etc/gshadow-

Ensure no world writable files exist
for file in $(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -0002)
do
  chmod o-w $file
done

Ensure no unowned files or directories exist 
for file in $(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser)
do
  chown root:root $file
done

Ensure no ungrouped files or directories exist
for file in $(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nogroup)
do
  chown root:root $file
done

Ensure password fields are not empty
for user in $(cat /etc/shadow | awk -F: '($2 == "!" ) { print $1 }')
do
  passwd -l $user
do

Ensure no legacy "+" entries exist in /etc/passwd
grep '^\+:' /etc/passwd
if [ $? -eq 0 ]
then
  userdel '+'
fi

Ensure no legacy "+" entries exist in /etc/shadow
grep '^\+:' /etc/shadow
if [ $? -eq 0 ]
then
  userdel '+'
fi

Ensure no legacy "+" entries exist in /etc/group
grep '^\+:' /etc/group
if [ $? -eq 0 ]
then
  userdel '+'
fi

Ensure root is the only UID 0 account
for name in $(cat /etc/passwd | awk -F: '($3 == 0) { print $1 }')
do
  if [[ "$name" != "root" ]]
  then
    userdel $name
  fi
done

Ensure all users home directories exist
cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 != "/usr/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do 
if [ ! -d "$dir" ]; then mkdir $dir
chown $user:$user $dir
usermod -d $user
fi
done

Ensure users home directories permissions are 750 or more restrictive
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

Ensure users own their home directories
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

Ensure users dot files are not group or world writable
cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do
if [ ! -d "$dir" ]; then echo "The home directory ($dir) of user $user does not exist."
else
        for file in $dir/.[A-Za-z0-9]*
        do
                if [ ! -h "$file" -a -f "$file" ]
                then
                        fileperm=`ls -ld $dir/$file | cut -f1 -d" "`
                        if [ `echo $fileperm | cut -c6` != "-" ]
                        then
                                chmod g-w $file
                        fi
                        if [ `echo $fileperm | cut -c9` != "-" ]
                        then
                                chmod o-w $file
                        fi
                fi
        done
fi
done    


Ensure no users have .forward files
cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do
if [ ! -d "$dir" ]; then echo "The home directory ($dir) of user $user does not exist."
else
        if [ ! -h "$dir/.forward" -a -f "$dir/.forward" ]; then
                rm $dir/.forward
        fi
fi
done

Ensure no users have .netrc files 
cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do
if [ ! -d "$dir" ]; then echo "The home directory ($dir) of user $user does not exist."
else
        if [ ! -h "$dir/.netrc" -a -f "$dir/.netrc" ]; then
                rm $dir/.netrc
        fi
fi
done

Ensure users .netrc Files are not group or world accessible 
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

Ensure no users have .rhosts files 
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

Ensure all groups in /etc/passwd exist in /etc/group
for i in $(cut -s -d: -f4 /etc/passwd | sort -u ) 
do
 grep -q -P "^.*?:[^:]*:$i:" /etc/group
 if [ $? -ne 0 ]; then
         groupadd $(cat /etc/passwd | awk  -F: '($4 == $i) { print $1 }')
 fi
done

Ensure no duplicate UIDs exist
cat /etc/passwd | cut -f3 -d":" | sort -n | uniq -c | while read x ; do
[ -z "${x}" ] && break
set - $x
if [ $1 -gt 1 ]; then
users=`awk -F: '($3 == n) { print $1 }' n=$2 /etc/passwd | xargs`
userdel $(echo $users | awk '{ print $2 }')
fi
done

Ensure no duplicate GIDs exist
cat /etc/group | cut -f3 -d":" | sort -n | uniq -c | while read x ; do
 [ -z "${x}" ] && break
 set - $x
 if [ $1 -gt 1 ]; then
 groups=`awk -F: '($3 == n) { print $1 }' n=$2 /etc/group | xargs`
 groupdel $( echo $groups | awk '{ print $2 }')
 fi
done

Ensure shadow group is empty
a=$(grep ^shadow /etc/group | awk -F: '{ print $3 }')
deluser $(awk -F: '($4 == "42") { print $1 }' /etc/passwd ') shadow































 
 







































 








































































systemctl reload sshd
