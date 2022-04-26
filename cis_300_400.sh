Ensure sshd daemon is installed 
echo -e "\e[1;31m Ensure sshd daemon is intalled \e[0m"
dpkg -s openssh-server
if [ $? -ne 0 ]
then
  echo -e "y" | openssh-server
fi
