#!/bin/bash

if [ $EUID = 0 ]; then
echo "ARE YOU READY"
sleep 2
echo "TO"
sleep 2
echo "RUUUUUUUUUUUUUUUUUUUUUUUUUUUMBLE"
sleep 1
else
echo "hb i need them root perms use that sweet sweet sudo brochacho"
return 1
fi

sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
passwd -l root
chsh -s /usr/sbin/nologin root

apt update && apt upgrade && apt install unattended-upgrades
systemctl enable --now unattended-upgrades

chown root:root /etc/shadow
chown root:root /etc/passwd
chown 640 /etc/shadow
chmod 644 /etc/passwd

apt install ufw
systemctl enable --now ufw
ufw enable

if [ -e /etc/sysctl.conf ]; then
sed -i 's/^net.ipv4.tcp_syncookies.*/net.ipv4.tcp_syncookies = 1/' /etc/sysctl.conf
sysctl --system
elif [ -e /etc/sysctl.d ]; then
echo 'net.ipv4.tcp_syncookies = 1' | tee /etc/sysctl.d/47-syn-cookies.conf
sysctl --system
else
mkdir /etc/sysctl.d
echo 'net.ipv4.tcp_syncookies = 1' | tee /etc/sysctl.d/47-syn-cookies.conf
sysctl --system
fi

if [ -e /etc/sysctl.conf ]; then
sed -i 's/^kernel.randomize_va_space.*/kernel.randomize_va_space = 2/' /etc/sysctl.conf
sysctl --system
elif [ -e /etc/sysctl.d ]; then
echo 'kernel.randomize_va_space = 2' | tee /etc/sysctl.d/38-aslr.conf
sysctl --system
else
mkdir /etc/sysctl.d
echo 'kernel.randomize_va_space = 2' | tee /etc/sysctl.d/38-aslr.conf
sysctl --system
fi

sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 30/w /tmp/sedcheck0.txt' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 7/w /tmp/sedcheck1.txt' /etc/login.defs
if [ -s /tmp/sedcheck0.txt ]; then
echo 'PASS_MAX_DAYS section successfully modified!'
else
echo 'PASS_MAX_DAYS change failed!'
fi
if [ -s /tmp/sedcheck1.txt ]; then
echo 'PASS_MIN_DAYS section successfully modified!'
else
echo 'PASS_MIN_DAYS change failed!'
fi
rm /tmp/sedcheck0.txt
rm /tmp/sedcheck1.txt

export TOWRITE=/usr/share/pam-configs/faillock
if [ -e $TOWRITE ]; then
echo "uhh it exists i recommend that you go in and edit this manually."
echo "here's what you need to write:"
echo 'Name: Enforce failed login attempt counter'
echo 'Default: no'
echo 'Priority: 0'
echo 'Auth-Type: Primary'
echo 'Auth:'
echo '    [default=die] pam_faillock.so authfail'
echo '    sufficient pam_faillock.so authsucc'
else
touch $TOWRITE
chmod 777 $TOWRITE
echo 'Name: Enforce failed login attempt counter' | tee -a $TOWRITE
echo 'Default: no' | tee -a $TOWRITE
echo 'Priority: 0' | tee -a $TOWRITE
echo 'Auth-Type: Primary' | tee -a $TOWRITE
echo 'Auth:' | tee -a $TOWRITE
echo '    [default=die] pam_faillock.so authfail' | tee -a $TOWRITE
echo '    sufficient pam_faillock.so authsucc' | tee -a $TOWRITE
chmod 755 $TOWRITE
pam-auth-update
fi

export TOWRITE=/usr/share/pam-configs/faillock_notify
if [ -e $TOWRITE ]; then
echo "uhh it exists i recommend that you go in and edit this manually."
echo "here's what you need to write:"
echo 'Name: Notify on failed login attempts'
echo 'Default: no'
echo 'Priority: 1024'
echo 'Auth-Type: Primary'
echo 'Auth:'
echo '    requisite pam_faillock.so preauth'
else
touch $TOWRITE
chmod 777 $TOWRITE
echo 'Name: Notify on failed login attempts' | tee -a $TOWRITE
echo 'Default: no' | tee -a $TOWRITE
echo 'Priority: 1024' | tee -a $TOWRITE
echo 'Auth-Type: Primary' | tee -a $TOWRITE
echo 'Auth:' | tee -a $TOWRITE
echo '    requisite pam_faillock.so preauth' | tee -a $TOWRITE
chmod 755 $TOWRITE
pam-auth-update
fi

sed -i 's/nullok//' /etc/pam.d/common-auth