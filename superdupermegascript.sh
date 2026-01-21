#!/bin/bash
# accumulated cypat resources from across the interwebs
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

apt update && apt full-upgrade -y && apt install unattended-upgrades
systemctl enable --now unattended-upgrades

chown root:root /etc/shadow
chown root:root /etc/passwd
chmod 640 /etc/shadow
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
sed -i 's/^net.ipv4.ip_forward.*/net.ipv4.ip_forward = 0/' /etc/sysctl.conf
sysctl --system
elif [ -e /etc/sysctl.d ]; then
echo 'net.ipv4.ip_forward = 0' | tee /etc/sysctl.d/02-ip-forward.conf
sysctl --system
else
mkdir /etc/sysctl.d
echo 'net.ipv4.ip_forward = 0' | tee /etc/sysctl.d/02-ip-forward.conf
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

snap refresh

echo "100000" > /proc/sys/net/core/netdev_max_backlog

echo "4096" > /proc/sys/net/core/somaxconn

echo "600000" > /proc/sys/net/ipv4/tcp_max_tw_buckets

echo "16777216" > /proc/sys/net/core/rmem_max
echo "16777216" > /proc/sys/net/core/rmem_default

echo "16777216" > /proc/sys/net/core/wmem_max
echo "16777216" > /proc/sys/net/core/wmem_default

echo "4096 87380 16777216" > /proc/sys/net/ipv4/tcp_rmem
echo "4096 87380 16777216" > /proc/sys/net/ipv4/tcp_wmem

echo "0" > /proc/sys/net/ipv4/tcp_sack
echo "0" > /proc/sys/net/ipv4/tcp_dsack

echo "1" > /proc/sys/net/ipv4/tcp_no_metrics_save

echo "5" > /proc/sys/net/ipv4/tcp_retries2

echo "120" > /proc/sys/net/ipv4/tcp_keepalive_time

echo "30" > /proc/sys/net/ipv4/tcp_keepalive_intvl

echo "3" > /proc/sys/net/ipv4/tcp_keepalive_probes

echo "30" > /proc/sys/net/ipv4/tcp_fin_timeout

echo "15" > /proc/sys/net/ipv4/tcp_reordering

echo "cubic" > /proc/sys/net/ipv4/tcp_congestion_control

echo "0" > /proc/sys/fs/suid_dumpable

echo "1" > /proc/sys/kernel/exec-shield
echo "1" > /proc/sys/kernel/randomize_va_space


echo "0" > /proc/sys/net/ipv4/ip_forward
echo "0" > /proc/sys/net/ipv4/conf/all/send_redirects
echo "0" > /proc/sys/net/ipv4/conf/default/send_redirects

echo "1" > /proc/sys/net/ipv4/tcp_syncookies

echo "0" > /proc/sys/net/ipv4/conf/all/accept_source_route
echo "0" > /proc/sys/net/ipv4/conf/default/accept_source_route
echo "0" > /proc/sys/net/ipv4/conf/all/accept_redirects
echo "0" > /proc/sys/net/ipv4/conf/default/accept_redirects
echo "0" > /proc/sys/net/ipv4/conf/all/secure_redirects 
echo "0" > /proc/sys/net/ipv4/conf/default/secure_redirects 

echo "1" > /proc/sys/net/ipv4/conf/all/log_martians

echo "1" > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts

echo "1" > /proc/sys/net/ipv4/conf/all/rp_filter
echo "1" > /proc/sys/net/ipv4/conf/default/rp_filter

echo "5000 65535" > /proc/sys/net/ipv4/ip_local_port_range


echo "1" > /proc/sys/net/ipv6/conf/all/disable_ipv6
echo "1" > /proc/sys/net/ipv6/conf/default/disable_ipv6

echo "7930900" > /proc/sys/fs/file-max

echo "65536" > /proc/sys/kernel/pid_max

echo "5" > /proc/sys/vm/swappiness

echo "20" > /proc/sys/vm/dirty_background_ratio

echo "25" > /proc/sys/vm/dirty_ratio

sys_upgrades() {
    apt-get --yes --force-yes update
    apt-get --yes --force-yes upgrade
    apt-get --yes --force-yes autoremove
    apt-get --yes --force-yes autoclean
}

unattended_upg() {
    # IMPORTANT - Unattended upgrades may cause issues
    # But it is known that the benefits are far more than
    # downsides
    apt-get --yes --force-yes install unattended-upgrades
    dpkg-reconfigure -plow unattended-upgrades
    # This will create the file /etc/apt/apt.conf.d/20auto-upgrades
    # with the following contents:
    #############
    # APT::Periodic::Update-Package-Lists "1";
    # APT::Periodic::Unattended-Upgrade "1";
    #############
}

disable_root() {
    passwd -l root
    # for any reason if you need to re-enable it:
    # passwd -l root
}

purge_telnet() {
    # Unless you need to specifically work with telnet, purge it
    # less layers = more sec
    apt-get --yes purge telnet
}

purge_nfs() {
    # This the standard network file sharing for Unix/Linux/BSD
    # style operating systems.
    # Unless you require to share data in this manner,
    # less layers = more sec
    apt-get --yes purge nfs-kernel-server nfs-common portmap rpcbind autofs
}

purge_whoopsie() {
    # Although whoopsie is useful(a crash log sender to ubuntu)
    # less layers = more sec
    apt-get --yes purge whoopsie
}

set_chkrootkit() {
    apt-get --yes install chkrootkit
    chkrootkit
    }

disable_compilers() {
    chmod 000 /usr/bin/byacc
    chmod 000 /usr/bin/yacc
    chmod 000 /usr/bin/bcc
    chmod 000 /usr/bin/kgcc
    chmod 000 /usr/bin/cc
    chmod 000 /usr/bin/gcc
    chmod 000 /usr/bin/*c++
    chmod 000 /usr/bin/*g++
    # 755 to bring them back online
    # It is better to restrict access to them
    # unless you are working with a specific one
}

firewall() {
    ufw allow ssh
    ufw allow http
    ufw deny 23
    ufw default deny
    ufw enable
    }

harden_ssh_brute() {
    # Many attackers will try to use your SSH server to brute-force passwords.
    # This will only allow 6 connections every 30 seconds from the same IP address.
    ufw limit OpenSSH
}

harden_ssh(){
    sh -c 'echo "PermitRootLogin no" >> /etc/ssh/ssh_config'
}

logwatch_reporter() {
    apt-get --yes --force-yes install logwatch
    # make it run weekly
    cd /
    mv /etc/cron.daily/00logwatch /etc/cron.weekly/
    cd
}

purge_atd() {
    apt-get --yes purge at
    # less layers equals more security
}

disable_avahi() {
    # The Avahi daemon provides mDNS/DNS-SD discovery support
    # (Bonjour/Zeroconf) allowing applications to discover services on the network.
    update-rc.d avahi-daemon disable
}

process_accounting() {
    # Linux process accounting keeps track of all sorts of details about which commands have been run on the server, who ran them, when, etc.
    apt-get --yes --force-yes install acct
    cd /
    touch /var/log/wtmp
    cd
    # To show users' connect times, run ac. To show information about commands previously run by users, run sa. To see the last commands run, run lastcomm.
    }
kernel_tuning() {
    sysctl kernel.randomize_va_space=1
    
    # Enable IP spoofing protection
    sysctl net.ipv4.conf.all.rp_filter=1

    # Disable IP source routing
    sysctl net.ipv4.conf.all.accept_source_route=0
    
    # Ignoring broadcasts request
    sysctl net.ipv4.icmp_echo_ignore_broadcasts=1
        
    # Make sure spoofed packets get logged
    sysctl net.ipv4.conf.all.log_martians=1
    sysctl net.ipv4.conf.default.log_martians=1

    # Disable ICMP routing redirects
    sysctl -w net.ipv4.conf.all.accept_redirects=0
    sysctl -w net.ipv6.conf.all.accept_redirects=0
    sysctl -w net.ipv4.conf.all.send_redirects=0

    # Disables the magic-sysrq key
    sysctl kernel.sysrq=0
    
    # Turn off the tcp_timestamps
    sysctl net.ipv4.tcp_timestamps=0

    # Enable TCP SYN Cookie Protection
    sysctl net.ipv4.tcp_syncookies=1

    # Enable bad error message Protection
    sysctl net.ipv4.icmp_ignore_bogus_error_responses=1
    
    # RELOAD WITH NEW SETTINGS
    sysctl -p
}

main() {
    sys_upgrades
    unattended_upg
    disable_root
    purge_telnet
    purge_nfs
    purge_whoopsie
    set_chkrootkit
    disable_compilers
    firewall
    harden_ssh_brute
    harden_ssh
    logwatch_reporter
    process_accounting
    purge_atd
    disable_avahi
    kernel_tuning
}

main "$@"

unalias -a #Get rid of aliases
echo "unalias -a" >> ~/.bashrc
echo "unalias -a" >> /root/.bashrc
PWDthi=$(pwd)
if [ ! -d $PWDthi/referenceFiles ]; then
	echo "Please Cd into this script's directory"
	exit
fi
if [ "$EUID" -ne 0 ] ;
	then echo "Run as Root"
	exit
fi
#List of Functions:
#PasswdFun
#zeroUidFun
#rootCronFun
#apacheSecFun
#fileSecFun
#netSecFun
#aptUpFun
#aptInstFun
#deleteFileFun
#firewallFun
#sysCtlFun
#scanFun
startFun()
{
	clear

	PasswdFun
	zeroUidFun
	rootCronFun
	apacheSecFun
	fileSecFun
	netSecFun
	aptUpFun
	aptInstFun
	deleteFileFun
	# firewallFun
	sysCtlFun
	scanFun
	printf "\033[1;31mDone!\033[0m\n"
}
cont(){
	printf "\033[1;31mI have finished this task. Continue to next Task? (Y/N)\033[0m\n"
	read contyn
	if [ "$contyn" = "N" ] || [ "$contyn" = "n" ]; then
		printf "\033[1;31mAborted\033[0m\n"
		exit
	fi
	clear
}
PasswdFun(){
	printf "\033[1;31mChanging Root's Password..\033[0m\n"
	#--------- Change Root Password ----------------
	passwd -l root
	echo "Please change other user's passwords too"
	cont
}
zeroUidFun(){
	printf "\033[1;31mChecking for 0 UID users...\033[0m\n"
	#--------- Check and Change UID's of 0 not Owned by Root ----------------
	touch /zerouidusers
	touch /uidusers

	cut -d: -f1,3 /etc/passwd | egrep ':0$' | cut -d: -f1 | grep -v root > /zerouidusers

	if [ -s /zerouidusers ]
	then
		echo "There are Zero UID Users! I'm fixing it now!"

		while IFS='' read -r line || [[ -n "$line" ]]; do
			thing=1
			while true; do
				rand=$(( ( RANDOM % 999 ) + 1000))
				cut -d: -f1,3 /etc/passwd | egrep ":$rand$" | cut -d: -f1 > /uidusers
				if [ -s /uidusers ]
				then
					echo "Couldn't find unused UID. Trying Again... "
				else
					break
				fi
			done
			usermod -u $rand -g $rand -o $line
			touch /tmp/oldstring
			old=$(grep "$line" /etc/passwd)
			echo $old > /tmp/oldstring
			sed -i "s~0:0~$rand:$rand~" /tmp/oldstring
			new=$(cat /tmp/oldstring)
			sed -i "s~$old~$new~" /etc/passwd
			echo "ZeroUID User: $line"
			echo "Assigned UID: $rand"
		done < "/zerouidusers"
		update-passwd
		cut -d: -f1,3 /etc/passwd | egrep ':0$' | cut -d: -f1 | grep -v root > /zerouidusers

		if [ -s /zerouidusers ]
		then
			echo "WARNING: UID CHANGE UNSUCCESSFUL!"
		else
			echo "Successfully Changed Zero UIDs!"
		fi
	else
		echo "No Zero UID Users"
	fi
	cont
}
rootCronFun(){
	printf "\033[1;31mChanging cron to only allow root access...\033[0m\n"
	
	#--------- Allow Only Root Cron ----------------
	#reset crontab
	crontab -r
	cd /etc/
	/bin/rm -f cron.deny at.deny
	echo root >cron.allow
	echo root >at.allow
	/bin/chown root:root cron.allow at.allow
	/bin/chmod 644 cron.allow at.allow
	cont
}
apacheSecFun(){
	printf "\033[1;31mSecuring Apache...\033[0m\n"
	#--------- Securing Apache ----------------
	a2enmod userdir

	chown -R root:root /etc/apache2
	chown -R root:root /etc/apache

	if [ -e /etc/apache2/apache2.conf ]; then
		echo "<Directory />" >> /etc/apache2/apache2.conf
		echo "        AllowOverride None" >> /etc/apache2/apache2.conf
		echo "        Order Deny,Allow" >> /etc/apache2/apache2.conf
		echo "        Deny from all" >> /etc/apache2/apache2.conf
		echo "</Directory>" >> /etc/apache2/apache2.conf
		echo "UserDir disabled root" >> /etc/apache2/apache2.conf
	fi

	systemctl restart apache2.service
	cont
}
fileSecFun(){
	printf "\033[1;31mSome automatic file inspection...\033[0m\n"
	#--------- Manual File Inspection ----------------
	cut -d: -f1,3 /etc/passwd | egrep ':[0-9]{4}$' | cut -d: -f1 > /tmp/listofusers
	echo root >> /tmp/listofusers
	
	#Replace sources.list with safe reference file (For Ubuntu 14 Only)
	cat $PWDthi/referenceFiles/sources.list > /etc/apt/sources.list
	apt-get update

	#Replace lightdm.conf with safe reference file
	cat $PWDthi/referenceFiles/lightdm.conf > /etc/lightdm/lightdm.conf

	#Replace sshd_config with safe reference file
	cat $PWDthi/referenceFiles/sshd_config > /etc/ssh/sshd_config
	/usr/sbin/sshd -t
	systemctl restart sshd.service

	#/etc/rc.local should be empty except for 'exit 0'
	echo 'exit 0' > /etc/rc.local

	printf "\033[1;31mFinished automatic file inspection. Continue to manual file inspection? (Y/N)\033[0m\n"
	read contyn
	if [ "$contyn" = "N" ] || [ "$contyn" = "n" ]; then
		exit
	fi
	clear

	printf "\033[1;31mSome manual file inspection...\033[0m\n"

	#Manual File Inspection
	nano /etc/resolv.conf #make sure if safe, use 8.8.8.8 for name server
	nano /etc/hosts #make sure is not redirecting
	visudo #make sure sudoers file is clean. There should be no "NOPASSWD"
	nano /tmp/listofusers #No unauthorized users

	cont
}
netSecFun(){ 
	printf "\033[1;31mSome manual network inspection...\033[0m\n"
	#--------- Manual Network Inspection ----------------
	lsof -i -n -P
	netstat -tulpn
	cont
}
aptUpFun(){
	printf "\033[1;31mUpdating computer...\033[0m\n"
	#--------- Update Using Apt-Get ----------------
	#apt-get update --no-allow-insecure-repositories
	apt-get update
	apt-get dist-upgrade -y
	apt-get install -f -y
	apt-get autoremove -y
	apt-get autoclean -y
	apt-get check
	cont
}
aptInstFun(){
	printf "\033[1;31mInstalling programs...\033[0m\n"
	#--------- Download programs ----------------
	apt-get install -y chkrootkit clamav rkhunter apparmor apparmor-profiles
}
deleteFileFun(){
	printf "\033[1;31mDeleting dangerous files...\033[0m\n"
	#--------- Delete Dangerous Files ----------------
	find / -name '*.mp3' -type f -delete
	find / -name '*.mov' -type f -delete
	find / -name '*.mp4' -type f -delete
	find / -name '*.avi' -type f -delete
	find / -name '*.mpg' -type f -delete
	find / -name '*.mpeg' -type f -delete
	find / -name '*.flac' -type f -delete
	find / -name '*.m4a' -type f -delete
	find / -name '*.flv' -type f -delete
	find / -name '*.ogg' -type f -delete
	find /home -name '*.gif' -type f -delete
	find /home -name '*.png' -type f -delete
	find /home -name '*.jpg' -type f -delete
	find /home -name '*.jpeg' -type f -delete
	cd / && ls -laR 2> /dev/null | grep rwxrwxrwx | grep -v "lrwx" &> /tmp/777s
	cont

	printf "\033[1;31m777 (Full Permission) Files : \033[0m\n"
	printf "\033[1;31mConsider changing the permissions of these files\033[0m\n"
	cat /tmp/777s
	cont
}
firewallFun(){
	printf "\033[1;31mSetting up firewall...\033[0m\n"
	#--------- Setup Firewall ----------------
	#Please verify that the firewall wont block any services, such as an Email server, when defaulted.
	#I will back up iptables for you in and put it in /iptables/rules.v4.bak and /iptables/rules.v6.bak
	#Uninstall UFW and install iptables
	apt-get remove -y ufw
	apt-get install -y iptables
	apt-get install -y iptables-persistent
	#Backup
	mkdir /iptables/
	touch /iptables/rules.v4.bak
	touch /iptables/rules.v6.bak
	iptables-save > /iptables/rules.v4.bak
	ip6tables-save > /iptables/rules.v6.bak
	#Clear out and default iptables
	iptables -t nat -F
	iptables -t mangle -F
	iptables -t nat -X
	iptables -t mangle -X
	iptables -F
	iptables -X
	iptables -P INPUT DROP
	iptables -P FORWARD DROP
	iptables -P OUTPUT ACCEPT
	ip6tables -t nat -F
	ip6tables -t mangle -F
	ip6tables -t nat -X
	ip6tables -t mangle -X
	ip6tables -F
	ip6tables -X
	ip6tables -P INPUT DROP
	ip6tables -P FORWARD DROP
	ip6tables -P OUTPUT DROP
	#Block Bogons
	printf "\033[1;31mEnter primary internet interface: \033[0m\n"
	read interface
	#Blocks bogons going into the computer
	iptables -A INPUT -s 127.0.0.0/8 -i $interface -j DROP
	iptables -A INPUT -s 0.0.0.0/8 -j DROP
	iptables -A INPUT -s 100.64.0.0/10 -j DROP
	iptables -A INPUT -s 169.254.0.0/16 -j DROP
	iptables -A INPUT -s 192.0.0.0/24 -j DROP
	iptables -A INPUT -s 192.0.2.0/24 -j DROP
	iptables -A INPUT -s 198.18.0.0/15 -j DROP
	iptables -A INPUT -s 198.51.100.0/24 -j DROP
	iptables -A INPUT -s 203.0.113.0/24 -j DROP
	iptables -A INPUT -s 224.0.0.0/3 -j DROP
	#Blocks bogons from leaving the computer
	iptables -A OUTPUT -d 127.0.0.0/8 -o $interface -j DROP
	iptables -A OUTPUT -d 0.0.0.0/8 -j DROP
	iptables -A OUTPUT -d 100.64.0.0/10 -j DROP
	iptables -A OUTPUT -d 169.254.0.0/16 -j DROP
	iptables -A OUTPUT -d 192.0.0.0/24 -j DROP
	iptables -A OUTPUT -d 192.0.2.0/24 -j DROP
	iptables -A OUTPUT -d 198.18.0.0/15 -j DROP
	iptables -A OUTPUT -d 198.51.100.0/24 -j DROP
	iptables -A OUTPUT -d 203.0.113.0/24 -j DROP
	iptables -A OUTPUT -d 224.0.0.0/3 -j DROP
	#Blocks outbound from source bogons - A bit overkill
	iptables -A OUTPUT -s 127.0.0.0/8 -o $interface -j DROP
	iptables -A OUTPUT -s 0.0.0.0/8 -j DROP
	iptables -A OUTPUT -s 100.64.0.0/10 -j DROP
	iptables -A OUTPUT -s 169.254.0.0/16 -j DROP
	iptables -A OUTPUT -s 192.0.0.0/24 -j DROP
	iptables -A OUTPUT -s 192.0.2.0/24 -j DROP
	iptables -A OUTPUT -s 198.18.0.0/15 -j DROP
	iptables -A OUTPUT -s 198.51.100.0/24 -j DROP
	iptables -A OUTPUT -s 203.0.113.0/24 -j DROP
	iptables -A OUTPUT -s 224.0.0.0/3 -j DROP
	#Block receiving bogons intended for bogons - Super overkill
	iptables -A INPUT -d 127.0.0.0/8 -i $interface -j DROP
	iptables -A INPUT -d 0.0.0.0/8 -j DROP
	iptables -A INPUT -d 100.64.0.0/10 -j DROP
	iptables -A INPUT -d 169.254.0.0/16 -j DROP
	iptables -A INPUT -d 192.0.0.0/24 -j DROP
	iptables -A INPUT -d 192.0.2.0/24 -j DROP
	iptables -A INPUT -d 198.18.0.0/15 -j DROP
	iptables -A INPUT -d 198.51.100.0/24 -j DROP
	iptables -A INPUT -d 203.0.113.0/24 -j DROP
	iptables -A INPUT -d 224.0.0.0/3 -j DROP
	iptables -A INPUT -i lo -j ACCEPT
	#Least Strict Rules
	#iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
	#Strict Rules -- Only allow well known ports (1-1022)
	#iptables -A INPUT -p tcp --match multiport --sports 1:1022 -m conntrack --ctstate ESTABLISHED -j ACCEPT
	#iptables -A INPUT -p udp --match multiport --sports 1:1022 -m conntrack --ctstate ESTABLISHED -j ACCEPT
	#iptables -A OUTPUT -p tcp --match multiport --dports 1:1022 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
	#iptables -A OUTPUT -p udp --match multiport --dports 1:1022 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
	#iptables -A OUTPUT -o lo -j ACCEPT
	#iptables -P OUTPUT DROP
	#Very Strict Rules - Only allow HTTP/HTTPS, NTP and DNS
	iptables -A INPUT -p tcp --sport 80 -m conntrack --ctstate ESTABLISHED -j ACCEPT
	iptables -A INPUT -p tcp --sport 443 -m conntrack --ctstate ESTABLISHED -j ACCEPT
	iptables -A INPUT -p tcp --sport 53 -m conntrack --ctstate ESTABLISHED -j ACCEPT
	iptables -A INPUT -p udp --sport 53 -m conntrack --ctstate ESTABLISHED -j ACCEPT
	iptables -A OUTPUT -p tcp --dport 80 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
	iptables -A OUTPUT -p tcp --dport 443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
	iptables -A OUTPUT -p tcp --dport 53 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
	iptables -A OUTPUT -p udp --dport 53 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
	iptables -A OUTPUT -o lo -j ACCEPT
	iptables -P OUTPUT DROP
	mkdir /etc/iptables/
	touch /etc/iptables/rules.v4
	touch /etc/iptables/rules.v6
	iptables-save > /etc/iptables/rules.v4
	ip6tables-save > /etc/iptables/rules.v6
	cont
}
sysCtlFun(){
	printf "\033[1;31mMaking Sysctl Secure...\033[0m\n"
	#--------- Secure /etc/sysctl.conf ----------------
	sysctl -w net.ipv4.tcp_syncookies=1
	sysctl -w net.ipv4.ip_forward=0
	sysctl -w net.ipv4.conf.all.send_redirects=0
	sysctl -w net.ipv4.conf.default.send_redirects=0
	sysctl -w net.ipv4.conf.all.accept_redirects=0
	sysctl -w net.ipv4.conf.default.accept_redirects=0
	sysctl -w net.ipv4.conf.all.secure_redirects=0
	sysctl -w net.ipv4.conf.default.secure_redirects=0
	sysctl -p
	cont
}
scanFun(){
	printf "\033[1;31mScanning for Viruses...\033[0m\n"
	#--------- Scan For Vulnerabilities and viruses ----------------

	#chkrootkit
	printf "\033[1;31mStarting CHKROOTKIT scan...\033[0m\n"
	chkrootkit -q
	cont

	#Rkhunter
	printf "\033[1;31mStarting RKHUNTER scan...\033[0m\n"
	rkhunter --update
	rkhunter --propupd #Run this once at install
	rkhunter -c --enable all --disable none
	cont
	
	#Lynis
	printf "\033[1;31mStarting LYNIS scan...\033[0m\n"
	cd /usr/share/lynis/
	/usr/share/lynis/lynis update info
	/usr/share/lynis/lynis audit system
	cont
	
	#ClamAV
	printf "\033[1;31mStarting CLAMAV scan...\033[0m\n"
	systemctl stop clamav-freshclam
	freshclam --stdout
	systemctl start clamav-freshclam
	clamscan -r -i --stdout --exclude-dir="^/sys" /
	cont
}

repoFun(){
	read -p "Please check the repo for any issues [Press any key to continue...]" -n1 -s
	nano /etc/apt/sources.list
	gpg /etc/apt/trusted.gpg > /tmp/trustedGPG
	printf "\033[1;31mPlease check /tmp/trustedGPG for trusted GPG keys\033[0m\n"
	cont
}

startFun

# Malware
apt-get -y purge hydra*
apt-get -y purge john*
apt-get -y purge nikto*
apt-get -y purge netcat*

# Media Files
for suffix in mp3 txt wav wma aac mp4 mov avi gif jpg png bmp img exe msi bat sh
do
  find /home -name *.$suffix
done

# Disable anonymous uploads
sed -i '/^anon_upload_enable/ c\anon_upload_enable no' /etc/vsftpd.conf
sed -i '/^anonymous_enable/ c\anonymous_enable=NO' /etc/vsftpd.conf
# FTP user directories use chroot
sed -i '/^chroot_local_user/ c\chroot_local_user=YES' /etc/vsftpd.conf
systemctl restart vsftpd