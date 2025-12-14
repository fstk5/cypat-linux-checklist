# Patrick Henry High School Patriots' Linux Checklist

![Logo of Patrick Henry High School](/phhs_logo.png)

## Other images for reference

### Training round READMEs and answer keys:

- [CyPat 18 TR2 - Mint 21 README](https://www.uscyberpatriot.org/Pages/Readme/cp18_tr2_mint21_readme_93752gifdsw7ef.aspx)
- [CyPat 18 TR2 - Mint 21 Answer Key](https://cp-18.s3.us-east-1.amazonaws.com/cp18_tr2/CP18_Mint21_Training2_Answer_Key.pdf)
- [CyPat 18 TR2 - Ubuntu 22 README](https://www.uscyberpatriot.org/Pages/Readme/cp18_tr2_m_ubu22_readme_vw964wj88122.aspx)
- [CyPat 18 TR2 - Ubuntu 22 Answer Key](https://cp-18.s3.us-east-1.amazonaws.com/cp18_tr2/CP18_Ubuntu22_Training2_Answer_Key.pdf)

### CyberPatriot competition image answer keys:

- [CyPat 18 R1 Answer Key](https://github.com/fstk5/cypat-linux-checklist/blob/main/CP-18%20Round%201%20Answers%20and%20Vulnerabilities.pdf)
- [CyPat 18 R2 Answer Key](https://github.com/fstk5/cypat-linux-checklist/blob/main/CP-18%20Round%202%20Answers%20and%20Vulnerabilities.pdf)

## User Account Actions

### Non-Scriptable actions

- Check for unauthorized accounts and remove them using `sudo userdel username` or the settings GUI.
- Check for unauthorized administrator accounts and strip admin permissions using one of two methods
  1. Use the Settings app to change permissions.
  2. Recommended for command-line: `sudo gpasswd -d username group` (if it's an unauthorized admin, use `sudo` as the group.)
  3. Advanced: `sudo nano /etc/groups`
- Check insecure administrator passwords and change them using `sudo passwd username` or use the GUI.
- Disable guest account (GUI)
- Create any new groups or accounts with `sudo groupadd group`, `sudo useradd username`, or the Settings app.
  - For new accounts, make sure to use `sudo passwd -e username` to force a change on login.
  - Also, for adding a user to a group, use `sudo gpasswd -a username group`

Weird subnote for this, there _could_ be a regular user with a sub-1000 UID, if this happens, you should go ask someone smart if this needs to be fixed.
Many services use sub-1000 UIDs if they need a user account, so _unless_ its a regular user account (like one somebody actually uses), you're perfectly fine.

### Scriptable actions

Things like disabling root logins are very important since these instantly give an attacker the highest level of permissions on a system.

```bash
sudo sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sudo passwd -l root
sudo chsh -s /usr/sbin/nologin
```

## Packages and files

### Update all available packages through apt

- Usually, `sudo apt update && sudo apt upgrade` is sufficient for this.
- Updates all package lists and gets new package versions from the set mirror.

### Search for unauthorized files

Before altering the directory or files, read the README file and/or forensic questions.

- When finding unauthorized files, the common directories to search are `/home` and `/srv`. The home directory holds all a users files (similar to C:\Users), and the srv directory holds all of an FTP server’s files.
- To find any of these files, use the find command, with a pipe into grep with the thing you want to find (mp3, mp4, avi, mkv, etc.)
- Example of searching the home directory for unauthorized mp3 files.
- `find /home | grep mp3` The find command lists all files in a given directory.
- The vertical line operator tells the following command to read the output of the last command.
- The grep tool is used to search long text for a line with the text requested.

### Check for unauthorized services

Usually, common services on Linux include:

- nginx (Web server)
- shd (SSH Daemon/Server)
- vsftpd (FTP Server)
- telnet (Telnet server)
- cups (CUPS print server)
- vnc !!COULD BE A DIFFERENT NAME!! (VNC server)
- rdp !!COULD BE A DIFFERENT NAME!! (RDP server)

Unless it is explicitly said in the README that it’s allowed, disable it using systemctl.
An example command of using systemctl to disable the nginx service now would be `systemctl disable --now nginx`

### Install any new, required packages

You can either use the package manager GUI (i think its called synaptic) or the apt command. Not elaborating on this.

### Enable automatic upgrades

```bash
sudo apt update && sudo apt upgrade
sudo apt install unattended-upgrades
sudo systemctl enable --now unattended-upgrades
```

## File permissions

### Check FTP permissions

Last competition, we missed points on having insecure permissions for the root FTP directory (`/srv`).
This was most likely caused because of having 777 permissions or similar. Usually, for most directories, 755 is safe, except if it's a private user folder.
Generally if the directory is owned by a specific user, it should probably be 700.

#### FTP over SSL

Not directly related to file permissions, but good practice for FTP.
All you should need to do is modify the `ssl_enable` line to equal YES.
I'm not writing a script for this since, again, modifying existing files where the value can vary is very risky.

### Check important files in /etc

Make sure /etc/shadow and /etc/passwd are set to 640 and 644, respectively.

```bash
sudo chown root:root /etc/shadow
sudo chown root:root /etc/passwd
sudo chmod 640 /etc/shadow
sudo chmod 644 /etc/passwd
```

<details>
<summary>Linux permissions breakdown</summary>
Essentially, Linux permissions are shown in one of two ways. There's <code>ls -l</code> syntax, and <code>chmod</code> syntax.
<code>ls -l</code> syntax usually looks similar to something like this: <code>-rwxr-xr-x or lrwxrwxrwx</code>.
It breaks down into 4 parts, which (from left to right) are owner indication, owner permissions, group permissions, and global permissions.
<code>chmod</code> syntax usually looks something like 777 (gambling??). 7 is the highest permission a user can have on a file.
It means read (the r), write (the w), and excecute (the x). Like <code>ls -l</code>, it has a few parts, but this only has 3 parts.
Owner permissions, group permissions, and global permissions.
This is an extremely basic overview, you should probably go to a <a href="https://chmod-calculator.com/">permissions calculator</a> to see how it actually works.
To actually write permissions, it has to be in <code>chmod</code> syntax. To write new permissions (777 will be used as an example), you would write <code>chmod 777 "file"</code>. (sudo may be required if you are not the owner of the file)
If you needed to write these changes to a folder <b>AND</b> all of its contents, you would add -R (R stands for recursive) in between the command and the permissiosn
</details>

### Check for unauthorized apps

Generally, you should be able to go through the start menu and uninstall any apps from there. This is usually all that's required.

If there is a game that **you know the name of**, you can:

1. find the **package name** of the game. This is usually done using `apt list --installed | grep "name"`
2. uninstall the package using its **package name**, using `sudo apt uninstall package`

### Check if UFW is set up

This one is simple:

1. Check if UFW is installed (run `ufw` in a terminal)
2. If it isn't installed, run `sudo apt install ufw`
3. Enable UFW by running `sudo ufw enable`

## sysctl related changes

### Enable IPv4 TCP SYN cookies

I'ma be honest, I got no clue what these things do. But, all you gotta do is open a superuser terminal session with `sudo -s` then run the code snippet below.

```bash
if [ -e /etc/sysctl.conf ]; then
sudo sed -i 's/^net.ipv4.tcp_syncookies.*/net.ipv4.tcp_syncookies = 1/' /etc/sysctl.conf
sudo sysctl --system
else
sudo touch /etc/sysctl.d/47-syn-cookies.conf
if [ -e /etc/sysctl.d ]; then
echo 'net.ipv4.tcp_syncookies = 1' | sudo tee /etc/sysctl.d/47-syn-cookies.conf
sudo sysctl --system
else
sudo mkdir /etc/sysctl.d
echo 'net.ipv4.tcp_syncookies = 1' | sudo tee /etc/sysctl.d/47-syn-cookies.conf
sudo sysctl --system
fi
```

### Enable ASLR

I still have no clue what this does lowk

```bash
if [ -e /etc/sysctl.conf ]; then
sudo sed -i 's/^kernel.randomize_va_space.*/kernel.randomize_va_space = 2/' /etc/sysctl.conf
sudo sysctl --system
else
if [ -e /etc/sysctl.d ]; then
sudo mkdir /etc/sysctl.d
fi
echo 'kernel.randomize_va_space = 2' | sudo tee /etc/sysctl.d/38-aslr.conf
sudo sysctl --system
fi
```

### Disable IPv4 forwarding

lowk im tired of writing explanations for all the scripts just ask gemini or someone smart for the explanation

```bash
if [ -e /etc/sysctl.conf ]; then
sudo sed -i 's/^net.ipv4.ip_forward.*/net.ipv4.ip_forward = 0/' /etc/sysctl.conf
sudo sysctl --system
else
if [ -e /etc/sysctl.d ]; then
sudo mkdir /etc/sysctl.d
fi
echo 'net.ipv4.ip_forward = 0' | sudo tee /etc/sysctl.d/02-ip-forward.conf
sudo sysctl --system
fi
```

## Password actions

### Ages

For this one, you can simply use your favourite command line text editor for editing the file. This example will use nano since it's (in my opinion) the easiest for anyone to use.

1. Use `sudo nano /etc/login.defs` to enter the file.
2. Use Ctrl+F and type `PASS_MAX_DAYS`
3. If the line is commented out with a #, remove the tag.
4. Set the value to something reasonable, like 30 or 90 days.
5. Use Ctrl+F again and now find `PASS_MIN_DAYS`
6. Same as 3, uncomment the line.
7. Set the value to 7 days.

or lowk just paste the cool script thingy

```bash
sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 30/w /tmp/sedcheck0.txt' /etc/login.defs
sudo sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 7/w /tmp/sedcheck1.txt' /etc/login.defs
if [ -s /tmp/sedcheck0.txt ]; then
echo 'PASS_MAX_DAYS section successfully modified!'
else
echo 'PASS_MAX_DAYS change failed!'
fi
sudo rm /tmp/sedcheck0.txt
if [ -s /tmp/sedcheck1.txt ]; then
echo 'PASS_MIN_DAYS section successfully modified!'
else
echo 'PASS_MIN_DAYS change failed!'
fi
sudo rm /tmp/sedcheck1.txt
```

Also, DO NOT, and I mean **DO NOT** use `chage`. If you do and mess something up (like using it on your own account), you will be locked out, your password will not work, sudo will not work, and you will have to stop scoring. Basically if you do, you're screwed.
Weird addition to this like a week agter i wrote this, in TR2, only the user noir needed chage to 90 days? You might want to cat the shadow file to see which ones are extremely old and do it for only those. Only try this after not being able to get anything else though.

### PAM Modules

This section relates to things such as password lengths, remembering past passwords, disallowing empty passwords, and configuring account lockout policies.

#### Non-scriptable actions

Edit `/etc/pam.d/common-password` and find the line that says `password requisite pam_pwquality.so retry=3`. Append `minlen=10` to this line and save. No script for this one since editing existing PAM files using command line options is really sketchy... stick to nano or a text editor for this one.

#### Scriptable Actions

Enabling account lockout policy script (1), enabling notifications on failed attempts (2), and disable authentication of null passwords (3).

```bash
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
elif [ -e /dev ]; then
sudo touch $TOWRITE
sudo chmod 777 $TOWRITE
echo 'Name: Enforce failed login attempt counter' | sudo tee -a $TOWRITE
echo 'Default: no' | sudo tee -a $TOWRITE
echo 'Priority: 0' | sudo tee -a $TOWRITE
echo 'Auth-Type: Primary' | sudo tee -a $TOWRITE
echo 'Auth:' | sudo tee -a $TOWRITE
echo '    [default=die] pam_faillock.so authfail' | sudo tee -a $TOWRITE
echo '    sufficient pam_faillock.so authsucc' | sudo tee -a $TOWRITE
sudo chmod 755 $TOWRITE
sudo pam-auth-update
fi
```

```bash
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
elif [ -e /dev ]; then
sudo touch $TOWRITE
sudo chmod 777 $TOWRITE
echo 'Name: Notify on failed login attempts' | sudo tee -a $TOWRITE
echo 'Default: no' | sudo tee -a $TOWRITE
echo 'Priority: 1024' | sudo tee -a $TOWRITE
echo 'Auth-Type: Primary' | sudo tee -a $TOWRITE
echo 'Auth:' | sudo tee -a $TOWRITE
echo '    requisite pam_faillock.so preauth' | sudo tee -a $TOWRITE
sudo chmod 755 $TOWRITE
sudo pam-auth-update
fi
```

`sudo sed -i 's/nullok//' /etc/pam.d/common-auth`

## Malware and viruses

### Checking open ports

Usually, a backdoor or something of the sort needs a port to recieve data. You can use `sudo ss -tulpn` to check what ports are open and if any of them are malicious. Usually, malicious ones are using either:

- a custom file
- netcat, ncat, or nc
- python
- others..

### Checking location

If it's a script or command, it can be useful to see where the file or script is located. Use `ps -aef` to list all running scripts and their cmdline options. To sort through quickly, you could also pipe it into grep if you know what language or whatever its using.

### Fixing these

Usually, these use cron to automatically restart. You can check the crontab file at `/etc/crontab`
