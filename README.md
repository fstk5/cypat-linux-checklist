# Linux Checklist

## Other images for reference

Training round READMEs and answer keys:

- [CyPat 18 TR2 - Mint 21 README](https://www.uscyberpatriot.org/Pages/Readme/cp18_tr2_mint21_readme_93752gifdsw7ef.aspx)
- [CyPat 18 TR2 - Mint 21 Answer Key](https://cp-18.s3.us-east-1.amazonaws.com/cp18_tr2/CP18_Mint21_Training2_Answer_Key.pdf)
- [CyPat 18 TR2 - Ubuntu 22 README](https://www.uscyberpatriot.org/Pages/Readme/cp18_tr2_m_ubu22_readme_vw964wj88122.aspx)
- [CyPat 18 TR2 - Ubuntu 22 Answer Key](https://cp-18.s3.us-east-1.amazonaws.com/cp18_tr2/CP18_Ubuntu22_Training2_Answer_Key.pdf)

CyberPatriot competition image answer keys:

- [CyPat 18 R1 Answer Key](https://github.com/fstk5/cypat-linux-checklist/blob/main/CP-18%20Round%201%20Answers%20and%20Vulnerabilities.pdf)
- [CyPat 18 R2 Answer Key](https://github.com/fstk5/cypat-linux-checklist/blob/main/CP-18%20Round%202%20Answers%20and%20Vulnerabilities.pdf)

## User Account Actions

### Non-Scriptable actions

- Check for unauthorized accounts and remove them using `sudo userdel username`
- Check for unauthorized administrator accounts and strip admin permissions using one of two methods
  1. Recommended: `sudo gpasswd -d username group` (if it's an unauthorized admin, use `sudo` as the group.)
  2. Advanced: `sudo nano /etc/groups`
- Check insecure administrator passwords and change them using `sudo passwd username`
- Disable guest account (GUI)
- Create any new groups or accounts with `sudo groupadd group` or `sudo useradd username`
  - For new accounts, make sure to use `sudo passwd -e username` to force a change on login.
  - Also, for adding a user to a group, use `sudo gpasswd -a username group`

Weird subnote for this, there _could_ be a regular user with a sub-1000 UID, if this happens, you should go ask someone smart if this needs to be fixed.
Many services use sub-1000 UIDs if they need a user account, so _unless_ its a regular user account (like one somebody actually uses), you're perfectly fine.

### Scriptable actions



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

### Check FTP permissions

Last competition, we missed points on having insecure permissions for the root FTP directory (`/srv`).
This was most likely caused because of having 777 permissions or similar. Usually, for most directories, 755 is safe, except if it's a private user folder.
Generally if the directory is owned by a specific user, it should probably be 700.

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
3. Enable UFW by going into the system settings and enabling the firewall option or running `sudo ufw enable`

## sysctl related changes

### Enable IPv4 TCP SYN cookies

I'ma be honest, I got no clue what these things do. But, all you gotta do is open a superuser terminal session with `sudo -s` then run the code snippet below.

```bash
if [ -e /etc/sysctl.conf ]; then
sudo sed -i 's/^net.ipv4.tcp_syncookies.*/net.ipv4.tcp_syncookies = 1/' /etc/sysctl.conf
sudo sysctl -p
else
sudo touch /etc/sysctl.d/47-syn-cookies.conf
if [ -e /etc/sysctl.d ]; then
echo 'net.ipv4.tcp_syncookies = 1' | sudo tee /etc/sysctl.d/47-syn-cookies.conf
sudo sysctl -p
else
sudo mkdir /etc/sysctl.d
echo 'net.ipv4.tcp_syncookies = 1' | sudo tee /etc/sysctl.d/47-syn-cookies.conf
sudo sysctl -p
fi
```

### Enable ASLR

I still have no clue what this does lowk

```bash
if [ -e /etc/sysctl.conf ]; then
sudo sed -i 's/^kernel.randomize_va_space.*/kernel.randomize_va_space = 2/' /etc/sysctl.conf
sudo sysctl -p
else
sudo touch /etc/sysctl.d/38-aslr.conf
if [ -e /etc/sysctl.d ]; then
sudo mkdir /etc/sysctl.d
fi
echo 'kernel.randomize_va_space = 2' | sudo tee /etc/sysctl.d/38-aslr.conf
sudo sysctl -p
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
sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS = 30/' /etc/login.defs
sudo sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS = 7/' /etc/login.defs
```

Also, DO NOT, and I mean **DO NOT** use `chage`. If you do and mess something up (like using it on your own account), you will be locked out, your password will not work, sudo will not work, and you will have to stop scoring. Basically if you do, you're screwed.

### PAM Modules

This section relates to things such as password lengths, remembering past passwords, disallowing empty passwords, and configuring account lockout policies.
