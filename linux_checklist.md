# Linux Checklist

### Other images for reference

Training round READMEs and answer keys:
- [CyPat 18 TR2 - Mint 21 README](https://www.uscyberpatriot.org/Pages/Readme/cp18_tr2_mint21_readme_93752gifdsw7ef.aspx)
- [CyPat 18 TR2 - Mint 21 Answer Key](https://cp-18.s3.us-east-1.amazonaws.com/cp18_tr2/CP18_Mint21_Training2_Answer_Key.pdf)
- [CyPat 18 TR2 - Ubuntu 22 README](https://www.uscyberpatriot.org/Pages/Readme/cp18_tr2_m_ubu22_readme_vw964wj88122.aspx)
- [CyPat 18 TR2 - Ubuntu 22 Answer Key](https://cp-18.s3.us-east-1.amazonaws.com/cp18_tr2/CP18_Ubuntu22_Training2_Answer_Key.pdf)

CyberPatriot competition image answer keys:
- [CyPat 18 R1 Answer Key](https://github.com/fstk5/cypat-linux-checklist/blob/main/CP-18_Round_1_Answers_and_Vulnerabilities.pdf)
- [CyPat 18 R2 Answer Key](https://github.com/fstk5/cypat-linux-checklist/blob/main/CP-18_Round_2_Answers_and_Vulnerabilities.pdf)

## Don’t paste any double quotes, single quotes are fine

### Account Related Actions (not scriptable):
 - Check for unauthorized accounts
 - Check for unauthorized administrator accounts
 - Check insecure administrator passwords
 - Disable guest account
 - Create any new groups or accounts
   - For new accounts, make sure to use `passwd -e username` to force a change on login.

Weird subnote for this, there <i>could</i> be a regular user with a sub-1000 UID, if this happens, you should go ask someone smart if this needs to be fixed.
Many services use sub-1000 UIDs if they need a user account, so <b>unless</b> its a regular user account (like one somebody actually uses), you're perfectly fine.

### Update all available packages through apt
- Usually, `sudo apt update && sudo apt upgrade` is sufficient for this.
- Updates all package lists and gets new package versions from the set mirror.
### Search for unauthorized files
- Before altering the directory or files, read the README file and/or forensic questions.
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
Unless it is explicitly said in the README that it’s allowed, disable it using systemctl

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
<code>chmod</code> syntax usually looks something like 777 (LETS GO GAMBLING). 7 is the highest permission a user can have on a file.
It means read (the r), write (the w), and excecute (the x). Like <code>ls -l</code>, it has a few parts, but this only has 3 parts.
Owner permissions, group permissions, and global permissions.
This is an extremely basic overview, you should probably go to https://chmod-calculator.com/ to see how it actually works.
To actually write permissions, it has to be in <code>chmod</code> syntax. To write new permissions (777 will be used as an example), you would write <code>chmod 777 <i>file</i></code>. (sudo may be required if you are not the owner of the file)
If you needed to write these changes to a folder <b>AND</b> all of its contents, you would add -R (R stands for recursive) in between the command and the permissiosn
</details>

### Check for unauthorized apps
Generally, you should be able to go through the start menu and uninstall any apps from there. This is usually all that's required.
If there is a game that <b>you know the name of</b>, you can:
1. find the <b>package name</b> of the game. This is usually done using <code>apt list --installed | grep <i>name</i></code>
2. uninstall the package using its <b>package name</b>, using </code>sudo apt uninstall <i>package name</i></code>


