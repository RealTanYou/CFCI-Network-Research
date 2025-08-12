#!/bin/bash

# Project creator: Tan You
# Project created during the Centre for Cybersecurity Insitute Training Programme


# How this code will proceed
# Step 1: Installations and Anonymity Check
# 1.1) check for installed packages. if not there, install them
# List of packages to install:
# "ssh", "sshpass", "nmap", "perl", "perl-doc", "cpan", "cpanminus", "nipe"
# 1.2) check if connection is anonymous. if not, enable nipe.
# 1.3) once anonymous, display spoofed country name.
# 1.4) Get the ip address or URL to do a whois on. It can also be a list of them.
# Step 2: Automatically Scan the Remote Server for open ports.
# 2.1) Once scanned, find the ssh port number and connect to it
# 2.2) Display the details of the remote server (country, Public IP, and Uptime)
# 2.3) Get the remote server to check the Whois of the given addresses/URLs
# Step 3: Results
# 3.1) Save the whois results into their respective files, labeled with their ip/url
# 3.2) Using a INSECURE protocol e.g. ftp, retrieve the files from the remote server.
# 3.3) Create a log and audit your data collection; save the log locally.

# This code checks if the script is being run as root. if not, exit.
if [ "$EUID" -ne 0 ]; then
    echo "Root/Superuser privileges are required to run this script."
    exit
fi

declare -a tools_to_check=("ssh" "sshpass" "nmap" "geoiplookup" "whois" "perl" "perl-doc" "cpan" "cpanm" "git")
declare -A commands_to_install=(["ssh"]="ssh"
["sshpass"]="sshpass"
["nmap"]="nmap"
["geoiplookup"]="geoip-bin"
["whois"]="whois"
["perl"]="perl"
["perl-doc"]="perl-doc"
["cpan"]="cpan"
["cpanm"]="cpanminus"
["git"]="git-all")
declare -a ips_to_check
declare hostname
declare remote_server="192.168.152.130"
declare ssh_port_num
declare ftp_port_num
declare logfile_location="/var/log/CCK_NR_250506_s29.log"
declare nipe_directory
declare current_directory="$(pwd)"
declare remote_script_file="remote_script.txt"
declare remote_script="
echo \"--------------------------------------------------\"\n
echo \"[#] Public IP of remote server is\"\n
pub_ip=\"\$(curl -s https://ipinfo.io/ip)\"\n
echo \$pub_ip\n
echo \"[#] Country of remote server is:\"\n
geoiplookup \$pub_ip\n
echo \"[#] Uptime of remote server is:\"\n
uptime -p\n
echo \"--------------------------------------------------\"\n
mkdir whois_results\n
cd whois_results\n
rm -r *\n
echo \"[#] Running whois now...\"
"
#make the log file if it doesn't exist:
if [ ! -f "$logfile_location" ]; then
    echo "[!] Log file not found! making" $logfile_location
    touch $logfile_location
fi


log_output(){
    # for anything done in this script, append them into the log file
    # formatted appropriately for easy reading.
    info=$1
    log_input="$(date -u '+%a %F %T:%N %Z')"": "$info
    sudo echo $log_input >> $logfile_location
}

check_installed() {
    # given the name of the tool, check if it is installed.
    # if not, then install it.
    tool=$1
    log_output "checking if $tool is installed."
    is_it_installed="$(command -v $tool)"
    if [ -z "$is_it_installed" ]; then
        echo "[#]" $tool "is not installed. installing..."
        sudo apt-get -qq install ${commands_to_install[$tool]} > /dev/null
        echo "[#]" $tool "is now installed."
        log_output "$tool is now installed."
    else
        echo "[#]" $tool "is already installed."
        log_output "$tool is already installed."
    fi
    echo "--------------------------------------------------" 
}

check_whois(){
    # given the ip address, check the whois of that ip.
    # then make a file related to the hostname of the ip,
    # and save the whois results into it
    # note: the file will be created and saved where this
    # bash file is run.
    ip=$1
    filename=$2
    log_output "Checking whois of $ip"
    echo "echo "[#] Checking whois of" $ip" >> $filename
    echo "result=\"\$(whois $ip)\"" >> $filename
    #hostname="$(echo $result | grep -i "domain name:" | awk '{print $3}')"
    #if [ -z $hostname ]; then
    #    hostname=$ip
    #fi
    #echo $hostname
    echo "echo -e \"\$result\" > $ip".whois.lst"" >> $filename
    echo "echo "[#] whois result stored in" $ip".whois.lst"" >> $filename
    log_output "whois result stored in $ip.whois.lst"
    #log_output "whois result stored in $hostname.whois.lst"
}

check_nmap(){
    ip=$1
    # given the ip address, check the nmap of that ip,
    # checking common services and ports
    # then make a file related to the hostname of the ip,
    # and save the whois results into it
    # note: the file will be created and saved where this
    # bash file is run.
    log_output "Running nmap of $ip" 
    echo "[#] Running nmap of" $ip
    nmap -A -sV -v0 $ip -p- -oG $hostname".nmap.lst"
    echo "[#] nmap result stored in" $hostname".nmap.lst"
    echo "--------------------------------------------------"
    log_output "nmap result stored in $hostname.nmap.lst"
}
# Step 1: Installations and Anonymity Check
# 1.1) check for installed packages. if not there, install them
# List of packages to install:
# "ssh", "sshpass", "nmap", "perl", "perl-doc", "cpan", "cpanminus", "nipe"
echo "Logging enabled. Logs stored in" $logfile_location
echo "[#] Updating repositories first."
sudo apt-get -qq update 2>/dev/null
echo "[#] Updated repositories"
echo "--------------------------------------------------" 
for tool in "${tools_to_check[@]}"
do
    check_installed $tool
done
# note: for nipe, this has be installed and checked with specific code,
# as the files come from git rather than apt.
tool="nipe"
log_output "checking if $tool is installed."
is_it_installed="$(perldoc -l Config::Simple 2>&1)"
echo $is_it_installed
if [[ "$is_it_installed" =~ "No documentation found for" ]]; then
    echo "[#]" $tool "is not installed. installing..."
    git clone "https://github.com/htrgouvea/nipe"
    cd "nipe"
    yes | sudo cpanm --installdeps .
    yes | sudo cpan install Try::Tiny Config::Simple JSON
    yes | sudo perl nipe.pl install
    nipe_directory=$(pwd)
    cd ..
    echo "[#]" $tool "is now installed."
    log_output "$tool is now installed."
else
    # if nipe is already installed, find the 'nipe.pl' file location,
    # and save the folder location.
    temp="$(sudo find / -name nipe.pl -print -quit 2>/dev/null)"
    nipe_directory="${temp::-8}"
    echo "[#]" $tool "is already installed."
    log_output "$tool is already installed."
    #echo $nipe_directory
fi
echo "--------------------------------------------------"

# 1.2) check if connection is anonymous. if not, enable nipe.
echo "[#] Checking if nipe is enabled and connected"
cd "$nipe_directory"
status="$(sudo perl nipe.pl status | grep "Status" | awk '{print $3}')"
if [ $status == 'false' ]; then
    #not enabled; enable nipe
    echo "[!] nipe is not enabled! Enabling..."
    sudo perl nipe.pl start
    sudo perl nipe.pl restart
fi
log_output "nipe is enabled"

# 1.3) once anonymous, display spoofed country name.
echo "[#] nipe is enabled and connected. Checking anonymous location..."
anon_ip="$(sudo perl nipe.pl status | grep "Ip" | awk '{print $3}')"
anon_location="$(geoiplookup $anon_ip | awk -F: '{print $2}')"
echo "[#] Your anonymous location is$anon_location"
cd "$current_directory"
echo "--------------------------------------------------"

# 1.4) Get the ip address or URL to do a whois on. It can also be a list of them.
while [ -z $ips_to_check ]
do
    read -p "[?] Enter one or more ip addresses or hostname, space seperated: " -a ips_to_check
    if [ -z $ips_to_check ]; then
        echo "[!] No input detected. Please enter at least one ip address or hostname."
    fi
echo "--------------------------------------------------"
done

# Step 2: Automatically Scan the Remote Server for open ports.
echo "[#] Scanning remote server for SSH and FTP port numbers..."
log_output "Running nmap of $remote_server" 
echo "[#] Running nmap of" $remote_server
nmap -A -sV -v0 $remote_server -p- -oG $remote_server".nmap.lst"
echo "[#] nmap result stored in" $remote_server".nmap.lst"
echo "--------------------------------------------------"
log_output "nmap result stored in $remote_server.nmap.lst"

# 2.1) Once scanned, find the ssh port number and connect to it
# 2.2) Display the details of the remote server (country, Public IP, and Uptime)
# 2.3) Get the remote server to check the Whois of the given addresses/URLs
ssh_port_num="$(cat $remote_server.nmap.lst | grep -i "ports" | awk '{for (i=1; i<=NF; i++) {if ($i ~ "ssh") {print $i}}}' | awk -F'/' '{print $1}')"
echo "[#] SSH port number is:" $ssh_port_num
ftp_port_num="$(cat $remote_server.nmap.lst | grep -i "ports" | awk '{for (i=1; i<=NF; i++) {if ($i ~ "ftp") {print $i}}}' | awk -F'/' '{print $1}')"
echo "[#] FTP port number is:"$ftp_port_num
if [ ! -f remote_script.txt ]; then
    echo "[!] Remote script file not found! making" $remote_script_file
    touch $remote_script_file
fi
echo "[#] Loading commands into" $remote_script_file "..."
echo -e $remote_script > $remote_script_file
for ip in "${ips_to_check[@]}"
do
    check_whois $ip $remote_script_file
done
echo "cd .." >> $remote_script_file
echo "echo \"Zipping whois files...\""
echo "tar -zcvf whois_results.tar.gz whois_results/" >> $remote_script_file
echo "exit" >> $remote_script_file
echo "[#] Logging into remote server and executing script..."
sshpass -p "tc" ssh -o StrictHostKeyChecking=no -p $ssh_port_num tc@$remote_server < $remote_script_file

# Step 3: Results
# 3.1) Save the whois results into their respective files, labeled with their ip/url
# 3.2) Using a INSECURE protocol e.g. ftp, retrieve the files from the remote server.
# 3.3) Create a log and audit your data collection; save the log locally.
echo "[#] Retrieving file results..."
wget ftp://tc:tc@$remote_server:$ftp_port_num/whois_results.tar.gz
echo "[#] whois_results.tar.gz retrieved"
log_output "whois_results.tar.gz retrieved from $remote_server"
# Finally, disable nipe for the user.
echo "[#] Finished work. Stopping Nipe... "
cd "$nipe_directory"
sudo perl nipe.pl stop
cd "$current_directory"