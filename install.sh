#!/bin/bash

#check root privileges
if [[ $(/usr/bin/id -u) -ne 0 ]]; then
    echo "Not running as root"
    exit
fi

#get the domain name

echo domain name to install mattermost

read domainname



#update the packages
apt update -y
apt upgrade -y

#get the latest release of mattermost open source team edition
wget https://releases.mattermost.com/5.21.0/mattermost-team-5.21.0-linux-amd64.tar.gz

#unzip the installed package
tar -xvzf mattermost*.gz

#move extracted mattermost to opt
mv mattermost /opt

#move extracted mattermost to opt
mkdir /opt/mattermost/data

#add new user:mattermost and grant permissions
useradd --system --user-group mattermost
chown -R mattermost:mattermost /opt/mattermost
sudo chmod -R g+w /opt/mattermost

# mattermost.service
echo "[Unit]
Description=Mattermost
After=network.target

[Service]
Type=notify
ExecStart=/opt/mattermost/bin/mattermost
TimeoutStartSec=3600
Restart=always
RestartSec=10
WorkingDirectory=/opt/mattermost
User=mattermost
Group=mattermost
LimitNOFILE=49152

[Install]
WantedBy=multi-user.target" > /lib/systemd/system/mattermost.service

#update the packages
apt update -y
apt upgrade -y

#install nginx
apt install nginx -y
rm /etc/nginx/sites-enabled/default
rm /etc/nginx/sites-available/default
wget -O /etc/nginx/sites-available/mattermost.conf https://raw.githubusercontent.com/thesuhailcompany/mm-statuc/master/mm-d.conf
ln -s /etc/nginx/sites-available/mattermost.conf /etc/nginx/sites-enabled/mattermost.conf

#install certbot
add-apt-repository ppa:certbot/certbot -y
apt update -y
apt upgrade -y
apt install python-certbot-nginx -y

#write out current crontab
crontab -l > renewcert
#echo new cron into cron file
echo "0 0,12 * * * certbot renew >/dev/null 2>&1" >> renewcert
#install new cron file
crontab renewcert
rm renewcert

#update the packages
apt update -y
apt update -y

#


