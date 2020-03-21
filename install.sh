#!/bin/bash

#check root privileges
if [[ $(/usr/bin/id -u) -ne 0 ]]; then
    echo "Not running as root"
    exit
fi

#get the domain name

echo 

echo 

read -p 'ENTER DOMAIN NAME WITHOUT WWW PREFIX : ' domain

echo

echo Installing Mattermost For $domain



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

tee /etc/nginx/sites-available/mattermost.conf > /dev/null <<EOF

upstream backend {
    server localhost:8065;
    keepalive 32;
}

proxy_cache_path /var/cache/nginx levels=1:2 keys_zone=mattermost_cache:10m max_size=3g inactive=120m use_temp_path=off;

server {
    listen 80;

    server_name $domain;

    location ~ /api/v[0-9]+/(users/)?websocket$ {
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

        client_max_body_size 50M;

        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Frame-Options SAMEORIGIN;
        proxy_buffers 256 16k;
        proxy_buffer_size 16k;

        client_body_timeout 60;
        send_timeout 300;
        lingering_timeout 5;

        proxy_connect_timeout 90;
        proxy_send_timeout 300;
        proxy_read_timeout 90s;
        proxy_pass http://backend;
    }

    location / {
        client_max_body_size 50M;

        proxy_set_header Connection "";
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Frame-Options SAMEORIGIN;

        proxy_buffers 256 16k;
        proxy_buffer_size 16k;
        proxy_read_timeout 600s;

        proxy_cache mattermost_cache;
        proxy_cache_revalidate on;
        proxy_cache_min_uses 2;
        proxy_cache_use_stale timeout;
        proxy_cache_lock on;

        proxy_http_version 1.1;
        proxy_pass http://backend;
    }
}

EOF

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

