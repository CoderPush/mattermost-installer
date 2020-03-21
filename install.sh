#!/bin/bash

#check root privileges
if [[ $(/usr/bin/id -u) -ne 0 ]]; then
    echo "Not running as root"
    exit
fi

export DEBIAN_FRONTEND=noninteractive

#get the domain name

echo 

echo 

read -p 'ENTER DOMAIN NAME WITHOUT WWW PREFIX (eg: mm.example.com) : ' domain

echo

read -p 'ENTER SQL CLOUD INSTANCE ENDPOINT   : ' dbpath


echo

read -p 'ENTER DATABASE ADMIN : ' dbadmin

echo

read -p 'ENTER DATABASE NAME : ' dbname

echo

read -sp 'ENTER DATABASE PASSWORD : ' dbpassword

echo





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

#make config.json for mm

tee /opt/mattermost/config/config.json > /dev/null <<EOF

{
  "ServiceSettings": {
    "SiteURL": "https://$domain",
    "WebsocketURL": "",
    "LicenseFileLocation": "",
    "ListenAddress": ":8000",
    "ConnectionSecurity": "",
    "TLSCertFile": "",
    "TLSKeyFile": "",
    "TLSMinVer": "1.2",
    "TLSStrictTransport": false,
    "TLSStrictTransportMaxAge": 63072000,
    "TLSOverwriteCiphers": [],
    "UseLetsEncrypt": false,
    "LetsEncryptCertificateCacheFile": "./config/letsencrypt.cache",
    "Forward80To443": false,
    "ReadTimeout": 300,
    "WriteTimeout": 300,
    "MaximumLoginAttempts": 10,
    "GoroutineHealthThreshold": -1,
    "GoogleDeveloperKey": "",
    "EnableOAuthServiceProvider": false,
    "EnableIncomingWebhooks": true,
    "EnableOutgoingWebhooks": true,
    "EnableCommands": true,
    "EnableOnlyAdminIntegrations": true,
    "EnablePostUsernameOverride": false,
    "EnablePostIconOverride": false,
    "EnableAPIv3": false,
    "EnableLinkPreviews": false,
    "EnableTesting": false,
    "EnableDeveloper": false,
    "EnableSecurityFixAlert": true,
    "EnableInsecureOutgoingConnections": false,
    "AllowedUntrustedInternalConnections": "",
    "EnableMultifactorAuthentication": false,
    "EnforceMultifactorAuthentication": false,
    "EnableUserAccessTokens": false,
    "AllowCorsFrom": "",
    "CorsExposedHeaders": "",
    "CorsAllowCredentials": false,
    "CorsDebug": false,
    "AllowCookiesForSubdomains": false,
    "SessionLengthWebInDays": 30,
    "SessionLengthMobileInDays": 30,
    "SessionLengthSSOInDays": 30,
    "SessionCacheInMinutes": 10,
    "SessionIdleTimeoutInMinutes": 0,
    "WebsocketSecurePort": 443,
    "WebsocketPort": 80,
    "WebserverMode": "gzip",
    "EnableCustomEmoji": false,
    "EnableEmojiPicker": true,
    "EnableGifPicker": false,
    "GfycatApiKey": "2_KtH_W5",
    "GfycatApiSecret": "3wLVZPiswc3DnaiaFoLkDvB4X0IV6CpMkj4tf2inJRsBY6-FnkT08zGmppWFgeof",
    "RestrictCustomEmojiCreation": "all",
    "RestrictPostDelete": "all",
    "AllowEditPost": "always",
    "PostEditTimeLimit": -1,
    "ExperimentalEnableAuthenticationTransfer": true,
    "TimeBetweenUserTypingUpdatesMilliseconds": 5000,
    "EnablePostSearch": true,
    "EnableUserTypingMessages": true,
    "EnableChannelViewedMessages": true,
    "EnableUserStatuses": true,
    "ClusterLogTimeoutMilliseconds": 2000,
    "EnablePreviewFeatures": true,
    "CloseUnusedDirectMessages": false,
    "EnableTutorial": true,
    "ExperimentalEnableDefaultChannelLeaveJoinMessages": true,
    "ExperimentalGroupUnreadChannels": "disabled",
    "ExperimentalChannelOrganization": false,
    "ImageProxyType": "",
    "ImageProxyOptions": "",
    "ImageProxyURL": "",
    "EnableAPITeamDeletion": false,
    "ExperimentalEnableHardenedMode": false,
    "EnableEmailInvitations": false
  },
  "TeamSettings": {
    "SiteName": "Mattermost",
    "MaxUsersPerTeam": 50,
    "EnableTeamCreation": true,
    "EnableUserCreation": true,
    "EnableOpenServer": false,
    "EnableUserDeactivation": false,
    "RestrictCreationToDomains": "",
    "EnableCustomBrand": false,
    "CustomBrandText": "",
    "CustomDescriptionText": "",
    "RestrictDirectMessage": "any",
    "RestrictTeamInvite": "all",
    "RestrictPublicChannelManagement": "all",
    "RestrictPrivateChannelManagement": "all",
    "RestrictPublicChannelCreation": "all",
    "RestrictPrivateChannelCreation": "all",
    "RestrictPublicChannelDeletion": "all",
    "RestrictPrivateChannelDeletion": "all",
    "RestrictPrivateChannelManageMembers": "all",
    "EnableXToLeaveChannelsFromLHS": false,
    "UserStatusAwayTimeout": 300,
    "MaxChannelsPerTeam": 2000,
    "MaxNotificationsPerChannel": 1000,
    "EnableConfirmNotificationsToChannel": true,
    "TeammateNameDisplay": "username",
    "ExperimentalViewArchivedChannels": false,
    "ExperimentalEnableAutomaticReplies": false,
    "ExperimentalHideTownSquareinLHS": false,
    "ExperimentalTownSquareIsReadOnly": false,
    "ExperimentalPrimaryTeam": "",
    "ExperimentalDefaultChannels": ""
  },
  "DisplaySettings": {
    "CustomUrlSchemes": [],
    "ExperimentalTimezone": false
  },
  "ClientRequirements": {
    "AndroidLatestVersion": "",
    "AndroidMinVersion": "",
    "DesktopLatestVersion": "",
    "DesktopMinVersion": "",
    "IosLatestVersion": "",
    "IosMinVersion": ""
  },
  "SqlSettings": {
    "DriverName": "mysql",
    "DataSource": "$dbadmin:$dbpassword@tcp($dbpath:3306)/$dbname?charset=utf8mb4,utf8&readTimeout=30s&writeTimeout=30s"
    "DataSourceReplicas": [],
    "DataSourceSearchReplicas": [],
    "MaxIdleConns": 20,
    "ConnMaxLifetimeMilliseconds": 3600000,
    "MaxOpenConns": 300,
    "Trace": false,
    "AtRestEncryptKey": "",
    "QueryTimeout": 30
  },
  "LogSettings": {
    "EnableConsole": true,
    "ConsoleLevel": "DEBUG",
    "ConsoleJson": true,
    "EnableFile": true,
    "FileLevel": "INFO",
    "FileJson": true,
    "FileLocation": "",
    "EnableWebhookDebugging": true,
    "EnableDiagnostics": true
  },
  "PasswordSettings": {
    "MinimumLength": 5,
    "Lowercase": false,
    "Number": false,
    "Uppercase": false,
    "Symbol": false
  },
  "FileSettings": {
    "EnableFileAttachments": true,
    "EnableMobileUpload": true,
    "EnableMobileDownload": true,
    "MaxFileSize": 52428800,
    "DriverName": "local",
    "Directory": "./data/",
    "EnablePublicLink": false,
    "PublicLinkSalt": "",
    "InitialFont": "nunito-bold.ttf",
    "AmazonS3AccessKeyId": "",
    "AmazonS3SecretAccessKey": "",
    "AmazonS3Bucket": "",
    "AmazonS3Region": "",
    "AmazonS3Endpoint": "s3.amazonaws.com",
    "AmazonS3SSL": true,
    "AmazonS3SignV2": false,
    "AmazonS3SSE": false,
    "AmazonS3Trace": false
  },
  "EmailSettings": {
    "EnableSignUpWithEmail": true,
    "EnableSignInWithEmail": true,
    "EnableSignInWithUsername": true,
    "SendEmailNotifications": true,
    "UseChannelInEmailNotifications": false,
    "RequireEmailVerification": false,
    "FeedbackName": "",
    "FeedbackEmail": "test@example.com",
    "FeedbackOrganization": "",
    "EnableSMTPAuth": false,
    "SMTPUsername": "",
    "SMTPPassword": "",
    "SMTPServer": "dockerhost",
    "SMTPPort": "2500",
    "ConnectionSecurity": "",
    "InviteSalt": "",
    "SendPushNotifications": true,
    "PushNotificationServer": "https://push-test.mattermost.com",
    "PushNotificationContents": "generic",
    "EnableEmailBatching": false,
    "EmailBatchingBufferSize": 256,
    "EmailBatchingInterval": 30,
    "EnablePreviewModeBanner": true,
    "SkipServerCertificateVerification": false,
    "EmailNotificationContentsType": "full",
    "LoginButtonColor": "",
    "LoginButtonBorderColor": "",
    "LoginButtonTextColor": ""
  },
  "RateLimitSettings": {
    "Enable": false,
    "PerSec": 10,
    "MaxBurst": 100,
    "MemoryStoreSize": 10000,
    "VaryByRemoteAddr": true,
    "VaryByUser": false,
    "VaryByHeader": ""
  },
  "PrivacySettings": {
    "ShowEmailAddress": true,
    "ShowFullName": true
  },
  "SupportSettings": {
    "TermsOfServiceLink": "https://about.mattermost.com/default-terms/",
    "PrivacyPolicyLink": "https://about.mattermost.com/default-privacy-policy/",
    "AboutLink": "https://about.mattermost.com/default-about/",
    "HelpLink": "https://about.mattermost.com/default-help/",
    "ReportAProblemLink": "https://about.mattermost.com/default-report-a-problem/",
    "SupportEmail": "feedback@mattermost.com"
  },
  "AnnouncementSettings": {
    "EnableBanner": false,
    "BannerText": "",
    "BannerColor": "#f2a93b",
    "BannerTextColor": "#333333",
    "AllowBannerDismissal": true
  },
  "ThemeSettings": {
    "EnableThemeSelection": true,
    "DefaultTheme": "default",
    "AllowCustomThemes": true,
    "AllowedThemes": []
  },
  "TimezoneSettings": {
    "SupportedTimezonesPath": "timezones.json"
  },
  "GitLabSettings": {
    "Enable": false,
    "Secret": "",
    "Id": "",
    "Scope": "",
    "AuthEndpoint": "",
    "TokenEndpoint": "",
    "UserApiEndpoint": ""
  },
  "GoogleSettings": {
    "Enable": false,
    "Secret": "",
    "Id": "",
    "Scope": "profile email",
    "AuthEndpoint": "https://accounts.google.com/o/oauth2/v2/auth",
    "TokenEndpoint": "https://www.googleapis.com/oauth2/v4/token",
    "UserApiEndpoint": "https://www.googleapis.com/plus/v1/people/me"
  },
  "Office365Settings": {
    "Enable": false,
    "Secret": "",
    "Id": "",
    "Scope": "User.Read",
    "AuthEndpoint": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    "TokenEndpoint": "https://login.microsoftonline.com/common/oauth2/v2.0/token",
    "UserApiEndpoint": "https://graph.microsoft.com/v1.0/me"
  },
  "LdapSettings": {
    "Enable": false,
    "EnableSync": false,
    "LdapServer": "",
    "LdapPort": 389,
    "ConnectionSecurity": "",
    "BaseDN": "",
    "BindUsername": "",
    "BindPassword": "",
    "UserFilter": "",
    "FirstNameAttribute": "",
    "LastNameAttribute": "",
    "EmailAttribute": "",
    "UsernameAttribute": "",
    "NicknameAttribute": "",
    "IdAttribute": "",
    "PositionAttribute": "",
    "LoginIdAttribute": "",
    "SyncIntervalMinutes": 60,
    "SkipCertificateVerification": false,
    "QueryTimeout": 60,
    "MaxPageSize": 0,
    "LoginFieldName": "",
    "LoginButtonColor": "",
    "LoginButtonBorderColor": "",
    "LoginButtonTextColor": ""
  },
  "ComplianceSettings": {
    "Enable": false,
    "Directory": "./data/",
    "EnableDaily": false
  },
  "LocalizationSettings": {
    "DefaultServerLocale": "en",
    "DefaultClientLocale": "en",
    "AvailableLocales": ""
  },
  "SamlSettings": {
    "Enable": false,
    "EnableSyncWithLdap": false,
    "EnableSyncWithLdapIncludeAuth": false,
    "Verify": true,
    "Encrypt": true,
    "IdpUrl": "",
    "IdpDescriptorUrl": "",
    "AssertionConsumerServiceURL": "",
    "ScopingIDPProviderId": "",
    "ScopingIDPName": "",
    "IdpCertificateFile": "",
    "PublicCertificateFile": "",
    "PrivateKeyFile": "",
    "IdAttribute": "",
    "FirstNameAttribute": "",
    "LastNameAttribute": "",
    "EmailAttribute": "",
    "UsernameAttribute": "",
    "NicknameAttribute": "",
    "LocaleAttribute": "",
    "PositionAttribute": "",
    "LoginButtonText": "SAML",
    "LoginButtonColor": "",
    "LoginButtonBorderColor": "",
    "LoginButtonTextColor": ""
  },
  "NativeAppSettings": {
    "AppDownloadLink": "https://about.mattermost.com/downloads/",
    "AndroidAppDownloadLink": "https://about.mattermost.com/mattermost-android-app/",
    "IosAppDownloadLink": "https://about.mattermost.com/mattermost-ios-app/"
  },
  "ClusterSettings": {
    "Enable": false,
    "ClusterName": "",
    "OverrideHostname": "",
    "UseIpAddress": true,
    "UseExperimentalGossip": false,
    "ReadOnlyConfig": true,
    "GossipPort": 8074,
    "StreamingPort": 8075,
    "MaxIdleConns": 100,
    "MaxIdleConnsPerHost": 128,
    "IdleConnTimeoutMilliseconds": 90000
  },
  "MetricsSettings": {
    "Enable": false,
    "BlockProfileRate": 0,
    "ListenAddress": ":8067"
  },
  "ExperimentalSettings": {
    "ClientSideCertEnable": false,
    "ClientSideCertCheck": "secondary",
    "EnablePostMetadata": false
  },
  "AnalyticsSettings": {
    "MaxUsersForStatistics": 2500
  },
  "ElasticsearchSettings": {
    "ConnectionUrl": "http://dockerhost:9200",
    "Username": "elastic",
    "Password": "changeme",
    "EnableIndexing": false,
    "EnableSearching": false,
    "Sniff": true,
    "PostIndexReplicas": 1,
    "PostIndexShards": 1,
    "AggregatePostsAfterDays": 365,
    "PostsAggregatorJobStartTime": "03:00",
    "IndexPrefix": "",
    "LiveIndexingBatchSize": 1,
    "BulkIndexingTimeWindowSeconds": 3600,
    "RequestTimeoutSeconds": 30
  },
  "DataRetentionSettings": {
    "EnableMessageDeletion": false,
    "EnableFileDeletion": false,
    "MessageRetentionDays": 365,
    "FileRetentionDays": 365,
    "DeletionJobStartTime": "02:00"
  },
  "MessageExportSettings": {
    "EnableExport": false,
    "DailyRunTime": "01:00",
    "ExportFromTimestamp": 0,
    "FileLocation": "export",
    "BatchSize": 10000,
    "GlobalRelaySettings": {
      "CustomerType": "A9",
      "SmtpUsername": "",
      "SmtpPassword": "",
      "EmailAddress": ""
    }
  },
  "JobSettings": {
    "RunJobs": true,
    "RunScheduler": true
  },
  "PluginSettings": {
    "Enable": true,
    "EnableUploads": false,
    "Directory": "./plugins",
    "ClientDirectory": "./client/plugins",
    "Plugins": {},
    "PluginStates": {}
  }
}

EOF


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


#reload daemon
systemctl daemon-reload

#start mm
systemctl start mattermost

#enable mm
systemctl enable mattermost

#restart mm
systemctl restart mattermost


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

    location ~ /api/v[0-9]+/(users/)?websocket\$ {
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";

        client_max_body_size 50M;

        proxy_set_header Host '\$http_host';
        proxy_set_header X-Real-IP '\$remote_addr';
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
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
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
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


#issue new certs

certbot --nginx certonly

#create new nginx server block


tee /etc/nginx/sites-available/mattermost.conf > /dev/null <<EOF

# mattermost default port config


upstream backend {
    server localhost:8065;
    keepalive 32;
}

proxy_cache_path /var/cache/nginx levels=1:2 keys_zone=mattermost_cache:10m max_size=3g inactive=120m use_temp_path=off;

server {
     listen [::]:80;
     listen 80;

     server_name $domain www.$domain;

     return 301 https://$domain\$request_uri;
}

server {
     listen [::]:443 ssl;
     listen 443 ssl;

     server_name www.$domain;

     ssl_certificate /etc/letsencrypt/live/$domain/fullchain.pem;
     ssl_certificate_key /etc/letsencrypt/live/$domain/privkey.pem;

     return 301 https://$domain\$request_uri;
}

server {
     listen [::]:443 ssl http2;
     listen 443 ssl http2;

     server_name $domain;

     ssl_certificate /etc/letsencrypt/live/$domain/fullchain.pem;
     ssl_certificate_key /etc/letsencrypt/live/$domain/privkey.pem;

     location ~ /api/v[0-9]+/(users/)?websocket\$ {
         proxy_set_header Upgrade \$http_upgrade;
         proxy_set_header Connection "upgrade";
         
         client_max_body_size 50M;
        
         proxy_set_header Host \$http_host;
         proxy_set_header X-Real-IP \$remote_addr;
         proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
         proxy_set_header X-Forwarded-Proto \$scheme;
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
         proxy_set_header Host \$http_host;
         proxy_set_header X-Real-IP \$remote_addr;
         proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
         proxy_set_header X-Forwarded-Proto \$scheme;
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

