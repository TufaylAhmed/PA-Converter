#!/bin/bash

rm -r /var/www/html/OS/installer/expedition1_Installer_latest
mkdir /var/www/html/OS/installer/expedition1_Installer_latest
cp /var/www/html/OS/installer/databases.tgz /var/www/html/OS/installer/expedition1_Installer_latest/databases.tgz
cp /var/www/html/OS/installer/initSetup_v2.0.sh /var/www/html/OS/installer/expedition1_Installer_latest/initSetup_v2.0.sh
tar -czvf /var/www/html/OS/installer/expedition1_Installer_latest.tgz /var/www/html/OS/installer/expedition1_Installer_latest/