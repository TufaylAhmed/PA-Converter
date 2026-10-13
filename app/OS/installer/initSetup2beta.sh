#!/bin/bash

currentwd="$(pwd)"
interactive=

# Configure variables
declare_variables() {
    #user=$(echo "$USER")
    #sourcePath=/PALogs/PaloAltoSC2
    #TrafficRotatorPath=/var/www/html/OS/trafficRotator/prepareTrafficLog.sh
    #deviceDeclarationPath=/var/www/html/OS/trafficRotator/devices.txt

    bold=$(tput bold)
    normal=$(tput sgr0)
    #BLACK=$(tput setaf 0)
    RED=$(tput setaf 1)
    GREEN=$(tput setaf 2)
    #YELLOW=$(tput setaf 3)
    BLUE=$(tput setaf 4)
    #MAGENTA=$(tput setaf 5)
    #CYAN=$(tput setaf 6)
    #WHITE=$(tput setaf 7)
}




printBanner(){
    echo ""
    echo "${GREEN}${bold}************************************************************"
    echo "$1"
    echo              "************************************************************${normal}"
}

printTitleWait(){
    if [[ $interactive -eq 1 ]]; then
        echo ""
        echo "${GREEN}"
        echo "$1"
        read -p -r   "${BLUE}Press enter to continue${normal}"

    else
        echo ""
        echo "${GREEN}"
        echo "$1"
        echo "${normal}"
    fi
}

printTitle(){
    echo "${GREEN}"
    echo "$1"
    echo "${normal}"
}

printTitleFailed(){
    echo "${RED}"
    echo "$1"
    echo "${normal}"
}

updateRepositories(){
    printTitle "Updating APT"
    apt-get update
    apt-get install -y software-properties-common
    printTitle "Installing Expect"
    apt-get install -y expect
    printTitle "Installing RSyslog debian repository"
    expect -c "
        set timeout 60
        spawn add-apt-repository ppa:adiscon/v8-stable
        expect -re \"Press *\" {
            send -- \"\r\"
            exp_continue
        }
    "

    printTitle "Installing PHP repository"
    expect -c "
        set timeout 60
        spawn add-apt-repository ppa:ondrej/php
        expect -re \"Press .ENTER. to continue*\" {
            send -- \"\r\"
            exp_continue
        }
    "

    printTitle "Installing Expedition debian repository"
    wget https://conversionupdates.paloaltonetworks.com/ex-repo.gpg > /etc/apt/trusted.gpg.d/ex-repo.gpg
    echo 'deb [trusted=yes] https://conversionupdates.paloaltonetworks.com/ expedition-updates/' > /etc/apt/sources.list.d/ex-repo.list

    printTitle "Installing RabbitMQ debian repository"
    echo 'deb [trusted=yes] http://www.rabbitmq.com/debian/ testing main' | tee /etc/apt/sources.list.d/rabbitmq.list
    wget -O- https://www.rabbitmq.com/rabbitmq-release-signing-key.asc | sudo apt-key add -

    #printTitle "Installing MariaDB debian repository"
    # (more info: https://www.linuxbabe.com/mariadb/install-mariadb-10-1-ubuntu14-04-15-10)
    #apt-key adv --recv-keys --keyserver hkp://keyserver.ubuntu.com:80 0xF1656F24C74CD1D8
    #add-apt-repository 'deb [arch=amd64,i386] http://sgp1.mirrors.digitalocean.com/mariadb/repo/10.1/ubuntu xenial main'

    apt-get update
}

prepareSystemService(){
    #sudo vi /etc/ssh/sshd_config

    printTitleWait "Changing CLI root password to 'paloalto'"
    echo -e "paloalto\npaloalto" | passwd root

    printTitleWait "Installing SSHD service"
    sudo apt-get install -y openssh-server

    printTitle "Enabling ROOT ssh access"
    filePath=/etc/ssh/sshd_config
    lineToChange=$(grep -n "PermitRootLogin prohibit-password" $filePath | awk -F ':' '{print $1}')
    sed -i "${lineToChange}s/.*/ PermitRootLogin yes/" $filePath;
    service sshd restart

    # Add ZIP and Zlib
    printTitle "Installing ZIP libraries"
    apt-get install -y zip
    apt-get install -y zlib1g-dev

        # Rsyslog
    printTitleWait "Installing Rsyslog for syslog Firewall traffic logs"
    apt-get install -y rsyslog

    systemctl disable syslog.service

    cp /lib/systemd/system/rsyslog.service /etc/systemd/system/rsyslog.service
    # vi /lib/systemd/system/rsyslog.service
    # [Service] 
    # Type=notify 
    # ExecStart=/usr/sbin/rsyslogd -n
    #  StandardOutput=null
    #  Restart=on-failure

    #update-rc.d rsyslog enable
    #systemctl enable rsyslog.service
}

installLAMP(){
# Install all Apache required modules
    printTitleWait "Installing Apache service and dependencies for PHP"
    apt-get install -y apache2 \
            php7.2 php7.2-ldap php7.2-ldap php7.2-bcmath php7.2-mbstring php7.2-gd php7.2-soap php7.2-zip php7.2-xml php7.2-opcache php7.2-curl php7.2-bz2 libapache2-mod-php7.2 php7.2-mysql \
            mysql-server

    # Install openssl for https
    printTitle "Activating SSL on Apache"
    apt-get install -y openssl
    # Enable SSL for the Web Server
    #a2ensite default-ssl;
    a2enmod rewrite; a2enmod ssl; systemctl restart apache2




    # Database Server
    printTitleWait "Setting UP the DB server. " # Please, do not enter a password for root. We will automatically update it later to 'paloalto'.Remember: DO NOT ENTER A PASSWORD"

    # Install the secure controls for MySQL
    expect -c "
        set timeout 600
        spawn mysql_secure_installation
        expect \"Press y|Y for Yes, any other key for No:\"
        send \"Y\r\"
        expect \"Please enter 0 = LOW, 1 = MEDIUM and 2 = STRONG:\"
        send \"0\r\"
        expect \"New password:\"
        send \"paloalto\r\"
        expect \"Re-enter new password:\"
        send \"paloalto\r\"
        expect \"Do you wish to continue with the password provided?(Press y|Y for Yes, any other key for No) :\"
        send \"Y\r\"
        expect \"Remove anonymous users? (Press y|Y for Yes, any other key for No) :\"
        send \"Y\r\"
        expect \"Disallow root login remotely? (Press y|Y for Yes, any other key for No) :\"
        send \"Y\r\"
        expect \"Remove test database and access to it? (Press y|Y for Yes, any other key for No) :\"
        send \"Y\r\"
        expect \"Reload privilege tables now? (Press y|Y for Yes, any other key for No) :\"
        send \"Y\r\"
        expect eof
    "

    # Make sure that NOBODY can access the server without a password. Password changes to "paloalto"
    mysql -e "alter user 'root'@'localhost' identified with mysql_native_password by 'paloalto';"
    mysql -e "FLUSH PRIVILEGES"
    # Any subsequent tries to run queries this way will get access denied because lack of usr/pwd param

    filePath=/etc/mysql/my.cnf
    sed -i 's/max_allowed_packet\t= 16M/max_allowed_packet\t= 64M/g' $filePath
    sed -i 's/bind-address\t\t= 127.0.0.1/#bind-address\t\t= 127.0.0.1/g' $filePath
    sed -i 's/#binlog_format=row/binlog_format=mixed/g' $filePath
    service mysql restart

    # Create Databases
    printTitle "Creating initial Databases"
    mysqladmin -uroot -ppaloalto create pandb
    mysqladmin -uroot -ppaloalto create pandbRBAC
    mysqladmin -uroot -ppaloalto create BestPractices
    mysqladmin -uroot -ppaloalto create RealTimeUpdates

    # PERL
    printTitleWait "Installing Perl"
    apt-get install -y perl
    apt-get install -y liblist-moreutils-perl

    #printTitleWait "Installing Python dependencies for BPA modules"
    #apt-get install -y python-pip
    #pip install lxml
    #pip install --upgrade pip
    #pip install unidecode
    #pip install pandas
    #pip install six
    #pip install sqlalchemy#

    # RabbitMQ
    printTitleWait "Installing Messaging system for background tasks"
    apt-get install -y rabbitmq-server
    update-rc.d rabbitmq-server defaults
    apt-get install -y policycoreutils
    /usr/sbin/setsebool httpd_can_network_connect=1

    #Add www-data to expedition group
    usermod -a -G expedition www-data
}

installExpeditionPackages(){
    # apt-get Repository
    printTitleWait "Installing Expedition packages"

    #Get the GPG key:
    cd "/etc/apt/trusted.gpg.d/" || exit
    wget https://conversionupdates.paloaltonetworks.com/ex-repo.gpg
    # Installing Expedition package
    # apt-get install -y --allow-unauthenticated expedition-beta
    expect -c "
        set timeout 600
        spawn apt-get install -y --allow-unauthenticated expedition2-beta
        expect -re \"Do you want to *\" {
            send \"Y\r\"
            exp_continue
        }
    "

    expect -c "
        set timeout 600
        spawn apt-get install -y --allow-unauthenticated expedition2-converter-beta
        expect -re \"Do you want to *\" {
            send \"Y\r\"
            exp_continue
        }
    "

    chown -R www-data:expedition /var/expedition-converter/
    chown -R www-data:www-data /var/www/html/expedition-api/

    printTitle "Updating databases"
#    cd "$currentwd" || exit
#    tar -zxvf databases.tgz
    mysql -uroot -ppaloalto pandb < /var/www/html/expedition-api/database/SQL/pandb.sql
    mysql -uroot -ppaloalto pandbRBAC < /var/www/html/expedition-api/database/SQL/pandbRBAC.sql
    mysql -uroot -ppaloalto BestPractices < /var/www/html/expedition-api/database/SQL/BestPractices.sql
    mysql -uroot -ppaloalto RealTimeUpdates < /var/www/html/expedition-api/database/SQL/RealTimeUpdates.sql


    printTitle "Tunning some Expedition parameters"
    cp /var/www/html/expedition-api/initSetup/apache2/default-ssl.conf /etc/apache2/sites-available/000-default.conf

    filePath=/etc/mysql/my.cnf
    sed -i 's/log_bin/skip-log_bin/g' $filePath

    sed -i 's/post_max_size = 8M/post_max_size = 2G/g' /etc/php/7.2/apache2/php.ini
    sed -i 's/upload_max_filesize = 2M/upload_max_filesize = 2G/g' /etc/php/7.2/apache2/php.ini
    #filePath=/etc/php/7.0/apache2/php.ini
    #sed -i 's/mysqli.reconnect = Off/mysqli.reconnect = On/g' $filePath
    #filePath=/etc/php/7.0/cli/php.ini
    #sed -i 's/mysqli.reconnect = Off/mysqli.reconnect = On/g' $filePath
    sudo service apache2 restart


    #printTitle "Updating Python modules"
    #expect -c "
    #    set timeout 600
    #    spawn bash /var/www/html/OS/BPA/updateBPA306.sh
    #    expect -re \"Do you want to *\" {
    #        send \"Y\r\"
    #        exp_continue
    #    }
    #"

    printTitle "Installing Spark dependencies"
    apt-get install -y openjdk-8-jre-headless
    apt-get install -y --allow-unauthenticated expeditionml-dependencies-beta

    #cp /var/www/html/OS/spark/config/log4j.properties /opt/Spark/
    #rm -f /home/userSpace/environmentParameters.php
}

settingUpFirewallSettings(){
    printTitle "Installing Firewall service"
    apt-get install -y firewalld

    printTitle "Firewall rules for Web-browsing"
    #APACHE2
    firewall-cmd --add-port=443/tcp
    firewall-cmd --permanent --add-port=443/tcp

    printTitle "Firewall rules for Database (skipped)"
    #MySQL/MariaDB (optional)
    #firewall-cmd --add-port=3306/tcp
    #firewall-cmd --permanent --add-port=3306/tcp

    #RabbitMQ

    #SPARK
    printTitle "Firewall rules for ML Web-Interfaces"
    firewall-cmd --add-port=4050-4070/tcp
    firewall-cmd --permanent --add-port=4050-4070/tcp

    firewall-cmd --add-port=5050-5070/tcp
    firewall-cmd --permanent --add-port=5050-5070/tcp
}


createExpeditionUser(){
    exists=$(id -u expedition | wc -l)
    if [ "$exists" -eq 1 ]; then
        printTitle "Expedition user already exists"
    else
        printTitleFailed "expedition user does not exist"
        printTitleFailed "Create expedition user via \"sudo adduser --gecos '' expedition\""
        printTitleFailed "Execute this installer again afterwards"
        exit 1
    fi
}

#createPanReadOrdersService(){
#    cp /var/www/html/OS/startup/panReadOrdersStarter /etc/init.d/panReadOrders
#    chmod 755 /etc/init.d/panReadOrders
#    chown root:root /etc/init.d/panReadOrders
#    ln -s  /etc/init.d/panReadOrders /etc/rc2.d/S99panReadOrders
#    ln -s  /etc/init.d/panReadOrders /etc/rc3.d/S99panReadOrders
#    ln -s  /etc/init.d/panReadOrders /etc/rc4.d/S99panReadOrders
#    ln -s  /etc/init.d/panReadOrders /etc/rc5.d/S99panReadOrders
#
#    systemctl daemon-reload
#    service panReadOrders start
#}

controlVersion(){
    ubuntuVersion=$(lsb_release -a | grep Release | awk '{print $2}')
    if [ "$ubuntuVersion" == "18.04" ]; then
        printTitle "Correct Ubuntu Server 18.04 version"
    else
        printTitleFailed "This script has been prepared for Ubuntu Server 18.04"
        printTitleFailed "Current version: "
        echo "$ubuntuVersion"
        exit 1
    fi

    # Check if some packages has already been installed
    expeditionAlreadyInstalled=$(apt list --installed | grep -c expedition)
    if [ "$expeditionAlreadyInstalled" -ne 0 ]; then
        printTitleFailed "This script has been prepared to install Expedition from scratch"
        printTitleFailed "Expedition package is already present"
        exit 1
    else
        printTitle "This machine does not have Expedition installed"
    fi;

}

updateSettings(){
    # myIP=$(ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1')
    myIP=$(hostname -I)
    echo "INSERT INTO ml_settings (server) VALUES ('${myIP}') " | mysql -uroot -ppaloalto pandbRBAC
}

introduction(){
    echo
    echo "${GREEN}   ****************************************************************************************"
    echo       "   *                                                                                      *"
    echo       "   *         WELCOME TO EXPEDITION 2.0 ${RED}BETA${GREEN} ASSISTED INSTALLER v.0.5 (08/30/2021)         *"
    echo       "   *                                                                                      *"
    echo       "   *  This script will download and install required packages to prepare Expedition 2.0   *"
    echo       "   *  on Ubuntu server 20.04. A ${bold}NEW image${normal}${GREEN} is expected for this installer to take effect.  *"
    echo       "   *  This installer requires ${bold}Internet Connection${normal}${GREEN}                                         *"
    echo       "   *                                                                                      *"
    echo       "   *                                                                                      *"
    echo       "   *  We do not take any responsibility and we are not liable for any damage caused       *"
    echo       "   *  through use of this tool, be it indirect, special, incidental or consequential      *"
    echo       "   *  damages (including but not limited to damages for loss of business, loss of pro-    *"
    echo       "   *  fits, interruption or the like). If you have any questions regarding the terms of   *"
    echo       "   *  use outlined here, please do not hesitate to contact us at                          *"
    echo       "   *                fwmigrate@paloaltonetworks.com                                        *"
    echo       "   *                                                                                      *"
    echo       "   *  If you continue with this installation you acknowledge having read the above lines  *"
    echo       "   *                                                                                      *"
    echo       "   ****************************************************************************************${normal}"
    printTitleWait ""

}


usage()
{
    echo "usage: initSetup [-i] | [-h]"
}

# Establish run order
main() {

    while [[ $# -gt 0 ]]; do
    key="$1"
        case $key in
            -i | --interactive )    interactive=1
                                    ;;
            -h | --help )           usage
                                    exit
                                    ;;
            * )                     usage
                                    exit 1
        esac
        shift
    done


    declare_variables

    introduction

    controlVersion

    createExpeditionUser

    printBanner "Updating Debian Repositories"
    #apt-get -y install expect
    updateRepositories # Update Debian repositories


    # Prepare userSpace for Expedition data storage
    printTitle "Preparing the /home/userSpace Space for data storage"
    mkdir /home/userSpace; chown www-data:www-data -R /home/userSpace
    mkdir /data; chown www-data:www-data -R /data

    printBanner "Installing System Services"
    prepareSystemService  # Allow remote root ssh access. Change PermitRootLogin prohibit-password to PermitRootLogin yes

    printBanner "Installing LAMP Services"
    installLAMP

    settingUpFirewallSettings

    printBanner "Installing Expedition packages"
    installExpeditionPackages

    # printBanner "Starting Task Manager"
    # createPanReadOrdersService

    updateSettings

    cd "$currentwd" || exit

}

main "$@"