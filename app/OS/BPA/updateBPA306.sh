#!/bin/bash
sudo apt install software-properties-common -y
sudo add-apt-repository ppa:deadsnakes/ppa -y
sudo apt-get update
sudo apt install python3.7 -y
sudo sudo rm /usr/bin/python3
sudo ln -s /usr/bin/python3.7 /usr/bin/python3
sudo apt-get install python3.7-distutils -y
sudo -H pip3 uninstall best-practice-assessment-ngfw-pano -y
sudo python3.7 /var/www/html/OS/BPA/get-pip.py
sudo rm /usr/local/bin/pip3
sudo ln -s /usr/local/bin/pip /usr/local/bin/pip3
sudo apt-get install -y libjpeg-dev
sudo -H pip3 install lxml --upgrade
sudo -H pip3 install matplotlib --upgrade
sudo -H pip3 install unidecode
sudo -H pip3 install pandas
sudo -H pip3 install six
sudo -H pip3 install sqlalchemy
sudo -H pip3 install 'Pillow<=5.4.1' --upgrade
sudo -H pip3 install chardet
sudo -H pip3 install zipp
# install the bpa-legacy-cli on python3.7
sudo -H pip3 install /var/www/html/OS/BPA/best_practice_assessment_ngfw_pano-master.zip --upgrade
# Recover python3.8 as default python version
sudo rm /usr/bin/python3
sudo ln -s /usr/bin/python3.8 /usr/bin/python3
sudo python3.8 /var/www/html/OS/BPA/get-pip.py
sudo rm /usr/local/bin/pip3
sudo ln -s /usr/local/bin/pip /usr/local/bin/pip3
