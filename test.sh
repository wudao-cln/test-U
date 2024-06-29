#!/bin/bash
sudo git clone -b my_22.04.4 https://github.com/wudao-cln/test-U.git
sudo add-apt-repository ppa:ubuntuhandbook1/apps
sudo apt-get update
sudo apt install make
cd test-U/
pwd && sudo make download
sudo make init && sudo make setup-isolinux 
ln -fs user-data.mbr config/user-data
#sed -i -e 's/---$/--- console=ttyS0,115200n8/' config/boot/grub/grub.cfg
sudo make setup
sudo make geniso-isolinux
mm=$(pwd) && sudo rm -rf $(ls $mm | grep -v "\.iso$")
