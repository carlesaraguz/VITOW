#! /bin/bash

echo "Script Running, setting Wlan1 and Wlan2 monitor 13"

sudo ifconfig wlan2 down
sudo iw dev wlan2 set monitor otherbss none
sudo ifconfig wlan2 up
sudo iwconfig wlan2 channel 13

sudo ifconfig wlan1 down
sudo iw dev wlan1 set monitor otherbss none
sudo ifconfig wlan1 up
sudo iwconfig wlan1 channel 13



echo "Done"
