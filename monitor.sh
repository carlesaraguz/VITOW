#! /bin/bash

WHOAMI=$(whoami)
if [ $WHOAMI == "root" ]; then
    if [ "$#" -ne 1 ]; then
        echo "Illegal number of parameters. Expected: ./monitor.sh <interface_name> <channel_num>"
    else
        echo "Setting interface '$1' in monitor mode (channel $2)"
        sudo ifconfig $1 down
        sudo iw dev $1 set monitor otherbss none
        sudo ifconfig $1 up
        sudo iwconfig $1 channel $2
    fi
else
    echo "This script has to be executed by root (or with sudo)"
fi
