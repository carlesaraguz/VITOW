#!/bin/bash

WHOAMI=$(whoami)
if [ $WHOAMI == "root" ]; then
    if [ "$#" -ne 1 ]; then
        echo "Illegal number of parameters. Expected: ./restart_hw.sh <tx|rx>"
    else
        rmmod ath9k_htc
        modprobe ath9k_htc
        echo "Device module reset succesfully. Setting monitor mode..."
        sleep 3
        if [ $1 == "tx" ]; then
            ./monitor.sh wlan1 13
            echo "Monitor mode set for interface wlan1, channel 13"
        elif [ $1 == "rx" ]; then
            ./monitor.sh wlx00c0ca84b9c4 13
            echo "Monitor mode set for interface wlx00c0ca84b9c4, channel 13"
        else
            echo "Wrong argument ($1). Expected `tx` or `rx`"
        fi
    fi
else
    echo "This script has to be executed by root (or with sudo)"
fi
