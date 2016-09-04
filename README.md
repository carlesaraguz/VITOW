#  VITOW - (Reliable) Video Transfer over Wifi

(Alpha Version)

VITOW is a project to convey HD video using off-the-shelf Wifi dongles. Reliability is achieved by means of LDPC-Staircase coding at the expense of adding delay. 

This project uses code or has been inspired from:  

  - [Packetspammer](https://warmcat.com/git/packetspammer/) 
  - [OpenFEC codec](http://openfec.org/)
  - [Wifibroadcast](https://befinitiv.wordpress.com/wifibroadcast-analog-like-transmission-of-live-video-data/)

Unlike wifibroadcast, which is focused on live transmission, VITOW is meant to be used by non delay sensitive applications that require high-quality video transmission.  


## Hardware

The following list of hardware is recommended: 

- Pair of computers running GNU/Linux or Rapsberry (B+/2/3 preferred for maximum USB output amperage) at the transmitting side  (TX). Computer running GNU/Linux at reception (RX). 
- ALFA AWUS036NHA or TP-LINK TL-WN722N wifi dongles. 
- Raspberry pi Camera. 

## Installation 

(Tested in Ubuntu 14.04 LTS)

VITOW uses the LDPC-Staircase codec from [OpenFEC](http://openfec.org/), so first of all this codec has to be downloaded and installed. Cmake is needed. The installation process is described in the README file of the OpenFEC codec, so just follow the instructions. 

When the project has been compiled by cmake, under the bin/Release directory three shared libraries have been created: libopenfec.so, libopefec.so.1, libopefec.1.4.2, that need to be (sudo)-copied to /usr/lib/.

The VITOW project comes with a compile.sh script, before running it libpcap has to be installed: 

```sh
$ sudo apt-get install libpcap-dev 
```

Now, the script may be run: 

```sh
$ sudo ./compile.sh
```


In order to display the video in RX, mplayer performs pretty well: 

```sh
$ sudo apt-get install mplayer
```


Finally, the firmware that comes with the VITOW project (htc_9271.fw) has to override the one that is located at /lib/firmware/

To load the new firmware, unplug and plug the device or run: 

```sh
$ sudo rmmod ath9k_htc
$ sudo modprobe ath9k_htc
```

## Usage

VITOW takes whatsoever is introduced in the standard input at the transmiting side and dumps to the standard output what has received and correctly decodified at the reciving side. 

First of all, the wifi dongles (in TX and RX) have to be set in monitor mode, the monitor.sh that is provided in the project shows the steps to follow. 

If the camera used is the raspicam, the following line will initiate the transmission of 720p video @ 4Mbps and 30fps at the transmitting side (TX). Note the necessity of using privileges:

```sh
$ sudo su
$ raspivid -t 0 -w 1270 -h 720 -b 4000000 -hf -ih -fps 30 -n -fl -pf high -o - | ./TX
```

At the receiving side (RX), the following command initiates the reception process (also privileges needed):

```sh
$ sudo su
$ ./RX
```

And in order to display the video that is being received:

```sh
$ tail -F  testing | mplayer -fps 30 -framedrop -demuxer h264es -
```





