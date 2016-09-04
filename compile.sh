gcc -o TX TX.c radiotap.c  -l:libopenfec.so.1.4.2 -lm -lpcap -L.  -lpthread -w
gcc -o RX RX.c radiotap.c  -l:libopenfec.so.1.4.2 -lm -lpcap -L.  -lpthread -w

