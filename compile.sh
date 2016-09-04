gcc -o TX TX.c radiotap.c -L/home/seitam/openfec_v1.4.2/bin/Release/ -l:libopenfec.so.1.4.2 -lm -lpcap -L.  -lpthread -w
gcc -o RX RX.c radiotap.c -L/home/seitam/openfec_v1.4.2/bin/Release/ -l:libopenfec.so.1.4.2 -lm -lpcap -L.  -lpthread -w

