tail -f vitow_output | pv -L 93750 | \
    ffmpeg  -re -ar 44100 -ac 2 -acodec pcm_s16le -f s16le -ac 2 \
            -i /dev/zero -f h264 -i - -i watermark.png -filter_complex 'overlay=0:0' \
            -vcodec h264 -profile:v high -level 4.0 -acodec aac -ab 128k -g 50 -strict experimental \
            -f flv rtmp://a.rtmp.youtube.com/live2/19vh-c3ku-c51y-279z
