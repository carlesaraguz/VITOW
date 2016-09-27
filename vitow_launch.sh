#!/bin/bash

# Raspivid options:
# =================
# -t 0          --> Start right now (no timeout).
# -w 854 -h 480 --> 480p 16:9 ratio (Youtube standard)
# -b 750000     --> Bitrate 750 kbps.
# -ih           --> Forces the stream to include PPS and SPS headers on every I-frame.
# -hf           --> Horizontal flip.
# -vf           --> Vertical flip.
# -fps 25       --> Framerate: 25 fps.
# -n            --> Do not display a preview in a new window.
# -pf high      --> Video profile: high.
# -o -          --> Output to stdout.

raspivid -t 0 -w 854 -h 480 -b 750000 -ih -fps 25 -n -pf high -o - | tee vitow_input.mp4 | sudo ./vitow_tx wlan1
