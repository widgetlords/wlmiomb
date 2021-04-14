#!/bin/sh

echo performance | sudo tee /sys/devices/system/cpu/cpufreq/policy0/scaling_governor > /dev/null
sudo ip link set can0 down
sudo ip link set can0 type can bitrate 500000 dbitrate 2000000 fd on sample-point 0.80 dsample-point 0.80 berr-reporting on restart-ms 100
sudo ip link set can0 up

sudo setcap 'cap_net_bind_service=+ep' wlmiomb

./wlmiomb $1
