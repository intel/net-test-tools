#!/usr/bin/env bash

sudo brctl addbr br1
sudo ip link set br1 address 00:00:00:00:00:03
sudo brctl addif br1 tap0
sudo brctl addif br1 zeth
sudo ifconfig br1 up
