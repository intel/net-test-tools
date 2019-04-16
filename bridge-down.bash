#!/usr/bin/env bash

sudo ip link set dev br1 down
sudo brctl delbr br1
sudo ip link delete zeth
