#!/usr/bin/env bash

ip link set dev br1 down
brctl delbr br1
