#!/usr/bin/env bash
#
# Copyright © 2018-2019, Intel Corporation.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms and conditions of the GNU Lesser General Public License,
# version 2.1, as published by the Free Software Foundation.
#
# This program is distributed in the hope it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.
#

QUIT=0

trap quit INT TERM

quit() {
    QUIT=1
}

while [[ $QUIT -ne 1 ]]; do
    sudo ./slipcat --tap="192.0.2.2" --tap-mac=00:00:00:00:00:02 $@
    sudo ./bridge-down.bash
done
