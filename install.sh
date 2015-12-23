#!/bin/sh

apt-get install libssl-dev
apt-get install xclip
make
make install
make clean
