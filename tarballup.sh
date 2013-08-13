#!/bin/sh
make distclean
./autogen.sh
./configure
make clean
make
make distcheck
make dist
