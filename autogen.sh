#! /bin/sh
set -x
cp README.md README
if [ ! -d "m4" ];then
mkdir m4
fi
aclocal -I m4 && autoheader && automake --add-missing --copy && autoconf
