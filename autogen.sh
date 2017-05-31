#! /bin/sh
set -x
cp README.md README > /dev/null 2>&1 
rm missing > /dev/null 2>&1 
aclocal -I m4 && autoheader && automake --add-missing --copy && autoconf
