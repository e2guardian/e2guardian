#! /bin/sh
set -x
cp README.md README
aclocal -I m4 && autoheader && automake --add-missing --copy && autoconf
