#! /bin/sh
set -x
cp README.md README
aclocal -I m4 && autoheader && automake --copy && autoconf
