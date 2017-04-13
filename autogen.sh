#! /bin/sh
set -x
cp README.md README
rm missing
aclocal -I m4 && autoheader && automake --add-missing --copy && autoconf
