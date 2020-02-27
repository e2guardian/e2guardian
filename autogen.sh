#! /bin/sh
set -x
cp README.md README
# remove previous generation
rm -f compile config.guess config.sub missing depcomp
aclocal -I m4 && autoheader && automake --add-missing --copy && autoconf
