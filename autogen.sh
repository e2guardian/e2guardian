#! /bin/sh
set -x
aclocal -I m4 && autoheader && automake --add-missing --copy && autoconf
