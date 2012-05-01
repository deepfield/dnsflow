#!/bin/sh

#libtoolize --copy --force
aclocal $ACLOCAL_FLAGS || exit;
autoheader || exit;
touch stamp-h
automake --add-missing --copy;
autoconf || exit;
