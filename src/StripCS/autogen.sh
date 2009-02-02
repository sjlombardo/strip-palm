#!/bin/sh
# Run this to generate all the initial makefiles, etc.

srcdir=`dirname $0`
test -z "$srcdir" && srcdir=.

ORIGDIR=`pwd`
cd $srcdir
PROJECT=StripCS
VERSION=0.05i
TEST_TYPE=-f
FILE=StripCS.c

DIE=0

(autoconf --version) < /dev/null > /dev/null 2>&1 || {
	echo
	echo "You must have autoconf installed to compile $PROJECT."
	echo "Download the appropriate package for your distribution,"
	echo "or get the source tarball at ftp://ftp.gnu.org/pub/gnu/"
	DIE=1
}

if test "$DIE" -eq 1; then
	exit 1
fi

test $TEST_TYPE $FILE || {
	echo "You must run this script in the top-level $PROJECT directory"
	exit 1
}

if test -z "$*"; then
	echo "I am going to run ./configure with no arguments - if you wish "
        echo "to pass any to it, please specify them on the $0 command line."
	echo ""
fi

case $CC in
*xlc | *xlc\ * | *lcc | *lcc\ *) am_opt=--include-deps;;
esac

if test -z "$ACLOCAL_FLAGS"; then

        for file in $m4list
        do
                if [ ! -f "$acdir/$file" ]; then
                        echo "WARNING: aclocal's directory is $acdir, but..."
                        echo "         no file $acdir/$file"
                        echo "         You may see fatal macro warnings below."
                        echo "         If these files are installed in /some/dir, set the ACLOCAL_FLAGS "
                        echo "         environment variable to \"-I /some/dir\", or install"
                        echo "         $acdir/$file."
                        echo ""
                fi
        done
fi

autogen_dirs="."

for i in $autogen_dirs; do
	echo "Processing $PROJECT $VERSION parameters $i..."
	echo "---------------------------------------"

	cd $i
	aclocal $ACLOCAL_FLAGS

	# optionally feature autoheader
	if grep AM_CONFIG_HEADER configure.in >/dev/null ; then
		(autoheader --version)  < /dev/null > /dev/null 2>&1 && autoheader
	fi
 	autoconf
done

cd $ORIGDIR

$srcdir/configure --enable-maintainer-mode "$@"

echo 
echo "Now type 'make' to compile $PROJECT."
