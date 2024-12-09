#! /bin/bash

scriptfile=`readlink -f $0`
scriptdir=`dirname $scriptfile`
#export LD_LIBRARY_PATH=/home/bt/sources/openssl/openssl-3.0.2
export LD_LIBRARY_PATH=/home/bt/sources/openssl/
$scriptdir/osslsigncode $@