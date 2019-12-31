#! /bin/bash

source extargsparse4sh
if [ $? -ne 0 ]
then
	echo "please download extargsparse4sh from https://github.com/jeppeter/extargsparse4sh" >&2
	exit 4
fi


_srcfile=`readlink -f $0`
_srcdir=`dirname $_srcfile`
_parentdir=`readlink -f "$_srcdir/.."`

EXTARGSPARSE_LOGLEVEL=0
DEBUG_LEVEL=2
INFO_LEVEL=1
ERROR_LEVEL=0
test_verbose=0


function __Debug()
{
	local _fmt=$1
	shift
	local _backstack=0
	if [ $# -gt 0 ]
		then
		_backstack=$1
	fi
	
	_fmtstr=""
	if [ $test_verbose -gt 2 ]
		then
		_fmtstr="${BASH_SOURCE[$_backstack]}:${BASH_LINENO[$_backstack]} "
	fi

	_fmtstr="$_fmtstr$_fmt"
	echo -e "$_fmtstr" >&2
}

function Debug()
{
	local _fmt=$1
	shift
	local _backstack=0
	if [ $# -gt 0 ]
		then
		_backstack=$1
	fi
	_backstack=`expr $_backstack \+ 1`
	
	if [ $test_verbose -ge $DEBUG_LEVEL ]	
		then
		__Debug "$_fmt" "$_backstack"
	fi
	return
}

function Info()
{
	local _fmt=$1
	shift
	local _backstack=0
	if [ $# -gt 0 ]
		then
		_backstack=$1
	fi
	_backstack=`expr $_backstack \+ 1`
	
	if [ $test_verbose -ge $INFO_LEVEL ]
		then
		__Debug "$_fmt" "$_backstack"
	fi
	return
}


function Error()
{
	local _fmt=$1
	shift
	local _backstack=0
	if [ $# -gt 0 ]
		then
		_backstack=$1
	fi
	_backstack=`expr $_backstack \+ 1`
	
	if [ $test_verbose -ge $ERROR_LEVEL ]
		then
		__Debug "$_fmt" "$_backstack"
	fi
	return
}

function run_command_must_succ()
{
	Debug "run [$@]"
	$@
	if [ $? -ne 0 ]
	then
		Error "run [$@] error[$?]"
		exit 5
	fi
}

function __sign_inner()
{
	local _f=$1
	local _tmppass=$2
	local _tmpname
	Debug "sign [$_f]"
	if [ -z "$_tmppass" ]
	then
		_tmppass=`dd if=/dev/urandom bs=1 count=16 2>/dev/null | md5sum -b | awk '{print $1}' | sed 's/\r\n//g'`
	fi
	_tmpname=`dd if=/dev/urandom bs=1 count 16 2>/dev/null | md5sum -b | awk '{print $1}' | sed 's/\r\n//g'`
	Debug "tmppass [$_tmppass] _tmpname[$_tmpname]"
	Debug "convert [$pkcs12] => PEM [${_tmpname}.pem]"
	if [ -n "$password" ]
	then
		#run_command_must_succ openssl pkcs12 -in $pkcs12 -passin pass:$password -nocerts -nodes -out $_tmpname.pem
		openssl pkcs12 -in $pkcs12 -passin pass:$password -nocerts -nodes -out $_tmpname.pem
	else
		#run_command_must_succ openssl pkcs12 -in "$pkcs12" -nocerts -nodes -out $_tmpname.pem
		openssl pkcs12 -in "$pkcs12" -nocerts -nodes -out $_tmpname.pem
	fi
	if [ $? -ne 0 ]
	then
		Error "run [$?]"
		exit 5
	fi

	Debug "extract rsa => [${_tmpname}_key.pem]"
	#run_command_must_succ openssl rsa -in $_tmpname.pem -out ${_tmpname}_key.pem -passout pass:${_tmppass}
	openssl rsa -in $_tmpname.pem -out ${_tmpname}_key.pem -passout pass:${_tmppass}

	Debug "extract rsa DER [${_tmpname}.der]"
	#run_command_must_succ openssl rsa -in $_tmpname.pem -outform DER -out ${_tmpname}.der -passout pass:${_tmppass}
	openssl rsa -in $_tmpname.pem -outform DER -out ${_tmpname}.der -passout pass:${_tmppass}

	Debug "extract rsa PVK [${_tmpname}.pvk]"
	#run_command_must_succ openssl rsa -in $_tmpname.pem -outform PVK -out ${_tmpname}.pvk -passout pass:${_tmppass}
	openssl rsa -in $_tmpname.pem -outform PVK -out ${_tmpname}.pvk -passout pass:${_tmppass}

	Debug "extract cert [${_tmpname}_cert.pem]"
	if [ -n "$password" ]
	then
		#run_command_must_succ openssl pkcs12 -in "$pkcs12" -passin pass:$password -nokeys -out ${_tmpname}_cert.pem
		openssl pkcs12 -in "$pkcs12" -passin pass:$password -nokeys -out ${_tmpname}_cert.pem
	else
		#run_command_must_succ openssl pkcs12 -in "$pkcs12" -nokeys -out ${_tmpname}_cert.pem
		openssl pkcs12 -in "$pkcs12" -nokeys -out ${_tmpname}_cert.pem
	fi

	Debug "convert to SPC [${_tmpname}.spc]"
	#run_command_must_succ openssl crl2pkcs7 -nocrl -certfile ${_tmpname}_cert.pem -outform DER -out ${_tmpname}.spc
	openssl crl2pkcs7 -nocrl -certfile ${_tmpname}_cert.pem -outform DER -out ${_tmpname}.spc


	#run_command_must_succ "$_parentdir/osslsigncode" sign -spc ${_tmpname}.spc -key ${_tmpname}.pem "$_f" "${_f}.1"
	Debug "1"
	"$_parentdir/osslsigncode" sign -spc ${_tmpname}.spc -key ${_tmpname}.pem "$_f" "${_f}.1"
	#run_command_must_succ "$_parentdir/osslsigncode" sign -certs ${_tmpname}.spc -key ${_tmpname}_key.pem -pass ${_tmppass} "$_f" "${_f}.2"
	Debug "2"
	"$_parentdir/osslsigncode" sign -certs ${_tmpname}.spc -key ${_tmpname}_key.pem -pass ${_tmppass} "$_f" "${_f}.2"
	#run_command_must_succ "$_parentdir/osslsigncode" sign -certs ${_tmpname}_cert.pem -key ${_tmpname}_key.pem -pass ${_tmppass} "$_f" "${_f}.3"
	Debug "3"
	"$_parentdir/osslsigncode" sign -certs ${_tmpname}_cert.pem -key ${_tmpname}_key.pem -pass ${_tmppass} "$_f" "${_f}.3"
	#run_command_must_succ "$_parentdir/osslsigncode" sign -certs ${_tmpname}.spc -key ${_tmpname}.der "$_f" "${_f}.4"
	Debug "4"
	"$_parentdir/osslsigncode" sign -certs ${_tmpname}.spc -key ${_tmpname}.der "$_f" "${_f}.4"
	Debug "5"
	#run_command_must_succ "$_parentdir/osslsigncode" sign -pkcs12 "$pkcs12" -pass $password "$_f" "${_f}.5"
	"$_parentdir/osslsigncode" sign -pkcs12 "$pkcs12" -pass $password "$_f" "${_f}.5"
	Debug "6"
	#run_command_must_succ "$_parentdir/osslsigncode" sign -certs ${_tmpname}.spc -key ${_tmpname}.pvk -pass ${_tmppass} "${_f}" "${_f}.6"
	"$_parentdir/osslsigncode" sign -certs ${_tmpname}.spc -key ${_tmpname}.pvk -pass ${_tmppass} "${_f}" "${_f}.6"

	return 0
}

function sign_handler() 
{
	if [ "$pkcs12" = "" ]
	then
		Error "no pkcs12 specified"
		exit 4
	fi

	for _i in ${subnargs[@]}
	do
		__sign_inner "$_i" "$temppass"
	done

}

read -r -d '' OPTIONS<<EOFMM
	{
		"verbose|v" : "+",
		"pkcs12|P" : "",
		"password|p" : "",
		"temppass|T" : "",
		"sign<SUBCOMMAND>##to sign file##" : {
			"\$" : "+"
		}
	}
EOFMM


parse_command_line "$OPTIONS" $@

test_verbose=$verbose
if [ "$SUBCOMMAND" = "sign" ]
then
	sign_handler
else
	Error "not supported subcommand[$SUBCOMMAND]"
	exit 4
fi