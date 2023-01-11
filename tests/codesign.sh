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
	local _cmd="$@";
	$_cmd;
	if [ $? -ne 0 ]
	then
		Error "run [$_cmd] error[$?]"
		exit 5
	fi
	Debug "run [$_cmd] succ";
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

function __genkey()
{
	local gtype=$1;
	local goutput=$2;
	local gbits=$3;
	local passwd=$4;

	if [ "$gtype" = "rsa" ]
	then
		crypto="-algorithm RSA -pkeyopt rsa_keygen_bits:$gbits";
	else
		crypto="-algorithm EC  -pkeyopt ec_paramgen_curve:secp384r1 -pkeyopt ec_param_enc:named_curve";
	fi
	run_command_must_succ openssl genpkey ${crypto} -aes-256-cbc -pass "pass:${passwd}" -out $goutput;
}

function __genpubkey()
{
	local _privpem=$1;
	local _pubpem=$2;
	local _passin=$3;

	run_command_must_succ openssl pkey -passin "pass:${_passin}" -in "${_privpem}" -pubout -out "${_pubpem}"
}

DEFAULT_KEY_TYPE=rsa;
DEFAULT_PRIVATE_FILE=root_private.pem;
DEFAULT_CERT_FILE=root_cert.pem;
DEFAULT_SIGN_PRIVATE=sign_private.pem;
DEFAULT_SIGN_PUBLIC=sign_public.pem;
DEFAULT_SIGN_CSR=sign_csr.pem;
DEFAULT_SIGN_CERT=sign_cert.pem;
DEFAULT_SIGN_P12=sign.p12;
DEFAULT_GPG_ASC=gpg.asc;
DEFAULT_GPG_FILE=gpg.gpg;
DEFAULT_GPG_PUBFILE=gpg.pub;
DEFAULT_GPG_PRIVFILE=gpg.priv;
DEFAULT_ECPEM=ec.pem;
DEFAULT_ECTYPE=secp521r1;
DEFAULT_ECHASH=echash.txt;
DEFAULT_ECFILE=ecfile.txt;
DEFAULT_SIGFILE=sig.txt;
DEFAULT_ECDIGEST=sha256;

function genkey_handler()
{
	local gtype=$DEFAULT_KEY_TYPE;
	local goutput=$DEFAULT_PRIVATE_FILE;

	if [ -n "$basedir" ]
	then
		goutput="$basedir/$goutput";
	fi

	if [ ${#subnargs[@]} -gt 0 ]
	then
		gtype=${subnargs[0]};
	fi

	if [ ${#subnargs[@]} -gt 1 ]
	then
		goutput=${subnargs[1]};
	fi

	Debug "gtype [$gtype] goutput [$goutput]";
	__genkey "$gtype" "$goutput" "$bits" "$passin";
}

function mkcert_inner()
{
	local _cnname=$1;
	local _privpem=$2;
	local _certpem=$3;
	local _password=$4;
	local _days=$5;
	local _tmpcfg=`mktemp`;

	cat > $_tmpcfg <<CONFIGEOF
[req]
encrypt_key = yes
prompt = no
utf8 = yes
string_mask = utf8only
distinguished_name = dn
x509_extensions = v3_ca

[v3_ca]
subjectKeyIdentifier = hash
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign

[dn]
CN = ${_cnname} Root CA
CONFIGEOF

	run_command_must_succ openssl req -batch -verbose -new -sha256 -x509 -days $_days -passin "pass:${_password}" -key "$_privpem" -out "$_certpem" -config $_tmpcfg;
	#rm -f $_tmpcfg;

}

function mkcert_handler()
{
	local _privpem=$DEFAULT_PRIVATE_FILE;
	local _rootpriv=$DEFAULT_PRIVATE_FILE;
	local _certpem=$DEFAULT_CERT_FILE;

	if [ -n "$basedir" ]
	then
		_privpem="$basedir/$_privpem";
		_certpem="$basedir/$_certpem";
	fi

	if [ ${#subnargs[@]} -gt 0 ]
	then
		_privpem=${subnargs[0]};
	fi

	if [ ${#subnargs[@]} -gt 1 ]
	then
		_certpem=${subnargs[1]};
	fi

	mkcert_inner "$cnname" "$_privpem" "$_certpem" "$passin" "$days";
}

function mksigncert_handler()
{
	local _privpem=$DEFAULT_SIGN_PRIVATE;
	local _pubpem=$DEFAULT_SIGN_PUBLIC;
	local _csrpem=$DEFAULT_SIGN_CSR;
	local _certpem=$DEFAULT_SIGN_CERT;
	local _rootcert=$DEFAULT_CERT_FILE;
	local _rootpriv=$DEFAULT_PRIVATE_FILE;
	local _signp12=$DEFAULT_SIGN_P12;
	local _gtype=rsa;
	local _csrtmpcfg=`mktemp`

	if [ -n "$basedir" ]
	then
		_privpem="$basedir/$_privpem";
		_pubpem="$basedir/$_pubpem";
		_csrpem="$basedir/$_csrpem";
		_certpem="$basedir/$_certpem";
		_rootcert="$basedir/$_rootcert";
		_rootpriv="$basedir/$_rootpriv";
		_signp12="$basedir/$_signp12";
	fi	

	if [ ${#subnargs[@]} -gt 0 ]
	then
		_gtype=${subnargs[0]};
	fi

	if [ ${#subnargs[@]} -gt 1 ]
	then
		_privpem=${subnargs[1]};
	fi

	if [ ${#subnargs[@]} -gt 2 ]
	then
		_csrpem=${subnargs[2]};
	fi

	if [ ${#subnargs[@]} -gt 3 ]
	then
		_pubpem=${subnargs[3]};
	fi

	if [ ${#subnargs[@]} -gt 4 ]
	then
		_certpem=${subnargs[4]};
	fi

	if [ ${#subnargs[@]} -gt 5 ]
	then
		_rootcert=${subnargs[5]};
	fi

	if [ ${#subnargs[@]} -gt 6 ]
	then
		_rootpriv=${subnargs[6]};
	fi

	if [ ${#subnargs[@]} -gt 7 ]
	then
		_signp12=${subnargs[7]};
	fi

	cat > $_csrtmpcfg <<CONFIGEOF
[req]
encrypt_key = yes
prompt = no
utf8 = yes
string_mask = utf8only
distinguished_name = dn
req_extensions = v3_req

[v3_req]
subjectKeyIdentifier = hash
keyUsage = critical, digitalSignature
# msCodeInd = Microsoft Individual Code Signing
# msCodeCom = Microsoft Commercial Code Signing
extendedKeyUsage = critical, codeSigning, msCodeInd

[dn]
CN = ${cnname} Code Signing Authority
CONFIGEOF


	__genkey "$_gtype" "$_privpem" "$bits" "$passin";
	__genpubkey "$_privpem"  "$_pubpem" "$passin";
	run_command_must_succ openssl req -batch -verbose -new -sha256  -passin "pass:${passin}" -key "$_privpem" -out "$_csrpem" -config "${_csrtmpcfg}";
	run_command_must_succ openssl x509 -req -sha256 -days $days -extfile "$_csrtmpcfg" -extensions v3_req -in "${_csrpem}" -passin "pass:${passin}" -CA "${_rootcert}" -CAkey "${_rootpriv}" -CAcreateserial -out "${_certpem}"

	run_command_must_succ openssl pkcs12 -export -keypbe aes-256-cbc -certpbe aes-256-cbc -macalg sha256 -passout "pass:${passin}" -passin "pass:${passin}" -inkey "${_privpem}" -in "${_certpem}" -chain -CAfile "${_rootcert}" -out "${_signp12}"
}

function gpgbatch_handler()
{
	local _signp12=$DEFAULT_SIGN_P12;
	local _gpgasc=$DEFAULT_GPG_ASC;
	local _gpgfile=$DEFAULT_GPG_FILE;

	if [ -n "$basedir" ]
	then
		_signp12="$basedir/$_signp12";
		_gpgasc="$basedir/$_gpgasc";
		_gpgfile="$basedir/$_gpgfile";
	fi	

	if [ ${#subnargs[@]} -gt 0 ]
	then
		_signp12=${subnargs[0]};
	fi

	if [ ${#subnargs[@]} -gt 1 ]
	then
		_gpgasc=${subnargs[1]};
	fi

	if [ ${#subnargs[@]} -gt 2 ]
	then
		_gpgfile=${subnargs[2]};
	fi

	run_command_must_succ gpg --batch --verbose --yes --passphrase "${passin}" --cipher-algo aes256 --digest-algo sha512 --s2k-cipher-algo aes256 --s2k-digest-algo sha512 --compress-algo none --set-filename 'ff' --output "${_gpgasc}" --armor --symmetric "${_signp12}"

	run_command_must_succ gpg --batch --verbose --yes --passphrase "${passin}"  --cipher-algo aes256 --digest-algo sha512 --s2k-cipher-algo aes256 --s2k-digest-algo sha512 --compress-algo none --set-filename 'ff' --output "${_gpgfile}" --symmetric "${_signp12}"

}

function gpggenkey_handler()
{
	local _pubfile=$DEFAULT_GPG_PUBFILE;
	local _privfile=$DEFAULT_GPG_PRIVFILE;
	local _tmpf=`mktemp`

	if [ -n "$basedir" ]
	then
		_pubfile="$basedir/$_pubfile";
		_privfile="$basedir/$_privfile";
	fi	

	if [ ${#subnargs[@]} -gt 0 ]
	then
		_pubfile=${subnargs[0]};
	fi

	if [ ${#subnargs[@]} -gt 1 ]
	then
		_privfile=${subnargs[1]};
	fi

cat > $_tmpf <<EOF
    #%echo Generating a basic OpenPGP key
    Key-Type: RSA
    Key-Length: 2048
    Subkey-Type: RSA
    Subkey-Length: 2048
    Name-Real: $username
    Name-Comment: $username comment
    Name-Email: $username@user.info
    Expire-Date: 0
    Passphrase: $passin
    %pubring $_pubfile
    %secring $_privfile
    # Do a commit here, so that we can later print "done" :-)
    %commit
    #%echo done
EOF
	run_command_must_succ gpg --batch --verbose --gen-key $_tmpf
}

function signexe_handler()
{
	local _exefile="";
	local _signp12=$DEFAULT_SIGN_P12;
	local _ossl="$_parentdir/osslsigncode"
	local _out1="";
	local _tsweb="https://tsa.swisssign.net";

	if [ -n "$basedir" ]
	then
		_signp12="$basedir/$_signp12";
	fi	

	if [ ${#subnargs[@]} -gt 0 ]
	then
		_exefile=${subnargs[0]};
	fi

	if [ ${#subnargs[@]} -gt 1 ]
	then
		_signp12=${subnargs[1]};
	fi

	if [ -z "$_exefile" ]
	then
		echo "must specified exe file" >&2
		exit 4
	fi

	_out1="${_exefile}.out1"

	run_command_must_succ "$_ossl" sign -h sha256 -in "${_exefile}" -out "${_out1}" -ts "${_tsweb}" -pkcs12 "${_signp12}" -pass \"${passin}\"
}

function ecgen_handler()
{
	local _ecpem="$DEFAULT_ECPEM";
	local _ectype="$DEFAULT_ECTYPE";

	if [ -n "$basedir" ]
	then
		_ecpem="$basedir/$_ecpem";
	fi	

	if [ ${#subnargs[@]} -gt 0 ]
	then
		_ecpem=${subnargs[0]};
	fi

	if [ ${#subnargs[@]} -gt 1 ]
	then
		_ectype=${subnargs[1]};
	fi

	run_command_must_succ openssl ecparam -genkey -name "$_ectype" -out "$_ecpem" -outform PEM;
}

function ecsign_handler()
{
	local _input="";
	local _hashfile="$DEFAULT_ECHASH";
	local _ecpem="$DEFAULT_ECPEM";
	local _sigfile="$DEFAULT_SIGFILE";
	local _ecdgst="$DEFAULT_ECDIGEST";

	if [ -n "$basedir" ]
	then
		_ecpem="$basedir/$_ecpem";
		_hashfile="$basedir/$_hashfile";
		_sigfile="$basedir/$_sigfile";
	fi

	if [ ${#subnargs[@]} -gt 0 ]
	then
		_input=${subnargs[0]};
	fi

	if [ ${#subnargs[@]} -gt 1 ]
	then
		_hashfile=${subnargs[1]};
	fi

	if [ ${#subnargs[@]} -gt 2 ]
	then
		_ecpem=${subnargs[2]};
	fi

	if [ ${#subnargs[@]} -gt 3 ]
	then
		_sigfile=${subnargs[3]};
	fi


	if [ ${#subnargs[@]} -gt 4 ]
	then
		_ecdgst=${subnargs[4]};
	fi

	if [ -z "$_input" ]
	then
		Error "please specified input";
		exit 4;
	fi

	if [ ! -f "$_input" ]
	then
		Error "[$_input] not file";
		exit 4;
	fi

	run_command_must_succ openssl dgst "-${_ecdgst}" -binary -out "$_hashfile" "$_input" ;
	run_command_must_succ openssl pkeyutl -sign -inkey "$_ecpem" -in "$_hashfile" -out "$_sigfile";

}

function ecsign_handler()
{
	local _hashfile="$DEFAULT_ECHASH";
	local _ecpem="$DEFAULT_ECPEM";
	local _sigfile="$DEFAULT_SIGFILE";

	if [ -n "$basedir" ]
	then
		_ecpem="$basedir/$_ecpem";
		_hashfile="$basedir/$_hashfile";
		_sigfile="$basedir/$_sigfile";
	fi

	if [ ${#subnargs[@]} -gt 0 ]
	then
		_hashfile=${subnargs[0]};
	fi

	if [ ${#subnargs[@]} -gt 1 ]
	then
		_ecpem=${subnargs[1]};
	fi

	if [ ${#subnargs[@]} -gt 2 ]
	then
		_sigfile=${subnargs[2]};
	fi


	run_command_must_succ openssl pkeyutl -verify -inkey "$_ecpem" -in "$_hashfile" -sigfile "$_sigfile";

}

read -r -d '' OPTIONS<<EOFMM
	{
		"verbose|v" : "+",
		"pkcs12|P" : "",
		"passin" : "",
		"passout" : "",
		"temppass|T" : "",
		"days" : 365,
		"bits|B" : 2048,
		"cnname" : "samplecn",
		"basedir" : "",
		"username" : "$USER",
		"sign<SUBCOMMAND>##to sign file##" : {
			"\$" : "+"
		},
		"genkey<SUBCOMMAND>##[rsa|ec] [outname] default outname root_private.pem##" : {
			"\$" : "*"
		},
		"mkcert<SUBCOMMAND>##privpem certpem default privpem root_private.pem default certpem root_cert.pem ##" : {
			"\$" : "*"
		},
		"mksigncert<SUBCOMMAND>##[rsa|dsa] [privpem] [certpem] [pubpem] [certpem] [rootcert] [rootpriv] [signp12] default privpem $DEFAULT_SIGN_PRIVATE default certpem $DEFAULT_SIGN_CSR default pubpem $DEFAULT_SIGN_PUBLIC certpem default $DEFAULT_SIGN_CERT rootcert default $DEFAULT_CERT_FILE rootpriv default $DEFAULT_PRIVATE_FILE default signp12 $DEFAULT_SIGN_P12 ##" : {
			"\$" : "*"
		},
		"gpgbatch<SUBCOMMAND>##[signp12] [gpgasc] [gpgfile]  signp12 default $DEFAULT_SIGN_P12 gpgasc default $DEFAULT_GPG_ASC gpgfile $DEFAULT_GPG_FILE##" : {
			"\$" : "*"
		},
		"gpggenkey<SUBCOMMAND>##[pubfile] [secretfile] pubfile default $DEFAULT_GPG_PUBFILE secretfile default $DEFAULT_GPG_PRIVFILE##" : {
			"\$" : "*"
		},
		"signexe<SUBCOMMAND>##exefile [signp12] to sign exe file##" : {
			"\$" : "+"
		},
		"batch<SUBCOMMAND>##to pack genkey mkcert mksigncert command##" : {
			"\$" : "*"
		},
		"ecgen<SUBCOMMAND>##[ecpem] [typename] to generate ec##" : {
			"\$" : "*"
		},
		"ecsign<SUBCOMMAND>##[inputfile] [hashfile] [ecpem] [sigfile] [dgsttype] to sign with ec##" : {
			"\$" : "*"
		},
		"ecverify<SUBCOMMAND>##[hashfile] [ecpem] [sigfile] to verify with ec##" : {
			"\$" : "*"
		}
	}
EOFMM


parse_command_line "$OPTIONS" $@

test_verbose=$verbose
if [ "$SUBCOMMAND" = "sign" ]
then
	sign_handler
elif [ "$SUBCOMMAND" = "genkey" ]
then
	genkey_handler
elif [ "$SUBCOMMAND" = "mkcert" ]
then
	mkcert_handler
elif [ "$SUBCOMMAND" = "mksigncert" ]
then
	mksigncert_handler
elif [ "$SUBCOMMAND" = "gpgbatch" ]
then
	gpgbatch_handler
elif [ "$SUBCOMMAND" = "gpggenkey" ]
then
	gpggenkey_handler
elif [ "$SUBCOMMAND" = "batch" ]
then
	genkey_handler
	mkcert_handler
	mksigncert_handler	
elif [ "$SUBCOMMAND" = "signexe" ]
then
	signexe_handler
elif [ "$SUBCOMMAND" = "ecgen" ]
then
	ecgen_handler
elif [ "$SUBCOMMAND" = "ecsign" ]
then
	ecsign_handler
elif [ "$SUBCOMMAND" = "ecverify" ]
then
	ecverify_handler
else
	Error "not supported subcommand[$SUBCOMMAND]"
	exit 4
fi