#!/bin/sh

usage(){
cat << EOF
Usage: ${0##*/} [OPTION]...
Install clipenc and create keyboard shortcuts

Options:
 -h, --help         print this message
 --no-package       do not install the required packages
 --no-build         do not build and install clipenc
 --no-shortcuts     do not create the keyboard shortcuts
EOF
}

check_root(){
	if [ "$(id -u)" != "0" ]; then
		echo "$0 : only root can do that" >&2;
		exit 1
	fi
}


install_packages(){
	PACKAGES=""

	test_libssl=`ldconfig -p | grep libssl`
	test_libcrypto=`ldconfig -p | grep libcrypto`
	test_xclip=`which xclip`
	test_python=`which python`

	if [ -z "$test_libssl"] || [ -z "$test_libcrypto"] ; then
		PACKAGES="$PACKAGES libssl-dev"
	fi
	if [ -z "$test_xclip" ]; then
		PACKAGES="$PACKAGES xclip"
	fi
	if [ -z "$test_python" ]; then
		PACKAGES="$PACKAGES python"
	fi

	if [ -n "$PACKAGES" ]; then
		apt=`command -v apt-get`
		yum=`command -v yum`
		if [ -n "$apt" ]; then
			apt-get update
			apt-get install -y $PACKAGES || exit 1 
		elif [ -n "$yum" ]; then
			yum -y install -y $PACKAGES || exit 1
		else
			echo "error : install not supported on this system" >&2;
			exit 1;    
		fi
	fi
}

build(){
	make || exit 1
	make install || exit 1
	make clean
}

keybd_biding(){
	test_gsettings=`which gsettings`
	if [ -n "$test_gsettings" ]; then
		./keybd_binding.py 'clipenc encryption' 'c_enc' '<Primary>e'
		./keybd_binding.py 'clipenc decryption' 'c_dec' '<Primary>d'
		./keybd_binding.py 'clipenc key generation' 'c_gen' '<Primary>g'
	else
		echo "clipenc keyboard shortcuts not created. Please refer to the documentation of your sytem for manual binding." >&2;
	fi
}

PACKAGE_F="0"
BUILD_F="0"
KBD_BINDING_F="0"

while :; do
    case $1 in
        -h|--help) 
            usage
            exit
            ;;
        --no-package)
            PACKAGE_F="1" 
            ;;
        --no-build)
            BUILD_F="1" 
            ;;
        --no-shortcuts)
            KBD_BINDING_F="1" 
            ;;
        -?*)
            printf 'WARN: Unknown option (ignored): %s\n' "$1" >&2
            ;;
        *)               
    break
    esac

    shift
done

check_root

if [ "${PACKAGE_F}" = "0" ]; then
	install_packages
fi
if [ "${BUILD_F}" = "0" ]; then
	build
fi
if [ "${KBD_BINDING_F}" = "0" ]; then
	keybd_biding
fi	

exit
