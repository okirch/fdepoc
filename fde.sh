#!/bin/bash

: ${SHAREDIR:-/usr/share/fde}

. $SHAREDIR/luks

opt_bootloader=grub2
opt_device=/
opt_ui=shell

function fde_usage {

    cat >&2 <<EOF

Usage: fde [global-options] command [cmd-options]

Global options:
  --help
	Display this message
  --device
	Specify the partition to operate on. Can be a device
	name or a mount point. Defaults to the current root
	device.
  --bootloader
	Specify the boot loader being used [grub2].
  --use-dialog
	Use the dialog(1) utility to interact with the user.

Commands:
  passwd - change the password protecting the partition
EOF
}

function fde_bad_option {

    echo "Error: $*" >&2
    fde_usage
    exit 1
}

function fde_bad_argument {

    echo "Error: $*" >&2
    exit 2
}

long_options="help,bootloader:,device:,use-dialog"

if ! getopt -Q -n fde -l "$long_options" -o h -- "$@"; then
    fde_usage
    exit 1
fi

eval set $(getopt -n fde -l "$long_options" -o h -- "$@")

while [ $# -gt 0 ]; do
    next="$1"; shift
    case $next in
    -h|--help)
    	fde_usage
	exit 0;;
    --bootloader)
    	opt_bootloader=$1; shift;;
    --device)
    	opt_device=$1; shift;;
    --use-dialog)
    	opt_ui=dialog;;
    -*)
    	fde_bad_option "Unsupported option $next";;
    *)	command=$next
    	break;;
    esac
done

if [ ! -e "$SHAREDIR/commands/$command" ]; then
    fde_bad_option "Unsupported command \"$command\""
fi

case $opt_device in
/dev/*) : ;;
/*)
    opt_device=$(luks_device_for_path "$opt_device")
    if [ ! -b "$opt_device" ]; then
	fde_bad_argument "Unable to determine partition to operate on"
    fi
    ;;
*)  fde_bad_argument "Don't know how to handle device \"$opt_device\"";;
esac

if [ "$opt_bootloader" != "grub2" -a "$opt_bootloader" != "systemd-boot" ]; then
    fde_bad_argument "Unsupported boot loader \"$opt_bootloader\""
fi

. /etc/sysconfig/fde
. "$SHAREDIR/ui/$opt_ui
. "$SHAREDIR/$opt_bootloader
. "$SHAREDIR/commands/$command"
