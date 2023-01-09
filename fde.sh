#!/bin/bash

: ${SHAREDIR:=/usr/share/fde}

. $SHAREDIR/luks

opt_bootloader=grub2
opt_rootdir="/"
opt_uefi_bootdir=""
opt_device=""
opt_ui=shell
opt_keyfile=""
opt_password=""

##################################################################
# Display a usage message.
# We do not document the add-secondary-key command, because it's
# purely for the installer.
##################################################################
function fde_usage {

    cat >&2 <<EOF

Usage: fde [global-options] command [cmd-options]

Global options:
  --help
	Display this message
  --root-dir
	Specify the root directory of the installed system [/].
  --device
	Specify the partition to operate on. Can be a device
	name or a mount point. Defaults to the current root
	device.
  --bootloader
	Specify the boot loader being used [grub2].
  --uefi-boot-dir
	Specify the location of the UEFI ESP [/boot/efi].
  --use-dialog
	Use the dialog(1) utility to interact with the user.
  --keyfile
	Specify the path to a LUKS key for use with tpm-enable.
  --password
	Specify the LUKS recovery password. Should be used by the
	installer only.

Commands:
  help - display this message
  passwd - change the password protecting the partition
  tpm-present - check whether a TPM2 chip is present and working
  tpm-enable - enable TPM protection
  tpm-disable - disable TPM protection
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

function fde_identify_fs_root {

    var_name=$1

    if [ -z "$opt_device" ]; then
	opt_device="$opt_rootdir"
    fi

    case $opt_device in
    /dev/*)
	fsdev="$opt_device";;
    /*)
	fsdev=$(luks_device_for_path "$opt_device")
	if [ ! -b "$fsdev" ]; then
	    fde_bad_argument "Unable to determine partition to operate on"
	fi
	;;
    *)  fde_bad_argument "Don't know how to handle device \"$opt_device\"";;
    esac

    declare -g $var_name="$fsdev"
}

long_options="help,bootloader:,device:,use-dialog,keyfile:,uefi-boot-dir:,root-dir:,password:"

if ! getopt -Q -n fdectl -l "$long_options" -o h -- "$@"; then
    fde_usage
    exit 1
fi

eval set -- $(getopt -n fdectl -l "$long_options" -o h -- "$@")

command=
while [ $# -gt 0 ]; do
    next="$1"
    shift

    case $next in
    --)
	command=$1; shift; break;;
    -h|--help)
    	fde_usage
	exit 0;;
    --bootloader)
    	opt_bootloader=$1; shift;;
    --device)
    	opt_device=$1; shift;;
    --use-dialog)
    	opt_ui=dialog;;
    --keyfile)
	opt_keyfile=$1; shift;;
    --password)
	opt_password=$1; shift;;
    --uefi-boot-dir)
	opt_uefi_bootdir=$1; shift;;
    --root-dir)
	opt_rootdir=$1; shift;;
    *)
    	fde_bad_option "Unsupported option $next";;
    esac
done

if [ -z "$command" ]; then
    fde_bad_option "Missing subcommand"
fi

if [ "$command" = "help" ]; then
    fde_usage
    exit 0
fi

if [ ! -e "$SHAREDIR/commands/$command" ]; then
    fde_bad_option "Unsupported command \"$command\""
fi


if [ "$opt_bootloader" != "grub2" -a "$opt_bootloader" != "systemd-boot" ]; then
    fde_bad_argument "Unsupported boot loader \"$opt_bootloader\""
fi

trap fde_clean_tempdir 0 1 2 11 15

. "$SHAREDIR/uefi"
if [ -n "$opt_uefi_bootdir" ]; then
    uefi_set_loader "$opt_uefi_bootdir"
fi

. "$opt_rootdir/etc/sysconfig/fde-tools"
. "$SHAREDIR/ui/$opt_ui"
. "$SHAREDIR/util"
. "$SHAREDIR/$opt_bootloader"
. "$SHAREDIR/commands/$command"
