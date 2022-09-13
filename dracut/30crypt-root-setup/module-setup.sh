
function get_luks_uuid {

    while read volume device keyfile options; do
	if [ "$volume" = "luks" ]; then
	    case "$device" in
	    UUID=*)
	    	echo "${device#UUID=}"
		break;;
	    esac
	fi
    done < /etc/crypttab
}

function check {

    echo "${host_fs_types[@]}"

    uuid=$(get_luks_uuid)
    test -n "$uuid"
}

function cmdline {

    :
}

depends() {
    echo 'systemd dracut-systemd'
    return 0
}

install () {

    inst "$moddir/fde-root.service" /usr/lib/systemd/system/fde-root.service
    unitfile="${initdir}/usr/lib/systemd/system/fde-root.service"

    uuid=$(get_luks_uuid)
    escaped_uuid="${uuid//-/\\x2d}"
    sed -i -e "s:@UUID@:$uuid:" \
           -e "s:@ESCAPED_UUID@:$escaped_uuid:" \
	   "$unitfile"

    echo "fde-root.service:"
    cat "$unitfile"
    echo "<<<<< end >>>>>>>"

    systemctl enable fde-root.service

    # the cryptsetup targets are already pulled in by 00systemd, but not
    # the enablement symlinks
    false && 
    inst_multiple -o \
            "$tmpfilesdir"/cryptsetup.conf \
            "$systemdutildir"/system-generators/systemd-cryptsetup-generator \
            "$systemdutildir"/systemd-cryptsetup \
            "$systemdsystemunitdir"/systemd-ask-password-console.path \
            "$systemdsystemunitdir"/systemd-ask-password-console.service \
            "$systemdsystemunitdir"/cryptsetup.target \
            "$systemdsystemunitdir"/sysinit.target.wants/cryptsetup.target \
            "$systemdsystemunitdir"/remote-cryptsetup.target \
            "$systemdsystemunitdir"/initrd-root-device.target.wants/remote-cryptsetup.target \
            systemd-ask-password systemd-tty-ask-password-agent

}
