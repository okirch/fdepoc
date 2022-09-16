#!/bin/bash
# Copyright (c) 2021 SUSE LLC
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# 
#======================================
# Functions...
#--------------------------------------
test -f /.kconfig && . /.kconfig
test -f /.profile && . /.profile

set -euxo pipefail

#======================================
# Greeting...
#--------------------------------------
echo "Configure image: [$kiwi_iname]-[$kiwi_profiles]..."

#======================================
# This is a workaround - someone,
# somewhere needs to load the xts crypto
# module, otherwise luksOpen will fail
#--------------------------------------
modprobe xts || true

#======================================
# add missing fonts
#--------------------------------------
# Systemd controls the console font now
echo FONT="eurlatgr.psfu" >> /etc/vconsole.conf

#======================================
# prepare for setting root pw, timezone
#--------------------------------------
echo "** reset machine settings"
rm -f /etc/machine-id \
      /var/lib/zypp/AnonymousUniqueId \
      /var/lib/systemd/random-seed

#======================================
# Specify default systemd target
#--------------------------------------
baseSetRunlevel multi-user.target

#======================================
# Import trusted rpm keys
#--------------------------------------
suseImportBuildKey

#======================================
# Enable sshd
#--------------------------------------
systemctl enable sshd.service

if [ -e /etc/cloud/cloud.cfg ]; then
        # not useful for cloud
        systemctl mask systemd-firstboot.service

        systemctl enable cloud-init-local
        systemctl enable cloud-init
        systemctl enable cloud-config
        systemctl enable cloud-final
else
        # Enable jeos-firstboot
        mkdir -p /var/lib/YaST2
        touch /var/lib/YaST2/reconfig_system

        systemctl mask systemd-firstboot.service
        systemctl enable jeos-firstboot.service
fi

#=====================================
# Configure /etc overlay if needed
#-------------------------------------

if [ -x /usr/sbin/setup-fstab-for-overlayfs ]; then 
	# The %post script can't edit /etc/fstab sys due to https://github.com/OSInside/kiwi/issues/945
	# so use the kiwi custom hack
	cat >/etc/fstab.script <<"EOF"
#!/bin/sh
set -eux

/usr/sbin/setup-fstab-for-overlayfs
# If /var is on a different partition than /...
if [ "$(findmnt -snT / -o SOURCE)" != "$(findmnt -snT /var -o SOURCE)" ]; then
	# ... set options for autoexpanding /var
	gawk -i inplace '$2 == "/var" { $4 = $4",x-growpart.grow,x-systemd.growfs" } { print $0 }' /etc/fstab
fi
EOF
	# ONIE additions
	if [[ "$kiwi_profiles" == *"onie"* ]]; then
		systemctl enable onie-adjust-boottype
		# For testing:
		echo root:linux | chpasswd
		systemctl enable salt-minion

	cat >>/etc/fstab.script <<"EOF"
# Grow the root filesystem. / is mounted read-only, so use /var instead.
gawk -i inplace '$2 == "/var" { $4 = $4",x-growpart.grow,x-systemd.growfs" } { print $0 }' /etc/fstab
# Remove the entry for the EFI partition
gawk -i inplace '$2 != "/boot/efi"' /etc/fstab
EOF
	fi

	chmod a+x /etc/fstab.script

	# To make x-systemd.growfs work from inside the initrd
	cat >/etc/dracut.conf.d/50-microos-growfs.conf <<"EOF"
install_items+=" /usr/lib/systemd/systemd-growfs "
force_drivers+=" xts dm-crypt "
EOF

	# Use the btrfs storage driver. This is usually detected in %post, but with kiwi
	# that happens outside of the final FS.
	if [ -e /etc/containers/storage.conf ]; then
		sed -i 's/driver = "overlay"/driver = "btrfs"/g' /etc/containers/storage.conf
	fi

	# Adjust zypp conf (no needed on transactional system)
	sed -i 's/^multiversion =.*/multiversion =/g' /etc/zypp/zypp.conf
fi

# Enable firewalld if installed
if [ -x /usr/sbin/firewalld ]; then
        systemctl enable firewalld.service
fi

# Enable NetworkManager if installed
if rpm -q --whatprovides NetworkManager >/dev/null; then
        systemctl enable NetworkManager.service
fi

#======================================
# Add repos from control.xml
#--------------------------------------
if [ -x /usr/sbin/add-yast-repos ]; then
	add-yast-repos
	zypper --non-interactive rm -u live-add-yast-repos
fi
#======================================
# Add default kernel boot options
#--------------------------------------
serialconsole='console=ttyS0,115200'
[[ "$kiwi_profiles" == *"RaspberryPi2" ]] && serialconsole='console=ttyAMA0,115200'
[[ "$kiwi_profiles" == *"Rock64" ]] && serialconsole='console=ttyS2,1500000'
[[ "$kiwi_profiles" == *"MS-HyperV"* ]] && serialconsole="rootdelay=300 $serialconsole earlyprintk=ttyS0,115200"
[[ "${kiwi_btrfs_root_is_readonly_snapshot-false}" != 'true' ]] && mount_root_rw='rw'

grub_cmdline=("${mount_root_rw}" 'quiet' 'systemd.show_status=yes' "${serialconsole}" 'console=tty0')
rpm -q wicked && grub_cmdline+=('net.ifnames=0')

# setup ignition if installed
if rpm -q ignition >/dev/null; then
  ignition_platform='metal'
  case "${kiwi_profiles}" in
	*kvm*) ignition_platform='qemu' ;;
	*DigitalOcean*) ignition_platform='digitalocean' ;;
	*VMware*) ignition_platform='vmware' ;;
	*OpenStack*) ignition_platform='openstack' ;;
	*VirtualBox*) ignition_platform='virtualbox' ;;
	*HyperV*) ignition_platform='metal'
	          grub_cmdline+=('rootdelay=300') ;;
	*Pine64*|*RaspberryPi*|*Rock64*|*Vagrant*|*onie*|*SelfInstall*) ignition_platform='metal' ;;
	*) echo "Unhandled profile?"
	   exit 1
	   ;;
  esac

  # One '\' for sed, one '\' for grub2-mkconfig
  grub_cmdline+=('\\$ignition_firstboot' "ignition.platform.id=${ignition_platform}")
fi

sed -i "s#^GRUB_CMDLINE_LINUX_DEFAULT=.*\$#GRUB_CMDLINE_LINUX_DEFAULT=\"${grub_cmdline[*]}\"#" /etc/default/grub

#======================================
# If SELinux is installed, configure it like transactional-update setup-selinux
#--------------------------------------
if [[ -e /etc/selinux/config ]]; then
	# Check if we don't have selinux already enabled.
	grep ^GRUB_CMDLINE_LINUX_DEFAULT /etc/default/grub | grep -q security=selinux || \
	    sed -i -e 's|\(^GRUB_CMDLINE_LINUX_DEFAULT=.*\)"|\1 security=selinux selinux=1"|g' "/etc/default/grub"

	# Adjust selinux config
# FIXME temporary set ALP on permissive mode
#	sed -i -e 's|^SELINUX=.*|SELINUX=enforcing|g' \
#	    -e 's|^SELINUXTYPE=.*|SELINUXTYPE=targeted|g' \
#	    "/etc/selinux/config"
	sed -i -e 's|^SELINUX=.*|SELINUX=permissive|g' \
	    -e 's|^SELINUXTYPE=.*|SELINUXTYPE=targeted|g' \
	    "/etc/selinux/config"

	# Move an /.autorelabel file from initial installation to writeable location
	test -f /.autorelabel && mv /.autorelabel /etc/selinux/.autorelabel
fi

#=====================================
# Configure snapper
#-------------------------------------
if [ "${kiwi_btrfs_root_is_snapshot-false}" = 'true' ]; then
        echo "creating initial snapper config ..."
        # we can't call snapper here as the .snapshots subvolume
        # already exists and snapper create-config doesn't like
        # that.
        cp /etc/snapper/config-templates/default /etc/snapper/configs/root \
                || cp /usr/share/snapper/config-templates/default /etc/snapper/configs/root
        # Change configuration to match SLES12-SP1 values
        sed -i -e '/^TIMELINE_CREATE=/s/yes/no/' /etc/snapper/configs/root
        sed -i -e '/^NUMBER_LIMIT=/s/50/10/'     /etc/snapper/configs/root

        baseUpdateSysConfig /etc/sysconfig/snapper SNAPPER_CONFIGS root
fi

#=====================================
# Enable chrony if installed
#-------------------------------------
if [ -f /etc/chrony.conf ]; then
	systemctl enable chronyd
fi

#======================================
# Disable recommends on virtual images (keep hardware supplements, see bsc#1089498)
#--------------------------------------
sed -i 's/.*solver.onlyRequires.*/solver.onlyRequires = true/g' /etc/zypp/zypp.conf

#======================================
# Disable installing documentation
#--------------------------------------
sed -i 's/.*rpm.install.excludedocs.*/rpm.install.excludedocs = yes/g' /etc/zypp/zypp.conf
