
# Tools for controlling Full Disk Encryption

This repository contains the scripts used to manage Full Disk Encryption
in ALP. The main utility to use is fdectl, and its main configuration file
is /etc/sysconfig/fde-tools.

The main purpose of this tool is to simplify the handling of TPM seal/unseal
for both the system admin and the installer. For sealing, it relies heavily
on ``pcr-oracle`` to predict the values of relevant TPM Platform Configuration
Registers (PCRs) at the time the boot loader will have to unseal the key.

## Testing for the presence of a TPM

This is fairly trivial:

	# fdectl tpm-present

This will return an exit status of 0 (success) or 1 (absent).


## Leaving the key under the doormat

When the user selects TPM protection during installation, we cannot
seal LUKS keys against the TPM immediately. That is because the
boot process the system is going through to bring up the installer
is normally vastly different from what the firmware will do when booting
the installed system. To begin with, the installer will usually be
booted from an attached medium such as a DVD or USB stick.

Therefore, we need to wait with TPM sealing until we have booted into
the final system. Unfortunately, this means the user will be asked to
enter the LUKS recovery password during first boot.

We can try to be more user-friendly by allowing this first boot
to proceed without prompting for the recovery password. In order to
achieve this, we need install a temporary, alternative password and
leave that in cleartext in the boot loader configuration (for grub,
this would be the grub.cfg file on the EFI System Partition).

In order to install such as "firstboot password", use the ``dormat``
command:

	# fdectl enable-doormat

This will ask for the recovery password, and create an additional
slot in the LUKS header that is protected by a additional, insecure
password, and will configure the bootloader to use that to unlock
the system partition on next boot.

If you do not want to be prompted for the recovery password, you can
also use either the ``--keyfile`` or the ``--password`` option to
specify a LUKS keyfile, or the recovery passphrase, respectively.

Normally, the first boot into a freshly installed system will dispose
of any firstboot password configured by the installer. If you want
to remove the password explicitly, you can use

	# fdectl disable-doormat


## Installation using PCR Policies

If the users asks for the LUKS partition to be protected by the TPM,
the installer needs to create a secondary key and pass this to the
installed system, like this:

	# fdectl add-secondary-key --keyfile /root/.root.key

This will prompt for the recovery password that is able to unlock the
LUKS partition. Alternatively, you can pass the password on the command
like using the ``--password`` option.

After booting into the installed system, TPM protection needs to
be enabled using this command:

	# fdectl tpm-enable --keyfile /root/.root.keyfile

This will create a _new_ LUKS key, which is then sealed against the
predicted TPM state, and installed in the UEFI System Partition.
The old key, which was created by the installer, is removed.

Note, when using ``fdectl doormat`` as described above, ``tpm-enable``
will also have to remove this well-known password from the LUKS header.

Usually, the ``tpm-enable`` command is invoked automatically on first
boot via the ``fde-tools.service`` unit file.


## Installation using Authorized Policies

Using a set of PCR values to seal a secret directly is a challenge
when dealing with updates of software components of grub, the shim
loader, etc - because these updates change the outcome of the PCR
computation done by the firmware.

To deal with this challenge, authorized policies were invented
(sometimes called "brittle PCR policies"). Now, what's the difference?

With regular PCR policies, you basically tell the TPM "I want you
to divulge the following secret whenever PCR registers A, B, and C
have the following value(s)."

With authorized PCR policies, you tell the TPM "Whenever I present
you with a set of PCR register values, and a digital signature
of these values signed with RSA key X, I want you to divulge the
secret whenever PCR registers A, B, and C have the given values."

In other words, with regular PCR policies, you tie the sealed
secret to specific PCR values directly. Whereas an authorized policy
inserts an RSA key in the middle - and if you update say the grub2
boot loader, you do not re-seal the secret, you just re-compute
the PCR values, and sign them with an RSA secret key.

To enable the use of authorized policies during installation, the
installer needs to perform these steps:

	# fdectl init-authorized-policy
	# fdectl add-secondary-key

The first command creates a suitable RSA key, and the authorized policy.
Both will be placed under ``/etc/fde``.

The second step will add a second key to the LUKS header, just as in
the case of regular PCR policies. However, this will not copy the
cleartext key to the installed system (note the absence of the ``--keyfile``
option), but have the TPM seal it against the authorized policy.

After booting into the installed system, we can now enable the
authorized policy:

	# fdectl tpm-enable
	# fdectl tpm-authorize

As before, ``tpm-enable`` will configure the boot loader to
unlock the LUKS partition by unsealing the secret key.

However, there is a second step required, which is to actually
_authorize_ the current system using the ``tpm-authorize``
command. This will predict a set of PCR values, and use the 
RSA key to sign the resulting PCR policy. 

# Updates of boot components

When updating components such as grub2 or the shim loader, or when
modifying the GPT of the disk from which the system is booting,
the PCR values during the next boot will be different, and unsealing
the LUKS key will fail. The user would have to enter their recovery
password, which can be rather unconvenient, especially for server
machines that are not easily accessible.

Therefore, a new PCR policy has to be computed (and installed)
after any changes of this kind. The recommended way to do this is
by using authorized policies.

If the system has been configured for authorized policies, updates
of grub and shim need to be followed by a call to ``tpm-authorize``:

	# fdectl tpm-authorize

In the absence of authorized policies, ``fdectl`` currently does
not support the update case. This could probably be implemented,
but in order to make it convenient, this would require a copy of a
LUKS to be stored on the system partition permanently, in clear-text.


# Security Considerations

Currently, the RSA key used by authorized policies is stored on
the system without pass phrase protection. This is an acceptable
risk, because in order to access the file, the attacker needs to
have access to the system partition - so at least attacks involving
hardware theft are thwarted. Of course, an attacker gaining root
to a running system could still abuse this key to install a
modified grub or shim EFI binary.

In terms of future work, it is possible to implement a centralized
service that holds the RSA key, and authorizes a system's
configuration.  The approach would probably involve the client
system submitting its TPM event log, the version numbers of the
grub/shim version it wants to authorize. The server would then
predict PCR values based on the client's event log plus the actual
hashes of the boot files used, compute the PCR policy and sign it
using its key.
