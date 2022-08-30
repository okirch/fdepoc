#!/bin/bash
#
# This is for testing authorized policies as a more flexible approach.
#

opt_persist=false

PCR_LIST=sha256:0,1,10

PERSISTENT_OBJECT_ID=""
if $opt_persist; then
	PERSISTENT_OBJECT_ID=0x81010001
fi

if false; then
	# Simulator Setup
	tpm_server -rm > /dev/null 2>&1 &
	TPM2_SERVER_PID=$!
	sleep 1
	export TPM2TOOLS_TCTI=mssim
	tpm2_startup --clear
fi

set -e
# set -x

rm -rf test-authpolicy
mkdir -p test-authpolicy
cd test-authpolicy

function traceme {

	echo "::: $*" >&2
}

function create_null_policy {

	local pcr_list="$1"
	local outfile="$2"

	traceme "Create NULL PCR policy for $pcr_list"
	pcr_algo=$(expr "$pcr_list" : '\(.*\):.*')
	pcr_indices=$(expr "$pcr_list" : '.*:\(.*\)')
	for n in ${pcr_indices//,/ }; do
		pcr-oracle --algorithm $pcr_algo --from-zero --format binary $n
	done >values

	tpm2_startauthsession --session session.ctx
	tpm2_policypcr \
	    --quiet \
	    --session session.ctx \
	    --pcr-list "$pcr_list" \
	    --pcr values \
	    --policy "$outfile"
	tpm2_flushcontext session.ctx
	rm -f session.ctx

	rm -f $values
}

function create_pcr_policy {

	local pcr_list="$1"
	local outfile="$2"

	traceme "Create a PCR policy for $pcr_list"

	tpm2_startauthsession --session session.ctx
	tpm2_policypcr \
	    --quiet \
	    --session session.ctx \
	    --pcr-list "$pcr_list" \
	    --policy "$outfile"
	tpm2_flushcontext session.ctx
	rm -f session.ctx
}

function sign_pcr_policy {

	local unsigned_policy="$1"
	local sign_key="$2"
	local outfile="$3"

	traceme "Sign PCR policy $unsigned_policy"

	# Sign the PCR policy
	openssl dgst \
	    -sign "$sign_key" \
	    -out "$outfile" \
	    $unsigned_policy
}

function create_key_signing_key {

	local priv_key_file=$1
	local pub_key_file=$2

	traceme "Generate public/private key pair for signing"
	openssl genrsa -out $priv_key_file
	openssl rsa \
	    -in $priv_key_file \
	    -out $pub_key_file \
	    -pubout
}

function create_authorized_policy {

	local pub_key_file=$1
	local input_policy=$2
	local outfile=$3

	traceme "Creating authorized policy for $input_policy"

	# Loading the public key in TPM
	tpm2_loadexternal \
	    --quiet \
	    --key-algorithm rsa \
	    --hierarchy o \
	    --public $pub_key_file \
	    --key-context signing.key.ctx \
	    --name signing.key.name

	# Flush transient objects
	tpm2_flushcontext --transient

	# Create an authorized policy
	tpm2_startauthsession --session session.ctx
	tpm2_policyauthorize \
	    --quiet \
	    --session session.ctx \
	    --policy $outfile \
	    --name signing.key.name \
	    --input $input_policy
	tpm2_flushcontext session.ctx
	rm -f session.ctx signing.key.ctx

}

function seal_secret_maybe_persist {

	local pub_key_file=$1
	local priv_key_file=$2
	local authorized_policy_file=$3

	traceme "Sealing secret using authorized policy $authorized_policy_file"

	# Create the TPM object that holds the secret
	echo "Secret" > secret.txt
	tpm2_createprimary \
	    --quiet \
	    --hierarchy o \
	    --hash-algorithm sha256 \
	    --key-algorithm rsa \
	    --key-context primary.ctx
	tpm2_create \
	    --quiet \
	    --parent-context primary.ctx \
	    --hash-algorithm sha256 \
	    --public $pub_key_file \
	    --private $priv_key_file \
	    --sealing-input secret.txt \
	    --policy $authorized_policy_file

	# Flush transient objects
	tpm2_flushcontext --transient

	# Load the generated object in the TPM
	tpm2_load \
	    --parent-context primary.ctx \
	    --public $pub_key_file \
	    --private $priv_key_file \
	    --name key.obj.name \
	    --key-context key.obj.ctx

	if $opt_persist; then
		# Persist the TPM Object
		tpm2_evictcontrol \
		    --hierarchy o \
		    --object-context $PERSISTENT_OBJECT_ID || true
		tpm2_evictcontrol \
		    --hierarchy o \
		    --object-context key.obj.ctx \
		    $PERSISTENT_OBJECT_ID
	fi

	# Flush transient objects
	tpm2_flushcontext --transient

	# tpm2_flushcontext primary.ctx
	# tpm2_flushcontext key.obj.ctx
	rm -f primary.ctx key.obj.ctx

}

# Generate public/private key pair for signing
create_key_signing_key signing.priv.pem signing.pub.pem

# Build the authorized policy from a PCR specification and a public key.
# This policy is satisfied IFF we present the TPM with
#   a) the current PCR values for a given set of PCRs matches a predicted
#	set of PCR values (a "PCR policy")
#   b) proof that this set of PCR values was signed with the private key
#	corresponding to the public key
#
# When creating the authorized policy, the actual PCR values do not matter;
# only the bank/indices matter.
create_null_policy "$PCR_LIST" null.policy
create_authorized_policy signing.pub.pem null.policy authorized.policy
rm -f null.policy

# Create a PCR policy and sign it
create_pcr_policy "$PCR_LIST" pcr.policy
sign_pcr_policy pcr.policy signing.priv.pem pcr.policy.signature

seal_secret_maybe_persist key.obj.pub key.obj.priv authorized.policy

function verify_signature {

	local pub_key_file=$1
	local message_file=$2
	local signature_file=$3
	local outfile=$4

	local key_ctx=signing.key.ctx

	traceme "Instruct TPM to verify signature on authorized policy"

	# Load the keys to be used in signature verification
	tpm2_loadexternal \
	    --quiet \
	    --key-algorithm rsa \
	    --hierarchy o \
	    --public $pub_key_file \
	    --key-context $key_ctx \
	    --name signing.key.name

	# Verify the signature
	tpm2_verifysignature \
	    --ticket $outfile \
	    --key-context $key_ctx \
	    --hash-algorithm sha256 \
	    --message $message_file \
	    --signature $signature_file \
	    --format rsassa

	# Flush transient objects
	tpm2_flushcontext --transient

}

function unseal_authorized {

	local pcr_list="$1"
	local authorized_policy_file="$2"
	local pcr_policy=$3
	local sealed_pub_file=$4
	local sealed_priv_file=$5
	local verification_ticket=$6

	traceme "Unseal the TPM secret using the Authorized PCR Policy"
	tpm2_startauthsession \
	    --policy-session \
	    --session session.ctx
	tpm2_policypcr \
	    --quiet \
	    --session session.ctx \
	    --pcr-list "$pcr_list"
	tpm2_policyauthorize \
	    --quiet \
	    --session session.ctx \
	    --policy $authorized_policy_file \
	    --input $pcr_policy \
	    --name signing.key.name \
	    --ticket verification.tkt

	if $opt_persist; then
		tpm2_unseal \
		    --object-context $PERSISTENT_OBJECT_ID \
		    --auth session:session.ctx
	else
		tpm2_createprimary \
		    --quiet \
		    --hierarchy o \
		    --hash-algorithm sha256 \
		    --key-algorithm rsa \
		    --key-context primary.ctx
		tpm2_load \
		    --parent-context primary.ctx \
		    --public $sealed_pub_file \
		    --private $sealed_priv_file \
		    --name key.obj.name \
		    --key-context key.obj.ctx
		tpm2_unseal \
		    --object-context key.obj.ctx \
		    --auth session:session.ctx
	fi

	rm -f key.obj.ctx primary.ctx

	tpm2_flushcontext session.ctx
	rm -f session.ctx

}

# verify the signed PCR policy. This creates a "ticket" file that can be
# fed to the TPM later
verify_signature \
	signing.pub.pem \
	pcr.policy \
	pcr.policy.signature \
	verification.tkt

unseal_authorized \
	"$PCR_LIST" \
	authorized.policy \
	pcr.policy \
	key.obj.pub key.obj.priv \
	verification.tkt

rm -f verification.tkt

# Update Test: Providing a new policy with updated values should work
if true; then

	traceme "Extending PCR 10"
	tpm2_pcrextend 10:sha256=0000000000000000000000000000000000000000000000000000000000000000

	# Create new policy with updated values
	create_pcr_policy "$PCR_LIST" newpcr.policy
	sign_pcr_policy newpcr.policy signing.priv.pem newpcr.policy.signature

	verify_signature \
		signing.pub.pem \
		newpcr.policy \
		newpcr.policy.signature \
		verification.tkt

	unseal_authorized \
		"$PCR_LIST" \
		authorized.policy \
		newpcr.policy \
		key.obj.pub key.obj.priv \
		verification.tkt

fi

exit 0
	# Update Test: Get new verification ticket for the policy
	tpm2_verifysignature \
	    --ticket newverification.tkt \
	    --key-context signing.key.ctx \
	    --hash-algorithm sha256 \
	    --message newpcr.policy \
	    --signature newpcr.policy.signature \
	    --format rsassa

	# Update Test: Unseal with updated policy
	tpm2_startauthsession \
	    --policy-session \
	    --session session.ctx
	tpm2_policypcr \
	    --session session.ctx \
	    --pcr-list "$PCR_LIST"
	tpm2_policyauthorize \
	    --session session.ctx \
	    --policy authorized.policy \
	    --input newpcr.policy \
	    --name signing.key.name \
	    --ticket newverification.tkt
	tpm2_unseal \
	    --object-context 0x81010001 \
	    --auth session:session.ctx
	tpm2_flushcontext session.ctx
	rm -f session.ctx
