/*
 *   Copyright (C) 2022 SUSE LLC
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Written by Olaf Kirch <okir@suse.com>
 */

#include <openssl/evp.h>
#include <sys/mount.h>
#include <getopt.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>
#include <ctype.h>
#include <tss2_fapi.h>

#include "util.h"
#include "eventlog.h"
#include "bufparser.h"
#include "runtime.h"

enum {
	PREDICT_FROM_ZERO,
	PREDICT_FROM_CURRENT,
	PREDICT_FROM_SNAPSHOT,
	PREDICT_FROM_EVENTLOG,
};

struct predictor {
	unsigned int		index;
	int			from;

	const char *		algo;
	const tpm_algo_info_t *	algo_info;
	const EVP_MD *		md;

	tpm_event_t *		event_log;

	void			(*report_fn)(struct predictor *);

	unsigned int		md_size;
	unsigned char		md_value[EVP_MAX_MD_SIZE];
};

#define GRUB_PCR_SNAPSHOT_UUID	"7ce323f2-b841-4d30-a0e9-5474a76c9a3f"

static struct option options[] = {
	{ "from-zero",		no_argument,		0,	'Z' },
	{ "from-current",	no_argument,		0,	'C' },
	{ "from-snapshot",	no_argument,		0,	'S' },
	{ "from-eventlog",	no_argument,		0,	'L' },
	{ "algorithm",		required_argument,	0,	'A' },
	{ "format",		required_argument,	0,	'F' },

	{ NULL }
};

unsigned int opt_debug	= 0;

static void	predictor_report_plain(struct predictor *pred);
static void	predictor_report_tpm2_tools(struct predictor *pred);
static void	predictor_report_binary(struct predictor *pred);

static void
usage(int exitval, const char *msg)
{
	if (msg)
		fputs(msg, stderr);

	fprintf(stderr,
		"\nUsage:\n"
		"pcr-oracle [options] pcr-index [updates...]\n"
		"\n"
		"The following options are recognized:\n"
		"  -Z, --from-zero        Assume a PCR state of all zero\n"
		"  -C, --from-current     Set the PCR state to the current state of the host's PCR\n"
		"  -S, --from-snapshot    Read the PCR state from a snapshot taken during boot (GrubPcrSnapshot EFI variable)\n"
		"  -L, --from-eventlog    Predict the PCR state using the event log, by substituting current values\n"
		"  -A name, --algorithm name\n"
		"                         Use hash algorithm <name>. Defaults to sha256\n"
		"  -F name, --output-format name\n"
		"                         Specify how to display the resulting PCR value. The default is \"plain\",\n"
		"                         which just prints the value as a hex string. When using \"tpm2-tools\", the\n"
		"                         output string is formatted to resemble the output of tpm2_pcrread.\n"
		"                         Finally, \"binary\" writes our the raw binary data so that it can be consumed\n"
		"                         tpm2_policypcr.\n"
		"\n"
		"The PCR index can be followed by zero or more pairs of data describing how to extend the PCR.\n"
		"Each pair is a type, and and argument. These types are currently recognized:\n"
		"  string                 The PCR is extended with the string argument.\n"
		"  file                   The argument is taken as a file name. The PCR is extended with the file's content.\n"
		"\n"
		"After the PCR predictor has been extended with all updates specified, its value is printed to standard output.\n"
	       );
	exit(exitval);
}

static void
predictor_init_from_snapshot(struct predictor *pred)
{
	const char *efivar_path = "/sys/firmware/efi/vars/GrubPcrSnapshot-" GRUB_PCR_SNAPSHOT_UUID "/data";
	char linebuf[256];
	bool found = false;
	FILE *fp;

	debug("Trying to find PCR %d in %s\n", pred->index, efivar_path);
	if (!(fp = fopen(efivar_path, "r")))
		fatal("Unable to open \"%s\": %m\n", efivar_path);

	while (fgets(linebuf, sizeof(linebuf), fp) != NULL) {
		unsigned int index;
		const char *algo, *value;
		unsigned int len;
		char *w;

		debug("=> %s", linebuf);
		if (!(w = strtok(linebuf, " \t\n")))
			continue;

		if (!parse_pcr_index(w, &index)
		 || !(algo = strtok(NULL, " \t\n")))
			continue;

		debug("inspecting %u:%s\n", index, algo);
		if (index != pred->index
		 || strcasecmp(algo, pred->algo))
			continue;

		if (!(value = strtok(NULL, " \t\n")))
			continue;

		len = parse_octet_string(value, pred->md_value, sizeof(pred->md_value));
		if (len == 0)
			continue;

		if (len == pred->md_size) {
			found = true;
			break;
		}

		debug("Found entry for %s:%u, but value has wrong size %u (expected %u)\n",
				pred->algo, pred->index, len, pred->md_size);
	}

	fclose(fp);

	if (!found)
		fatal("Could not find PCR value for %s:%u in %s\n", pred->algo, pred->index, efivar_path);
}

static void
predictor_load_eventlog(struct predictor *pred)
{
	tpm_event_log_reader_t *log;
	tpm_event_t *ev, **tail;

	log = event_log_open();

	tail = &pred->event_log;
	while ((ev = event_log_read_next(log)) != NULL) {
		*tail = ev;
		tail = &ev->next;
	}

	event_log_close(log);
}

static void
fapi_error(const char *func, int rc)
{
	fatal("TPM2: function %s returns %d\n", func, rc);
}

static void
predictor_init_state(struct predictor *pred, const unsigned char *md_value, unsigned int md_size)
{
	if (pred->md_size != md_size)
		fatal("Could not initialize predictor for PCR %s:%u: initial hash value has size %u (expected %u)\n",
				pred->algo, pred->index, (int) md_size, pred->md_size);
	memcpy(pred->md_value, md_value, md_size);
}

static void
predictor_init_from_current(struct predictor *pred)
{
	FAPI_CONTEXT *context = NULL;
	uint8_t *digests[8] = { NULL };
	size_t digest_sizes[8] = { 0 };
	int rc;

	if (strcmp(pred->algo, "sha256"))
		fatal("Cannot initialize from current TPM values for digest algorithm %s - not implemented\n",
				pred->algo);

	rc = Fapi_Initialize(&context, NULL);
	if (rc != 0)
		fapi_error("Fapi_Initialize", rc);

	/* FIXME: how does this function select a PCR bank?
	 * The answer is: it doesn't. The proper way to obtain current
	 * values for eg sha1 would be to use ESYS_PCR_Read() instead.
	 */
	rc = Fapi_PcrRead(context, pred->index, digests, digest_sizes, NULL);
	if (rc)
		fapi_error("Fapi_PcrRead", rc);

	predictor_init_state(pred, digests[0], digest_sizes[0]);

	Fapi_Free(digests[0]);

	debug("Initialized predictor from current PCR%u value\n", pred->index);
}

static struct predictor *
predictor_new(unsigned int index, int from, const char *algo_name, const char *output_format)
{
	struct predictor *pred;

	pred = calloc(1, sizeof(*pred));
	pred->index = index;
	pred->from = from >= 0? from : PREDICT_FROM_ZERO;

	pred->algo = algo_name? : "sha256";
	pred->md = EVP_get_digestbyname(pred->algo);
	if (pred->md == NULL) {
		fprintf(stderr, "Unknown message digest %s\n", pred->algo);
		usage(1, NULL);
	}

	pred->algo_info = digest_by_name(pred->algo);
	if (pred->algo_info == NULL)
		fatal("Digest algorithm %s not implemented\n");

	pred->md_size = EVP_MD_size(pred->md);
	assert(pred->md_size == pred->algo_info->digest_size);

	if (!output_format || !strcasecmp(output_format, "plain"))
		pred->report_fn = predictor_report_plain;
	else
	if (!output_format || !strcasecmp(output_format, "tpm2-tools"))
		pred->report_fn = predictor_report_tpm2_tools;
	else
	if (!output_format || !strcasecmp(output_format, "binary"))
		pred->report_fn = predictor_report_binary;
	else
		fatal("Unsupported output format \"%s\"\n", output_format);

	if (pred->from == PREDICT_FROM_CURRENT) {
		/* read current value of indicated PCR and store it to md_value */
		predictor_init_from_current(pred);
	} else
	if (pred->from == PREDICT_FROM_SNAPSHOT) {
		/* read value of indicated PCR from EFI snapshot variable */
		predictor_init_from_snapshot(pred);
	} else
	if (pred->from == PREDICT_FROM_EVENTLOG) {
		predictor_load_eventlog(pred);
	}

	debug("Created new predictor for %s:%u\n", pred->algo, pred->index);
	return pred;
}

static void
predictor_extend_hash(struct predictor *pred, const tpm_evdigest_t *d)
{
	EVP_MD_CTX *mdctx;
	unsigned int md_len;

	assert(d->size == pred->md_size);

	mdctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(mdctx, pred->md, NULL);

	EVP_DigestUpdate(mdctx, pred->md_value, pred->md_size);
	EVP_DigestUpdate(mdctx, d->data, d->size);

	EVP_DigestFinal_ex(mdctx, pred->md_value, &md_len);
	assert(pred->md_size == md_len);

	EVP_MD_CTX_free(mdctx);
}

static const tpm_evdigest_t *
predictor_compute_digest(struct predictor *pred, const void *data, unsigned int size)
{
	static tpm_evdigest_t md;
	EVP_MD_CTX *mdctx;

	mdctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(mdctx, pred->md, NULL);

	EVP_DigestUpdate(mdctx, data, size);
	EVP_DigestFinal_ex(mdctx, md.data, &md.size);
	EVP_MD_CTX_free(mdctx);

	md.algo = pred->algo_info;

	return &md;
}

static const tpm_evdigest_t *
predictor_compute_file_digest(struct predictor *pred, const char *filename, int flags)
{
	const tpm_evdigest_t *md;
	buffer_t *buffer;

	buffer = runtime_read_file(filename, flags);

	md = predictor_compute_digest(pred,
			buffer_read_pointer(buffer),
			buffer_available(buffer));
	buffer_free(buffer);

	return md;
}

static const tpm_evdigest_t *
predictor_compute_pecoff_digest(struct predictor *pred, const char *filename)
{
	char cmdbuf[8192], linebuf[1024];
	const tpm_evdigest_t *md = NULL;
	FILE *fp;

	snprintf(cmdbuf, sizeof(cmdbuf),
			"pesign --hash --in %s --digest_type %s",
			filename, pred->algo);

	debug("Executing command: %s\n", cmdbuf);
	if ((fp = popen(cmdbuf, "r")) == NULL)
		fatal("Unable to run command: %s\n", cmdbuf);

	while (fgets(linebuf, sizeof(linebuf), fp) != NULL) {
		char *w;

		/* line must start with "hash:" */
		if (!(w = strtok(linebuf, " \t\n:")) || strcmp(w, "hash"))
			continue;

		if (!(w = strtok(NULL, " \t\n")))
			fatal("cannot parse pesign output\n");

		if (!(md = parse_digest(w, pred->algo)))
			fatal("unable to parse %s digest printed by pesign: \"%s\"\n", pred->algo, w);

		break;
	}

	if (fclose(fp) != 0)
		fatal("pesign command failed: %m\n");

	return md;
}

static const tpm_evdigest_t *
predictor_compute_efi_file_digest(struct predictor *pred, const char *device_path, const char *file_path)
{
	const tpm_evdigest_t *md;
	char display_path[PATH_MAX];
	char fullpath[PATH_MAX];
	char template[] = "/tmp/efimnt.XXXXXX";
	char *dirname;

	snprintf(display_path, sizeof(display_path), "(%s)%s", device_path, file_path);
	debug("Updating PCR %d with %s\n", pred->index, display_path);

	if (!(dirname = mkdtemp(template)))
		fatal("Cannot create temporary mount point for EFI partition");

	if (mount(device_path, dirname, "vfat", 0, NULL) < 0) {
		(void) rmdir(dirname);
		fatal("Unable to mount %s on %s\n", device_path, dirname);
	}

	/* This is not correct; the proper thing to do here is to use libpde from
	 * pesign to compute the hash of the PE COFF binary in AuthentiCode style.
	 * Alternatively, we could implement a facility that lets the user pass
	 * the digest. This could be used to give us the output of
	 *  pesign --hash --in $path_of_efi_binary --digest_type sha256
	 */
	snprintf(fullpath, sizeof(fullpath), "%s/%s", dirname, file_path);
	md = predictor_compute_pecoff_digest(pred, fullpath);

	if (umount(dirname) < 0)
		fatal("unable to unmount temporary directory %s: %m\n", dirname);

	if (rmdir(dirname) < 0)
		fatal("unable to remove temporary directory %s: %m\n", dirname);

	return md;
}

static const tpm_evdigest_t *
predictor_compute_efi_variable_digest(struct predictor *pred, tpm_parsed_event_t *parsed, const char *var_name)
{
	buffer_t *file_data, *efi_data;
	const tpm_evdigest_t *md;

	file_data = runtime_read_efi_variable(var_name);
	if (file_data == NULL)
		return NULL;

	efi_data = tpm_parsed_event_rebuild(parsed,
			buffer_read_pointer(file_data),
			buffer_available(file_data));
	if (efi_data == NULL)
		fatal("Unable to re-marshal EFI variable\n");

	if (opt_debug > 1) {
		debug("  Remarshaled blob for EFI variable %s:\n", var_name);
		hexdump(buffer_read_pointer(efi_data),
			buffer_available(efi_data),
			debug, 8);
	}

	md = predictor_compute_digest(pred,
			buffer_read_pointer(efi_data),
			buffer_available(efi_data));

	buffer_free(file_data);
	buffer_free(efi_data);
	return md;
}

static void
predictor_update_string(struct predictor *pred, const char *value)
{
	const tpm_evdigest_t *md;

	debug("Extending PCR %u with string \"%s\"\n", pred->index, value);
	md = predictor_compute_digest(pred, value, strlen(value));
	predictor_extend_hash(pred, md);
}

static void
predictor_update_file(struct predictor *pred, const char *filename)
{
	const tpm_evdigest_t *md;

	md = predictor_compute_file_digest(pred, filename, 0);
	predictor_extend_hash(pred, md);
}

static const tpm_evdigest_t *
predictor_compute_boot_services_application(struct predictor *pred, tpm_event_t *ev,
		char **efi_partition_p, char **efi_application_p)
{
	tpm_parsed_event_t *parsed;

	if (!(parsed = tpm_event_parse(ev)))
		fatal("Unable to parse EFI_BOOT_SERVICES_APPLICATION event from TPM log");

	if (!tpm_efi_bsa_event_extract_location(parsed, efi_partition_p, efi_application_p))
		fatal("Unable to locate updated boot service application");

	return predictor_compute_efi_file_digest(pred, *efi_partition_p, *efi_application_p);
}

static const tpm_evdigest_t *
predictor_compute_efi_variable(struct predictor *pred, tpm_event_t *ev, const char **desc_p)
{
	tpm_parsed_event_t *parsed;
	const char *var_name;
	const tpm_evdigest_t *md;

	if (!(parsed = tpm_event_parse(ev)))
		fatal("Unable to parse EFI_VARIABLE event from TPM log");

	if (!(var_name = tpm_efi_variable_event_extract_full_varname(parsed)))
		fatal("Unable to extract EFI variable name from EFI_VARIABLE event\n");

	*desc_p = var_name;

	if (!strcmp(var_name, "KEK-8be4df61-93ca-11d2-aa0d-00e098032b8c")
	 || !strcmp(var_name, "db-d719b2cb-3d3a-4596-a3bc-dad00e67656f")
	 || !strcmp(var_name, "dbx-d719b2cb-3d3a-4596-a3bc-dad00e67656f")
	 || !strcmp(var_name, "SbatLevel-605dab50-e046-4300-abb6-3dd810dd8b23")) {
		md = tpm_event_get_digest(ev, pred->algo);
		if (md == NULL)
			debug("Event does not provide a digest for algorithm %s\n", pred->algo);
	} else {
		md = predictor_compute_efi_variable_digest(pred, parsed, var_name);
	}

	return md;
}

static void
predictor_update_eventlog(struct predictor *pred)
{
	char *efi_partition = NULL, *efi_application = NULL;
	tpm_event_t *ev;

	for (ev = pred->event_log; ev; ev = ev->next) {
		if (ev->pcr_index == pred->index) {
			const tpm_evdigest_t *old_digest, *new_digest;
			const char *description = NULL;

			debug("\n");
			__tpm_event_print(ev, debug);

			if (!(old_digest = tpm_event_get_digest(ev, pred->algo)))
				fatal("Event log lacks a hash for digest algorithm %s\n", pred->algo);

			switch (ev->event_type) {
			case TPM2_EFI_BOOT_SERVICES_APPLICATION:
			case TPM2_EFI_BOOT_SERVICES_DRIVER:
				new_digest = predictor_compute_boot_services_application(pred, ev, &efi_partition, &efi_application);
				description = efi_application;
				break;

			case TPM2_EFI_VARIABLE_BOOT:
			case TPM2_EFI_VARIABLE_AUTHORITY:
			case TPM2_EFI_VARIABLE_DRIVER_CONFIG:
				new_digest = predictor_compute_efi_variable(pred, ev, &description);
				break;

			/* Probably needs to be done:
			 * EFI_GPT_EVENT: used in updates of PCR5, seems to be a hash of several GPT headers.
			 *	We should probably rebuild in case someone changed the partitioning.
			 *	However, not needed as long as we don't seal against PCR5.
			 * EFI_VARIABLE_DRIVER_CONFIG: all the secure boot variables get hashed into this,
			 *	including PK, dbx, etc.
			 */

			case TPM2_EVENT_NO_ACTION:
			case TPM2_EVENT_S_CRTM_CONTENTS:
			case TPM2_EVENT_S_CRTM_VERSION:
			case TPM2_EFI_PLATFORM_FIRMWARE_BLOB:
			case TPM2_EVENT_SEPARATOR:
			case TPM2_EVENT_POST_CODE:
			case TPM2_EFI_HANDOFF_TABLES:
			case TPM2_EFI_GPT_EVENT:
			case TPM2_EFI_ACTION:
			case TPM2_EVENT_IPL:			/* used by grub2 for PCR9 */
				new_digest = old_digest;
				break;

			default:
				debug("Encountered unexpected event type %s\n",
						tpm_event_type_to_string(ev->event_type));
				new_digest = old_digest;
			}

			if (opt_debug && new_digest != old_digest) {
				if (new_digest->size == old_digest->size
				 && !memcmp(new_digest->data, old_digest->data, old_digest->size)) {
					debug("Digest for %s did not change\n", description);
				} else {
					debug("Digest for %s changed\n", description);
					debug("  Old digest: %s\n", digest_print(old_digest));
					debug("  New digest: %s\n", digest_print(new_digest));
				}
			}

			predictor_extend_hash(pred, new_digest);
		}
	}

	drop_string(&efi_partition);
	drop_string(&efi_application);
}

static void
predictor_update(struct predictor *pred, const char *type, const char *arg)
{
	if (!strcmp(type, "string")) {
		predictor_update_string(pred, arg);
	} else
	if (!strcmp(type, "file")) {
		predictor_update_file(pred, arg);
	} else {
		fprintf(stderr, "Unsupported keyword \"%s\" while trying to update predictor\n", type);
		usage(1, NULL);
	}
}

static void
predictor_report(struct predictor *pred)
{
	if (pred->from == PREDICT_FROM_EVENTLOG)
		predictor_update_eventlog(pred);

	pred->report_fn(pred);
}

static void
predictor_report_plain(struct predictor *pred)
{
	unsigned int i;

	/* printf("%s:%u ", pred->algo, pred->index); */
	for (i = 0; i < pred->md_size; i++)
		printf("%02x", pred->md_value[i]);
	printf("\n");
}

static void
predictor_report_tpm2_tools(struct predictor *pred)
{
	unsigned int i;

	printf("  %-2d: 0x", pred->index);
	for (i = 0; i < pred->md_size; i++)
		printf("%02X", pred->md_value[i]);
	printf("\n");
}

static void
predictor_report_binary(struct predictor *pred)
{
	if (fwrite(pred->md_value, pred->md_size, 1, stdout) != 1)
		fatal("failed to write hash to stdout");
}

int
main(int argc, char **argv)
{
	unsigned int pcr_index;
	struct predictor *pred;
	int opt_from = -1;
	char *opt_algo = NULL;
	char *opt_output_format = NULL;
	int c;

	while ((c = getopt_long(argc, argv, "dhA:CF:LSZ", options, NULL)) != EOF) {
		switch (c) {
		case 'A':
			opt_algo = optarg;
			break;
		case 'F':
			opt_output_format = optarg;
			break;
		case 'Z':
			opt_from = PREDICT_FROM_ZERO;
			break;
		case 'C':
			opt_from = PREDICT_FROM_CURRENT;
			break;
		case 'S':
			opt_from = PREDICT_FROM_SNAPSHOT;
			break;
		case 'L':
			opt_from = PREDICT_FROM_EVENTLOG;
			break;
		case 'd':
			opt_debug += 1;
			break;
		case 'h':
			usage(0, NULL);
		default:
			usage(1, "Invalid option");
		}
	}

	if (optind + 1 > argc)
		usage(1, "Expected PCR index as argument");

	if (!parse_pcr_index(argv[optind++], &pcr_index))
		usage(1, "Bad value for PCR argument");

	pred = predictor_new(pcr_index, opt_from, opt_algo, opt_output_format);

	for (; optind + 1 < argc; optind += 2) {
		predictor_update(pred, argv[optind], argv[optind + 1]);
	}

	predictor_report(pred);

	return 0;
}
