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
#include <sys/stat.h>
#include <getopt.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdarg.h>
#include <assert.h>
#include <ctype.h>
#include <tss2_fapi.h>

#include "eventlog.h"
#include "util.h"

enum {
	PREDICT_FROM_ZERO,
	PREDICT_FROM_CURRENT,
	PREDICT_FROM_SNAPSHOT,
	PREDICT_FROM_EVENTLOG,
};

struct predictor {
	unsigned int	index;
	int		from;

	const char *	algo;
	const EVP_MD *	md;

	tpm_event_t *	event_log;

	void		(*report_fn)(struct predictor *);

	unsigned int	md_size;
	unsigned char	md_value[EVP_MAX_MD_SIZE];
};

#define GRUB_PCR_SNAPSHOT_UUID	"7ce323f2-b841-4d30-a0e9-5474a76c9a3f"


#define debug(msg ...) \
	do {					\
		if (opt_debug)			\
			printf(msg);		\
	} while (0)

static struct option options[] = {
	{ "from-zero",		no_argument,		0,	'Z' },
	{ "from-current",	no_argument,		0,	'C' },
	{ "from-snapshot",	no_argument,		0,	'S' },
	{ "from-eventlog",	no_argument,		0,	'L' },
	{ "algorithm",		required_argument,	0,	'A' },
	{ "format",		required_argument,	0,	'F' },

	{ NULL }
};

static bool opt_debug	= false;

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
		"  -C, --from-snapshot    Read the PCR state from a snapshot taken during boot (GrubPcrSnapshot EFI variable)\n"
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

static bool
parse_pcr_index(const char *word, unsigned int *ret)
{
	unsigned int value;
	const char *end;

	value = strtoul(word, (char **) &end, 10);
	if (*end) {
		fprintf(stderr, "Unable to parse PCR index \"%s\"\n", word);
		return false;
	}

	*ret = value;
	return true;
}

static bool
parse_hexdigit(const char **pos, unsigned char *ret)
{
	char cc = *(*pos)++;
	unsigned int octet;

	if (isdigit(cc))
		octet = cc - '0';
	else if ('a' <= cc && cc <= 'f')
		octet = cc - 'a' + 10;
	else if ('A' <= cc && cc <= 'F')
		octet = cc - 'A' + 10;
	else
		return false;

	*ret = (*ret << 4) | octet;
	return true;
}

static bool
parse_octet(const char **pos, unsigned char *ret)
{
	return parse_hexdigit(pos, ret) && parse_hexdigit(pos, ret);
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
		unsigned int i;
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
		for (i = 0; parse_octet(&value, &pred->md_value[i]); ++i)
			;

		debug("parsed %u octets\n", i);
		if (*value)
			continue;

		if (i == pred->md_size) {
			found = true;
			break;
		}

		debug("Found entry for %s:%u, but value has wrong size %u (expected %u)\n",
				pred->algo, pred->index, i, pred->md_size);
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
		tpm_event_print(ev);
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
		fatal("Could not initialize predictor: initial hash value has size %u (expected %u)\n",
				pred->algo, pred->index, md_size, pred->md_size);
	memcpy(pred->md_value, md_value, md_size);
}

static void
predictor_init_from_current(struct predictor *pred)
{
	FAPI_CONTEXT *context = NULL;
	uint8_t *digests[1] = { NULL };
	size_t digest_sizes[1] = { 0 };
	char *pcrLog = NULL;
	int rc;

	rc = Fapi_Initialize(&context, NULL);
	if (rc != 0)
		fapi_error("Fapi_Initialize", rc);


	rc = Fapi_PcrRead(context, pred->index, digests, digest_sizes, &pcrLog);
	if (rc)
		fapi_error("Fapi_PcrRead", rc);

	predictor_init_state(pred, digests[0], digest_sizes[0]);

	Fapi_Free(digests[0]);
	if (pcrLog)
		Fapi_Free(pcrLog);

	debug("Initialized predictor from current PCR\n");
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

	pred->md_size = EVP_MD_size(pred->md);

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
		/* FIXME: read current value of indicated PCR and store it to md_value */
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
predictor_extend_hash(struct predictor *pred, const unsigned char *hash, unsigned int size)
{
	EVP_MD_CTX *mdctx;
	unsigned int md_len;

	assert(size == pred->md_size);

	mdctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(mdctx, pred->md, NULL);

	EVP_DigestUpdate(mdctx, pred->md_value, pred->md_size);
	EVP_DigestUpdate(mdctx, hash, size);

	EVP_DigestFinal_ex(mdctx, pred->md_value, &md_len);
	assert(pred->md_size == md_len);

	EVP_MD_CTX_free(mdctx);
}

static void
predictor_extend(struct predictor *pred, const char *data, unsigned int size)
{
	EVP_MD_CTX *mdctx;
	unsigned char md_value[EVP_MAX_MD_SIZE];
	unsigned int md_len;

	debug("Extending PCR %u with %u bytes of data\n", pred->index, size);

	mdctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(mdctx, pred->md, NULL);

	EVP_DigestUpdate(mdctx, data, size);
	EVP_DigestFinal_ex(mdctx, md_value, &md_len);
	EVP_MD_CTX_free(mdctx);

	predictor_extend_hash(pred, md_value, md_len);
}

static void
predictor_update_string(struct predictor *pred, const char *value)
{
	predictor_extend(pred, value, strlen(value));
}

static void
predictor_update_file(struct predictor *pred, const char *filename)
{
	struct stat stb;
	char *buffer;
	int fd, n;

	if ((fd = open(filename, O_RDONLY)) < 0)
		fatal("Unable to open file %s: %m\n", filename);

	if (fstat(fd, &stb) < 0)
		fatal("Cannot stat %s: %m\n", filename);

	if (!(buffer = malloc(stb.st_size)))
		fatal("Cannot allocate buffer of %lu bytes for %s: %m\n",
				(unsigned long) stb.st_size,
				filename);

	n = read(fd, buffer, stb.st_size);
	if (n < 0)
		fatal("Error while reading from %s: %m\n", filename);
	if (n != stb.st_size)
		fatal("Short read from %s\n", filename);

	close(fd);

	debug("Read %lu bytes from %s\n", (unsigned long) stb.st_size, filename);
	predictor_extend(pred, buffer, stb.st_size);
	free(buffer);
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
			opt_debug = true;
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
