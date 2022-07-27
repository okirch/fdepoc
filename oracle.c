/*
 * Copyright (C) 2022 SUSE LLC
 *
 * GPLv2 applies.
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
	{ "algorithm",		required_argument,	0,	'A' },

	{ NULL }
};

static bool opt_debug	= false;

static void
usage(int exitval, const char *msg)
{
	if (msg)
		fputs(msg, stderr);

	fprintf(stderr,
		"\nUsage:\n"
		"pcr-oracle [options] pcr-index\n"
	       );
	exit(exitval);
}

static void
fatal(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "Fatal: ");
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	exit(2);
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

enum {
	PREDICT_FROM_ZERO,
	PREDICT_FROM_CURRENT,
	PREDICT_FROM_SNAPSHOT,
};

struct predictor {
	unsigned int	index;
	int		from;

	const char *	algo;
	const EVP_MD *	md;

	unsigned int	md_size;
	unsigned char	md_value[EVP_MAX_MD_SIZE];
};

static bool
parse_hexdigit(const char **pos, unsigned char *ret)
{
	char cc = *(*pos)++;

	*ret <<= 4;

	if (isdigit(cc))
		*ret = cc - '0';
	else if ('a' <= cc && cc <= 'f')
		*ret = cc - 'a' + 10;
	else if ('A' <= cc && cc <= 'F')
		*ret = cc - 'A' + 10;
	else
		return false;
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
predictor_new(unsigned int index, int from, const char *algo_name)
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

	if (pred->from == PREDICT_FROM_CURRENT) {
		/* FIXME: read current value of indicated PCR and store it to md_value */
		predictor_init_from_current(pred);
	} else
	if (pred->from == PREDICT_FROM_SNAPSHOT) {
		/* read value of indicated PCR from EFI snapshot variable */
		predictor_init_from_snapshot(pred);
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
	unsigned int i;

	/* printf("%s:%u ", pred->algo, pred->index); */
	for (i = 0; i < pred->md_size; i++)
		printf("%02x", pred->md_value[i]);
	printf("\n");
}

int
main(int argc, char **argv)
{
	unsigned int pcr_index;
	struct predictor *pred;
	int opt_from = -1;
	char *opt_algo = NULL;
	int c;

	while ((c = getopt_long(argc, argv, "dhCSZ", options, NULL)) != EOF) {
		switch (c) {
		case 'A':
			opt_algo = optarg;
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

	pred = predictor_new(pcr_index, opt_from, opt_algo);

	for (; optind + 1 < argc; optind += 2) {
		predictor_update(pred, argv[optind], argv[optind + 1]);
	}

	predictor_report(pred);

	return 0;
}
