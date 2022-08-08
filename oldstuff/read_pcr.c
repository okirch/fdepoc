#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <assert.h>
#include <tss2_fapi.h>

static FAPI_CONTEXT *	context = NULL;

typedef struct Digest {
	uint8_t *	md;
	size_t		len;
} Digest;

void
digest_init(Digest *d)
{
	memset(d, 0, sizeof(*d));
}

Digest *
digest_new(const uint8_t *md, size_t len)
{
	size_t dlen;
	Digest *d;

	dlen = sizeof(*d) + len;

	d = calloc(8, (dlen + 7) / 8);
	d->len = len;
	d->md = (uint8_t *) (d + 1);
	memcpy(d->md, md, len);
	return d;
}

void
digest_free(Digest *d)
{
	memset(d, 0, sizeof(*d) + d->len);
	free(d);
}

static void
_fatal(const char *func, int rc)
{
	fprintf(stderr, "%s returns error %d\n", func, rc);
	exit(42);
}

static void
_initialize(void)
{
	if (context == NULL) {
		int rc;

		rc = Fapi_Initialize(&context, NULL);
		if (rc != 0)
			_fatal("Fapi_Initialize", rc);

		assert(context);
	}
}

Digest *
read_pcr(unsigned int num)
{
	uint8_t *digests[1] = { NULL };
	size_t digest_sizes[1] = { 0 };
	Digest *d;
	char *pcrLog = NULL;
	int rc;

	_initialize();

	rc = Fapi_PcrRead(context, num, digests, digest_sizes, &pcrLog);
	if (rc)
		_fatal("Fapi_PcrRead", rc);

	if (false)
		printf("log = %s\n", pcrLog);

	d = digest_new(digests[0], digest_sizes[0]);

	Fapi_Free(digests[0]);
	if (pcrLog)
		Fapi_Free(pcrLog);

	return d;
}

const char *
print_digest(Digest *d)
{
	static char pbuf[256];
	unsigned int offset = 0;
	unsigned int md_offset = 0;

	assert(!(d->len & 1));
	while (md_offset < d->len) {
		uint16_t word;

		if (offset)
			pbuf[offset++] = ':';

		word = (d->md[md_offset] << 8) | d->md[md_offset + 1];
		md_offset += 2;

		snprintf(pbuf + offset, sizeof(pbuf) - offset, "%04x", word);
		offset = strlen(pbuf);
	}

	return pbuf;
}

int
main(void)
{
	unsigned int num;

	for (num = 0; num < 16; ++num) {
		struct Digest *d;

		d = read_pcr(num);
		printf("PCR%d = %s\n", num, print_digest(d));
		digest_free(d);
	}

	return 0;
}
