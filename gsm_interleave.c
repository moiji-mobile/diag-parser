#include "gsm_interleave.h"

static unsigned _sacch_map[456];
static unsigned _facch_map[456];

void gsm_interleave_init()
{
	int j, k, B;

	/* sacch map */
	for (k = 0; k < 456; k++) {
		B = k % 4;
		j = 2 * ((49 * k) % 57) + ((k % 8) / 4);
		_sacch_map[k] = B * 114 + j;
	}

	/* facch map */
	for (k = 0; k < 456; k++) {
		B = k % 8;
		j = 2 * ((49 * k) % 57) + ((k % 8) / 4);
		_facch_map[k] = B * 114 + j;
	}
}

void gsm_inter_sacch(const uint8_t *src, uint8_t *dst)
{
	int k;
	for (k = 0; k < 456; k++)
		dst[_sacch_map[k]] = src[k];
}

void gsm_deinter_sacch(const uint8_t *src, uint8_t *dst)
{
	int k;
	for (k = 0; k < 456; k++)
		dst[k] = src[_sacch_map[k]];
}

void gsm_inter_facch(const uint8_t *src, uint8_t *dst)
{
	int k;
	for (k = 0; k < 456; k++)
		dst[_facch_map[k]] = src[k];
}

void gsm_deinter_facch(const uint8_t *src, uint8_t *dst)
{
	int k;
	for (k = 0; k < 456; k++)
		dst[k] = src[_facch_map[k]];
}

