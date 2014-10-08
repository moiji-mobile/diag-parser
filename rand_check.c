#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rand_check.h"
#include "bit_func.h"

void rand_init_2b(struct rand_state *r)
{
	r->valid = 1;
	r->ciphered = 0;
	r->len = sizeof(r->data);
	memset(r->data, 0x2b, r->len);	
}

int rand_check(uint8_t *data, uint8_t len, struct rand_state *r, int ciphered)
{
	uint8_t offset, real_len, diff_bytes;

	if (!len || len > 20)
		return 0;

	if (!r->valid) {
		r->valid = 1;
		r->ciphered = ciphered;
		r->len = (len < 21 ? len : 21);
		memcpy(r->data, data, r->len);
		return 0;
	}

#if 0
	printf("\n");
	printf("prev: %s\n", osmo_hexdump_nospc(r->data, r->len));
	printf("curr: %s\n", osmo_hexdump_nospc(data, len));
#endif

	if (r->len >= len) {
		offset = r->len - len;
		real_len = len;
		diff_bytes = hamming_distance(&r->data[offset], data, real_len);
		memcpy(&r->data[offset], data, len);
	} else {
		offset = len - r->len;
		real_len = r->len;
		diff_bytes = hamming_distance(r->data, &data[offset], real_len);
		memcpy(r->data, data, len);
		r->len = len;
	}

	if (r->ciphered) {
		if (ciphered) {
			if (diff_bytes) {
				// very well applied randomization
				r->rand_count += diff_bytes;
				r->byte_count += real_len;
				return 1;
			} else {
				// message didn't change once ciphering started
				r->byte_count += real_len;
				return 0;
			}
		} else {
			// should never happen
			printf("ERROR: unencrypted message after encryption cannot belong to the same session\n");
			fflush(stdout);
			abort();
		}
	} else {
		if (ciphered) {
			r->ciphered = 1;

			if (diff_bytes) {
				// correctly applied randomization
				r->rand_count += diff_bytes;
				r->byte_count += real_len;
				return 1;
			} else {
				// no randomization
				r->byte_count += real_len;
				return 0;
			}
		} else {
			// message can change before ciphering, randomization here is useless
			return 0;
		}
	}
}

