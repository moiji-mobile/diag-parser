#ifndef _RAND_CHECK_H
#define _RAND_CHECK_H

#include <stdint.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>

struct rand_state {
	uint8_t valid;
	uint8_t ciphered;
	uint8_t data[20];
	uint8_t len;
	uint32_t byte_count;
	uint32_t rand_count;
};

void rand_init_2b(struct rand_state *r);
int rand_check(uint8_t *data, uint8_t len, struct rand_state *r, int ciphered);

#endif
