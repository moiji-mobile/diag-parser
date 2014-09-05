#ifndef RLCMAC_H
#define RLCMAC_H

#include <stdint.h>

#include "process.h"

struct gprs_lime {
	uint8_t li:6,
		m:1,
		e:1;
	uint8_t used;
} __attribute__ ((packed));

struct gprs_frag {
	uint32_t fn;
	uint8_t last;
	uint8_t len;
	uint8_t data[53];
	uint8_t n_blocks;
	struct gprs_lime blocks[20];
} __attribute__ ((packed));

struct gprs_tbf {
	uint8_t last_bsn; // for windowing
	uint8_t start_bsn; // first block of current message
	struct gprs_frag frags[128];
} __attribute__ ((packed));

static struct gprs_tbf tbf_table[32*2]; // for one cell

void print_pkt(uint8_t *msg, unsigned len);
void process_blocks(struct gprs_tbf *t, int ul);
void rlc_data_handler(struct radio_message *m);
void rlc_type_handler(struct radio_message *m);

#endif

