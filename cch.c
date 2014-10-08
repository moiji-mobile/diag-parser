#include <stdio.h>
#include <string.h>

#include "cch.h"
#include "crc.h"
#include "viterbi.h"
#include "bit_func.h"
#include "gsm_interleave.h"

/*
 * Parity (FIRE) for the GSM SACCH channel.
 *
 * 	g(x) = (x^23 + 1)(x^17 + x^3 + 1)
 * 	     = x^40 + x^26 + x^23 + x^17 + x^3 + 1
 */

static const unsigned char parity_polynomial[PARITY_SIZE + 1] = {
   1, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 0, 0, 1, 0,
   0, 1, 0, 0, 0, 0, 0, 1,
   0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 0, 1, 0, 0,
   1
};

// remainder after dividing data polynomial by g(x)
static const unsigned char parity_remainder[PARITY_SIZE] = {
   1, 1, 1, 1, 1, 1, 1, 1,
   1, 1, 1, 1, 1, 1, 1, 1,
   1, 1, 1, 1, 1, 1, 1, 1,
   1, 1, 1, 1, 1, 1, 1, 1,
   1, 1, 1, 1, 1, 1, 1, 1
};

/*
 * 	Decode a "common" control channel
 *
 * 		BCCH Norm
 * 		BCCH Ext
 * 		PCH
 * 		AGCH
 * 		CBCH (SDCCH/4)
 * 		CBCH (SDCCH/8)
 * 		SDCCH/4
 * 		SACCH/C4
 * 		SDCCH/8
 * 		SACCH/C8
 * 		FACCH
 *
 */

void encode_signalling(const uint8_t *msg, uint8_t *raw_data)
{
	uint8_t decoded_data[PARITY_OUTPUT_SIZE];
	uint8_t coded_data[CONV_SIZE];

	expand_lsb(msg, decoded_data, DATA_BLOCK_SIZE);

	memset(&decoded_data[DATA_BLOCK_SIZE], 0, CONV_INPUT_SIZE-DATA_BLOCK_SIZE);

        parity_encode(decoded_data, DATA_BLOCK_SIZE, parity_polynomial,
		 	&decoded_data[DATA_BLOCK_SIZE], PARITY_SIZE);

	conv_cch_encode(decoded_data, coded_data, PARITY_OUTPUT_SIZE);

	gsm_inter_sacch(coded_data, raw_data);
}

int decode_signalling(const int8_t *soft_data, uint8_t *msg)
{
	int ret;
	uint8_t decoded_data[PARITY_OUTPUT_SIZE];
	FC_CTX fc_ctx;

	// soft_data: 0 -> 127, 1-> -127

	/* Viterbi decoding */
	conv_cch_decode((int8_t *) soft_data, decoded_data, CONV_INPUT_SIZE);

	/* parity check: if error detected try to fix it */
	ret = parity_check(decoded_data, DATA_BLOCK_SIZE, parity_polynomial,
			   parity_remainder, PARITY_SIZE);
	if (ret) {
		FC_init(&fc_ctx, PARITY_SIZE, DATA_BLOCK_SIZE);
		unsigned char crc_result[DATA_BLOCK_SIZE + PARITY_SIZE];
		ret = FC_check_crc(&fc_ctx, decoded_data, crc_result);
		if (!ret)
			return 0;
		else
			memcpy(decoded_data, crc_result, sizeof crc_result);
	}

	compress_lsb(decoded_data, msg, DATA_BLOCK_SIZE);

	return 23;
}

