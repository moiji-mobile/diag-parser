#ifndef CCH_H
#define CCH_H

#include <stdint.h>

#define DATA_BLOCK_SIZE         184
#define PARITY_SIZE             40
#define FLUSH_BITS_SIZE         4
#define PARITY_OUTPUT_SIZE (DATA_BLOCK_SIZE + PARITY_SIZE + FLUSH_BITS_SIZE)

#define CONV_INPUT_SIZE		PARITY_OUTPUT_SIZE
#define CONV_SIZE		(2 * CONV_INPUT_SIZE)

void encode_signalling(const uint8_t *msg, uint8_t *raw_data);
int decode_signalling(const int8_t *soft_data, uint8_t *sig_msg);

#endif
