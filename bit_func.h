#ifndef BIT_FUNC_H
#define BIT_FUNC_H

#include <stdint.h>

int not_zero(uint8_t *t, unsigned size);

void compress_lsb(const uint8_t *in, uint8_t *out, unsigned size);
void compress_msb(const uint8_t *in, uint8_t *out, unsigned size);

void expand_lsb(const uint8_t *in, uint8_t *out, unsigned size);
void expand_msb(const uint8_t *in, uint8_t *out, unsigned size);

int hex_bin2str(const uint8_t *vec, char *str, unsigned len);
int hex_str2bin(const char *str, uint8_t *vec, unsigned len);

int bcd2str(uint8_t *bcd, char *s, unsigned len, unsigned off);
unsigned hamming_distance(uint8_t *v1, uint8_t *v2, unsigned len);

#endif
