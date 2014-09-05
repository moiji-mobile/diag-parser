#ifndef VITERBI_H
#define VITERBI_H

int conv_cch_encode(const uint8_t *in, uint8_t *out, unsigned size);
int conv_cch_decode(int8_t *input, uint8_t *output, int n);

#endif
