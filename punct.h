#ifndef PUNCT_H
#define PUNCT_H

#include <stdint.h>

void fill_punct_cs2(unsigned *pattern);
void fill_punct_cs3(unsigned *pattern);
void depunct(int8_t *in, int8_t *out, unsigned size, unsigned *pattern);

#endif
