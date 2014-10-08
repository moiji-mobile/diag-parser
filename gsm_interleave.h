#ifndef GSM_INTERLEAVE_H
#define GSM_INTERLEAVE_H

#include <stdint.h>

void gsm_interleave_init();

void gsm_inter_sacch(const uint8_t *src, uint8_t *dst);
void gsm_deinter_sacch(const uint8_t *src, uint8_t *dst);

void gsm_inter_facch(const uint8_t *src, uint8_t *dst);
void gsm_deinter_facch(const uint8_t *src, uint8_t *dst);

#endif
