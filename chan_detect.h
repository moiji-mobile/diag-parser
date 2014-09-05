#ifndef CHAN_DETECT_H
#define CHAN_DETECT_H

#include <stdint.h>

enum {UNKNOWN=0, BCCH=1, CCCH=2, SDCCH=4, SACCH=8};

uint8_t chan_detect(uint32_t fn, uint8_t ts, uint8_t combined, uint8_t *subchan);

#endif
