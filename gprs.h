#ifndef GRPS_H
#define GRPS_H

#include <stdint.h>

#include "burst_desc.h"
#include "session.h"

void gprs_init();
unsigned distance(const uint8_t *a, const uint8_t *b, const unsigned size);
int cs_estimate(const uint8_t *sflags);
int usf6_estimate(const uint8_t *data);
int usf12_estimate(const uint8_t *data);
int process_pdch(struct session_info *s, struct l1ctl_burst_ind *bi, uint8_t *gprs_msg);

#endif

