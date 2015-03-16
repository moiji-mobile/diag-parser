#ifndef UMTS_RRC_H
#define UMTS_RRC_H

#include <stdint.h>
#include "session.h"

int handle_dcch_ul(struct session_info *s, uint8_t *msg, size_t len);
int handle_dcch_dl(struct session_info *s, uint8_t *msg, size_t len);
int handle_ccch_ul(struct session_info *s, uint8_t *msg, size_t len);
int handle_ccch_dl(struct session_info *s, uint8_t *msg, size_t len);
int handle_umts_bcch(struct session_info *s, uint8_t *msg, size_t len);

#endif
