#ifndef LTE_EPS_H
#define LTE_EPS_H

#include "session.h"

void handle_eps(struct session_info *s, uint8_t *data, unsigned len);

#endif
