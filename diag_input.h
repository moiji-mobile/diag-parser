#ifndef DIAG_INPUT_H
#define DIAG_INPUT_H

#include <stdint.h>

void diag_init(unsigned start_sid, unsigned start_cid);
void handle_diag(uint8_t *msg, unsigned len);
void handle_periodic_task();
void diag_destroy();

#endif
