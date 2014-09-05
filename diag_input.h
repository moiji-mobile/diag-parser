#ifndef DIAG_INPUT_H
#define DIAG_INPUT_H

#include <stdint.h>

void diag_init();
void handle_diag(uint8_t *msg, unsigned len);
void diag_destroy();

#endif
