#ifndef OUTPUT_H
#define OUTPUT_H

#include "session.h"

void net_init();
void net_send_msg(struct radio_message *m);
void net_send_llc(uint8_t *data, int len, uint8_t ul);
void net_send_rlcmac(uint8_t *msg, int len, int ts, uint8_t ul);

#endif
