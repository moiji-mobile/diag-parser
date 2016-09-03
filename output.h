#ifndef OUTPUT_H
#define OUTPUT_H

#include "session.h"

void net_init(const char *gsmtap, const char *pcap);
void net_destroy();
void net_send_msg(struct radio_message *m);

#endif
