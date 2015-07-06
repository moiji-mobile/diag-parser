#ifndef LTE_NAS_EPS_INFO_H
#define LTE_NAS_EPS_INFO_H

#include <stdint.h>

/* Set message description according to proto_disc/subtype */
void naseps_set_msg_info(struct session_info *s, naseps_msg_t *msg);

#endif
