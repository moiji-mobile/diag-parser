#ifndef _CCCH_H
#define _CCCH_H

int try_decode(struct session_info *s, struct radio_message *m);
void process_ccch(struct session_info *s, struct burst_buf *bb, struct l1ctl_burst_ind *bi);

#endif
