#ifndef PROCESS_H
#define PROCESS_H

#include <stdint.h>
#include <time.h>

#include "burst_desc.h"

#define RAT_GSM 0
#define RAT_UMTS 1
#define RAT_LTE 2

#define DOMAIN_CS 0
#define DOMAIN_PS 1

#define MSG_SDCCH	0x01
#define MSG_SACCH	0x02
#define MSG_FACCH	0x04
#define MSG_BCCH	0x08
#define MSG_CIPHERED	0x40
#define MSG_DECODED	0x80

#define FN_MAX (2048*26*51)

struct burst_buf {
	unsigned count;
	unsigned errors;
	unsigned snr[2*4];
	unsigned rxl[2*4];
	uint32_t fn[2*4];
	uint16_t arfcn[2*4];
	uint8_t data[2*4*114];
	uint8_t sbit[2*4*2];
};

struct radio_message {
	unsigned id;
	uint8_t rat;
	uint8_t domain;
	uint8_t flags;	/* MSG_* */
	struct timeval timestamp;
	char info[128];
	uint8_t chan_nr;
	uint8_t msg[256];
	unsigned msg_len;
	struct burst_buf bb;
	struct radio_message *next;
	struct radio_message *prev;
};

void process_init();
//int process_handle_burst(struct session_info *s, struct l1ctl_burst_ind *bi);

#endif
