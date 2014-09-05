#ifndef _SMS_H
#define _SMS_H

#include "session.h"

struct sms_meta {
	uint8_t sequence;
	uint8_t from_network;
	uint8_t pid;
	uint8_t dcs;
	uint8_t udhi;
	uint8_t rp;
	uint8_t concat;
	char smsc[GSM48_MI_SIZE];
	char msisdn[GSM48_MI_SIZE];
	uint8_t text[256];
	uint8_t data[256];
	struct sms_meta *next;
};

void handle_sms(struct session_info *s, struct gsm48_hdr *dtap, unsigned len);
void handle_cpdata(struct session_info *s, uint8_t *data, unsigned len);
void handle_rpdata(struct session_info *s, uint8_t *data, unsigned len, uint8_t from_network);

#endif
