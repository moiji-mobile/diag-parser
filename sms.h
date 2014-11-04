#ifndef _SMS_H
#define _SMS_H

#include "session.h"

struct sms_meta {
	uint8_t sequence;
	uint8_t from_network;
	uint8_t pid;
	uint8_t dcs;
	uint8_t alphabet;
	uint8_t class;
	uint8_t udhi;
	uint8_t ota;
	uint8_t concat;
	char smsc[32];
	char msisdn[32];
	uint8_t length;
	uint8_t data[256];
	char info[256];
	struct sms_meta *next;
};

void handle_sms(struct session_info *s, struct gsm48_hdr *dtap, unsigned len);
void handle_cpdata(struct session_info *s, uint8_t *data, unsigned len);
void handle_rpdata(struct session_info *s, uint8_t *data, unsigned len, uint8_t from_network);
void sms_make_sql(int sid, struct sms_meta *sm, char *query, unsigned len);

#endif
