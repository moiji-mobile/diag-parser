#ifndef _SMS_H
#define _SMS_H

#include "session.h"

#define DCS_COMPRESSED 0x80

enum sms_class {
	CLASS_DISPLAY = 0,
	CLASS_ME = 1,
	CLASS_SIM = 2,
	CLASS_TE = 3,
	CLASS_NONE = 4
};

enum ota_algo_type {
	OTA_ALGO_NONE = 0,
	OTA_ALGO_IMPLICIT,
	OTA_ALGO_PROPRIETARY,
	OTA_ALGO_RESERVED,
	OTA_ALGO_1DES_CBC,
	OTA_ALGO_3DES_2K,
	OTA_ALGO_3DES_3K,
	OTA_ALGO_1DES_ECB,
	OTA_ALGO_AES_CBC
};

enum ota_cntr_type {
	OTA_CNTR_NONE = 0,
	OTA_CNTR_AVAILABLE,
	OTA_CNTR_HIGHER_THAN_OLD,
	OTA_CNTR_OLD_PLUS_ONE
};

enum ota_sign_type {
	OTA_SIGN_NONE = 0,
	OTA_SIGN_REDUND_CHECK,
	OTA_SIGN_CRYPTO_CHECK,
	OTA_SIGN_DIGITAL_SIGN
};

struct sms_meta {
	uint8_t sequence;
	uint8_t from_network;
	uint8_t pid;
	uint8_t dcs;
	uint8_t alphabet;
	enum sms_class class;
	uint8_t udhi;
	uint8_t concat;
	uint16_t concat_frag;
	uint16_t concat_total;
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t ota;
	uint8_t ota_iei;
	uint8_t ota_enc;
	uint8_t ota_enc_algo;
	uint8_t ota_sign;
	uint8_t ota_sign_algo;
	uint8_t ota_counter_type;
	char ota_counter[5*2+1];
	char ota_tar[3*2+1];
	uint8_t ota_por;
	uint8_t ems;
	char smsc[32];
	char msisdn[32];
	uint8_t length;
	uint8_t udh_length;
	uint8_t real_length;
	uint8_t data[256];
	char info[256];
	struct sms_meta *next;
};

void handle_sms(struct session_info *s, struct gsm48_hdr *dtap, unsigned len);
void handle_cpdata(struct session_info *s, uint8_t *data, unsigned len);
void handle_rpdata(struct session_info *s, uint8_t *data, unsigned len, uint8_t from_network);
void sms_make_sql(int sid, struct sms_meta *sm, char *query, unsigned len);

#endif
