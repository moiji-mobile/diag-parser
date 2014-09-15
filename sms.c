#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <osmocom/gsm/rsl.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/gsm/gsm48.h>
#include <osmocom/gsm/gsm48_ie.h>
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/gsm/protocol/gsm_04_11.h>
#include <assert.h>

#include "sms.h"
#include "address.h"
#include "session.h"
#include "bit_func.h"

#define APPEND_INFO(sm, ...) snprintf((sm)->info+strlen((sm)->info), sizeof((sm)->info)-strlen((sm)->info), ##__VA_ARGS__);

struct sec_header {
	uint16_t cpl;
	uint8_t chl;
	uint8_t spi1;
	uint8_t spi2;
	uint8_t kic;
	uint8_t kid;
	uint8_t tar[3];
	uint8_t cntr[5];
	uint8_t pcntr;
};

struct sec_header_rp {
	uint16_t rpl;
	uint8_t rhl;
	uint8_t tar[3];
	uint8_t cntr[5];
	uint8_t pcntr;
	uint8_t status;
	uint8_t sign[8];
	uint8_t sw[0];
};

void handle_text(struct sms_meta *sm, uint8_t *msg, unsigned len)
{
	uint8_t text[256];

	switch (gsm338_get_sms_alphabet(sm->dcs)) {
	case DCS_7BIT_DEFAULT:
		gsm_7bit_decode_n(text, sizeof(text), msg, len);
		APPEND_INFO(sm, "TEXT \"%s\"", text);
		break;
	case DCS_NONE:
	case DCS_UCS2:
	case DCS_8BIT_DATA:
		if (sm->pid == 124 || sm->pid == 127) {
			sm->ota = 1;
		}
		if (sm->dcs == 246 || sm->dcs == 22) {
			sm->ota = 1;
		}
		APPEND_INFO(sm, "RAW %s", osmo_hexdump_nospc(msg, len));
		break;
	}
}

void handle_sec_cp(struct sms_meta *sm, uint8_t *msg, unsigned len)
{
	struct sec_header *sh = (struct sec_header *) msg;

	switch ((sh->spi1 >> 3) & 0x03) {
	case 0:
		APPEND_INFO(sm, " NO_CNTR");
		break;
	case 1:
		APPEND_INFO(sm, " CNTR_AV");
		break;
	case 2:
		APPEND_INFO(sm, " CNTR_HI");
		break;
	case 3:
		APPEND_INFO(sm, " CNTR_+1");
		break;

	}

	if (sh->spi1 & 0x04) {
		APPEND_INFO(sm, " ENC");
		switch (sh->kic & 0x03) {
		case 0:
			APPEND_INFO(sm, " IMPLICIT");
			break;
		case 1:
			switch((sh->kic>>2) & 0x03) {
			case 0:
				APPEND_INFO(sm, " 1DES-CBC");
				break;
			case 1:
				APPEND_INFO(sm, " 3DES-2K");
				break;
			case 2:
				APPEND_INFO(sm, " 3DES-3K");
				break;
			case 3:
				APPEND_INFO(sm, " 1DES-EBC");
				break;
			}
			break;
		case 2:
			APPEND_INFO(sm, " RESERVED");
			break;
		case 3:
			APPEND_INFO(sm, " PROPRIET");
			break;
		}
	} else {
		APPEND_INFO(sm, " --");
	}

	switch (sh->spi1 & 0x03) {
	case 0:
		APPEND_INFO(sm, " --");
		break;
	case 1:
		APPEND_INFO(sm, " RC");
		break;
	case 2:
		APPEND_INFO(sm, " CC");
		break;
	case 3:
		APPEND_INFO(sm, " DS");
		break;
	}

	if (sh->spi1 & 0x03) {
		switch (sh->kid & 0x03) {
		case 0:
			APPEND_INFO(sm, " IMPLICIT");
			break;
		case 1:
			switch((sh->kid>>2) & 0x03) {
			case 0:
				APPEND_INFO(sm, " 1DES-CBC");
				break;
			case 1:
				APPEND_INFO(sm, " 3DES-2K");
				break;
			case 2:
				APPEND_INFO(sm, " 3DES-3K");
				break;
			case 3:
				APPEND_INFO(sm, " RESERVED");
				break;
			}
			break;
		case 2:
			APPEND_INFO(sm, " RESERVED");
			break;
		case 3:
			APPEND_INFO(sm, " PROPRIET");
			break;
		}
	} else {
		APPEND_INFO(sm, " --");
	}
}

void handle_sec_rp(struct sms_meta *sm, uint8_t *msg, unsigned len)
{
	struct sec_header_rp *rp = (struct sec_header_rp *) msg;
	uint8_t sign_len;

	APPEND_INFO(sm, " TAR %02X%02X%02X",
		rp->tar[0], rp->tar[1], rp->tar[2]);

	APPEND_INFO(sm, " POR %02X", rp->status);

	if (len > 13) {
		sign_len = (len-13 > 16 ? 16 : len-13);
		APPEND_INFO(sm, " CC %s ", osmo_hexdump_nospc(rp->sign, sign_len));
	} else {
		APPEND_INFO(sm, " CC -- ");
	}
}

void handle_udh(struct sms_meta *sm, uint8_t *msg, unsigned len)
{
	uint8_t header_len;
	uint8_t *user_data;
	unsigned user_data_len;
	uint8_t offset = 1;
	uint8_t ota_cmd = 0;

	assert(sm != NULL);
	assert(msg != NULL);
	assert(len > 0);

	header_len = msg[0];

	/* Sanity check */
	if (header_len > (len-1))
		return;

	/* Data offset */
	user_data = msg + header_len + 1;
	user_data_len = len - header_len - 1;

	/* Parse header elements (TLV) */
	while (offset < header_len) {
		switch (msg[offset]) {
		case 0x00:
			/* Concatenated header */
			APPEND_INFO(sm, "FRAG(%d/%d)", msg[5], msg[4]);	
			sm->concat = 1;
			break;
		case 0x70:
			/* OTA Command */
			sm->ota = 1;
			ota_cmd = 1;
			break;
		case 0x71:
			/* OTA Response */
			sm->ota = 1;
			ota_cmd = 0;
			break;
		}

		offset += msg[offset + 1];
	}

	/* Parse message content */
	if (sm->ota) {
		APPEND_INFO(sm, "OTA");
		if (ota_cmd) {
			handle_sec_cp(sm, user_data, user_data_len);
		} else {
			handle_sec_rp(sm, user_data, user_data_len);
		}
	} else {
		handle_text(sm, user_data, user_data_len);
	}
}

void handle_tpdu(struct session_info *s, uint8_t *msg, unsigned len, uint8_t from_network, char *smsc)
{
	uint8_t off;
	uint8_t f_len;
	uint8_t vp;
	struct sms_meta *sm;

	assert(s != NULL);
	assert(msg != NULL);
	assert(len > 2);
	assert(smsc != NULL);

	sm = (struct sms_meta *) malloc(sizeof(struct sms_meta));

	assert(sm != NULL);

	memset(sm, 0, sizeof(*sm));

	/* Store SMSC */
	strncpy(sm->smsc, smsc, sizeof(sm->smsc));

	/* UDH presence */
	sm->udhi = !!(msg[0] & 0x40);

	/* Validity period */
	vp = !!(msg[0] & 0x18);

	/* Skip flags [+mr] */
	if (from_network)
		off = 1;
	else
		off = 2;

	/* Decode from/to address */
	f_len = (msg[off++]+1)/2;
	handle_address(&msg[off], f_len, sm->msisdn, 1);
	if (from_network) {
		sm->from_network = 1;
		APPEND_MSG_INFO(s, ", FROM %s", sm->msisdn);
	} else {
		sm->from_network = 0;
		APPEND_MSG_INFO(s, ", TO %s", sm->msisdn);
	}
	off += 1 + f_len;

	/* TP-PID and TP-DCS */
	sm->pid = msg[off++];
	sm->dcs = msg[off++];

	/* Validity period */
	if (vp)
		off += 1;

	if (from_network) {
		/* Timestamp */
		off += 7;
	}

	/* User data length */
	sm->length = msg[off++];
	assert(sm->length*7/8 <= len - off);

	/* Store unparsed bytes */
	memcpy(sm->data, &msg[off], len - off);

	/* Handle UDH if present */
	if (sm->udhi) {
		handle_udh(sm, &msg[off], sm->length);
	} else {
		handle_text(sm, &msg[off], sm->length);
	}

	/* Append SMS to list */
	if (s->sms_list) {
		sm->sequence = s->sms_list->sequence+1;
		sm->next = s->sms_list;
		s->sms_list = sm;
	} else {
		sm->sequence = 0;
		s->sms_list = sm;
	}
}

void handle_rpdata(struct session_info *s, uint8_t *data, unsigned len, uint8_t from_network)
{
	uint8_t off = 0;
	uint8_t f_len;
	uint8_t type;
	uint8_t smsc[GSM48_MI_SIZE];

	assert(s != NULL);
	assert(data != NULL);
	assert(len > 0);

	/* originating (SMSC) address length */
	f_len = data[off++];
	if (f_len) {
		assert(from_network == 1);
		handle_address(&data[off], f_len, smsc, 0);
	}
	off += f_len;

	/* destination (SMSC) address length */
	f_len = data[off++];
	if (f_len) {
		assert(from_network == 0);
		handle_address(&data[off], f_len, smsc, 0);
	}
	off += f_len;

	/* user data length */
	f_len = data[off++];

	/* MTI type */
	type = data[off] & 0x03;
	
	if (from_network) {
		switch (type) {
		case 0:
			/* SMS-DELIVER */
			strcat(s->last_msg->info, "-DELIVER");
			handle_tpdu(s, &data[off], f_len, from_network, smsc);
			break;
		case 1:
			/* SMS-SUBMIT REPORT */
			strcat(s->last_msg->info, "-SUBMIT-REPORT");
			break;
		case 2:
			/* SMS-STATUS REPORT */
			strcat(s->last_msg->info, "-STATUS-REPORT");
			break;
		case 3:
			/* RESERVED */
			strcat(s->last_msg->info, "-RESERVED");
			break;
		}
	} else {
		switch (type) {
		case 0:
			/* SMS-DELIVER REPORT */
			strcat(s->last_msg->info, "-DELIVER-REPORT");
			break;
		case 1:
			/* SMS-SUBMIT */
			strcat(s->last_msg->info, "-SUBMIT");
			handle_tpdu(s, &data[off], f_len, from_network, smsc);
			break;
		case 2:
			/* SMS-COMMAND */
			strcat(s->last_msg->info, "-COMMAND");
			break;
		case 3:
			/* RESERVED */
			strcat(s->last_msg->info, "-RESERVED");
			break;
		}
	}
}

void handle_cpdata(struct session_info *s, uint8_t *data, unsigned len)
{
	struct gsm411_rp_hdr *rp = (struct gsm411_rp_hdr *) data;

	switch (rp->msg_type & 0x0f) {
	case GSM411_MT_RP_DATA_MO:
		strcpy(s->last_msg->info, "SMS RP-DATA");
		handle_rpdata(s, rp->data, len-sizeof(struct gsm411_rp_hdr), 0);
		s->mo = 1;
		break;
	case GSM411_MT_RP_DATA_MT:
		strcpy(s->last_msg->info, "SMS RP-DATA");
		handle_rpdata(s, rp->data, len-sizeof(struct gsm411_rp_hdr), 1);
		s->mt = 1;
		break;
	case GSM411_MT_RP_ACK_MO:
		strcpy(s->last_msg->info, "SMS RP-ACK");
		s->mt = 1;
		break;
	case GSM411_MT_RP_ACK_MT:
		strcpy(s->last_msg->info, "SMS RP-ACK");
		s->mo = 1;
		break;
	case GSM411_MT_RP_ERROR_MO:
		strcpy(s->last_msg->info, "SMS RP-ERROR");
		s->mt = 1;
		break;
	case GSM411_MT_RP_ERROR_MT:
		strcpy(s->last_msg->info, "SMS RP-ACK");
		s->mo = 1;
		break;
	case GSM411_MT_RP_SMMA_MO:
		strcpy(s->last_msg->info, "SMS RP-SMMA");
		s->mo = 1;
		break;
	default:
		s->unknown = 1;
	}
}

void handle_sms(struct session_info *s, struct gsm48_hdr *dtap, unsigned len)
{
	s->sms = 1;
	s->sms_presence = 1;

	switch (dtap->msg_type & 0x1f) {
	case GSM411_MT_CP_DATA:
		handle_cpdata(s, dtap->data, len-sizeof(struct gsm48_hdr));
		break;
	case GSM411_MT_CP_ACK:
		strcpy(s->last_msg->info, "SMS CP-ACK");
		break;
	case GSM411_MT_CP_ERROR:
		strcpy(s->last_msg->info, "SMS CP-ERROR");
		break;
	default:
		s->unknown = 1;
	}
}

void sms_make_sql(int sid, struct sms_meta *sm, char *query, unsigned len)
{
	char *smsc;
	char *msisdn;
	char *info;

	assert(sm != NULL);
	assert(query != NULL);

	smsc = strescape_or_null(sm->smsc);
	msisdn = strescape_or_null(sm->msisdn);
	info = strescape_or_null(sm->info);

	snprintf(query, len, "INSERT INTO sms_meta VALUES ("
		 "%d,%d,%d,%d,%d,%d,%d,%d,%s,%s,%s);\n",
		 sid, sm->sequence, sm->from_network, sm->pid, sm->dcs,
		 sm->udhi, sm->ota, sm->concat, smsc, msisdn, info);

	free(smsc);
	free(msisdn);
	free(info);
}

