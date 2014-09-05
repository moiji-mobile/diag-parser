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

void handle_sec_cp(uint8_t *msg, unsigned len)
{
	struct sec_header *sh = (struct sec_header *) msg;

#if 0
	/* keysets should match in Kic and Kid */
	if ((sh->kic ^ sh->kid) & 0xf0) {
		printf(" KEYSETS DON'T MATCH");
		return;
	}
#endif

	printf(" TAR %02X%02X%02X",
		sh->tar[0],
		sh->tar[1],
		sh->tar[2]);

	switch ((sh->spi1 >> 3) & 0x03) {
	case 0:
		printf(" NO_CNTR");
		break;
	case 1:
		printf(" CNTR_AV");
		break;
	case 2:
		printf(" CNTR_HI");
		break;
	case 3:
		printf(" CNTR_+1");
		break;

	}

	if (sh->spi1 & 0x04) {
		printf(" ENC");
		switch (sh->kic & 0x03) {
		case 0:
			printf(" IMPLICIT");
			break;
		case 1:
			switch((sh->kic>>2) & 0x03) {
			case 0:
				printf(" 1DES-CBC");
				break;
			case 1:
				printf(" 3DES-2K ");
				break;
			case 2:
				printf(" 3DES-3K ");
				break;
			case 3:
				printf(" 1DES-EBC");
				break;
			}
			break;
		case 2:
			printf(" RESERVED");
			break;
		case 3:
			printf(" PROPRIET");
			break;
		}
	} else {
		printf(" --- --------");
	}

	switch (sh->spi1 & 0x03) {
	case 0:
		printf(" --");
		break;
	case 1:
		printf(" RC");
		break;
	case 2:
		printf(" CC");
		break;
	case 3:
		printf(" DS");
		break;
	}

	if (sh->spi1 & 0x03) {
		switch (sh->kid & 0x03) {
		case 0:
			printf(" IMPLICIT");
			break;
		case 1:
			switch((sh->kid>>2) & 0x03) {
			case 0:
				printf(" 1DES-CBC");
				break;
			case 1:
				printf(" 3DES-2K ");
				break;
			case 2:
				printf(" 3DES-3K ");
				break;
			case 3:
				printf(" RESERVED");
				break;
			}
			break;
		case 2:
			printf(" RESERVED");
			break;
		case 3:
			printf(" PROPRIET");
			break;
		}
	} else {
		printf(" --------");
	}
}

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

void handle_sec_rp(uint8_t *msg, unsigned len)
{
	struct sec_header_rp *rp = (struct sec_header_rp *) msg;
	uint8_t sign_len;

	printf(" TAR %02X%02X%02X",
		rp->tar[0],
		rp->tar[1],
		rp->tar[2]);

	printf(" POR %02X", rp->status);

	if (len > 13) {
		sign_len = (len-13 > 16 ? 16 : len-13);
		printf(" CC %s      ", osmo_hexdump_nospc(rp->sign, sign_len));
	} else {
		printf(" CC ----------------      ");
	}
}

void handle_binary_data(struct session_info *s, uint8_t *msg, unsigned len)
{
	uint8_t header_len;
	uint8_t *user_data;

	header_len = msg[0];

	if (header_len > (len-1)) {
		printf(" CORRUPTED DATA!");
		return;
	}

	user_data = msg + header_len + 1;

	switch (msg[1]) {
	case 0x00:
		/* Fragment */
		if ((msg[2] == 0x03) && (msg[5] == 0x01)) {
			/* First fragment */
			handle_sec_cp(user_data, len-header_len-1);
		} else {
			printf(" FRAGMENT (%3d/%3d)                         ", msg[5], msg[4]);	
		}
		break;
	case 0x70:
		/* Command */
		handle_sec_cp(user_data, len-header_len-1);
		break;
	case 0x71:
		/* Response */
		handle_sec_rp(user_data, len-header_len-1);
		break;
	}

	printf(" %s", osmo_hexdump_nospc(msg, len));
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
		sprintf(s->last_msg->info+strlen(s->last_msg->info), ", FROM %s", sm->msisdn);
	} else {
		sm->from_network = 0;
		sprintf(s->last_msg->info+strlen(s->last_msg->info), ", TO %s", sm->msisdn);
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
	f_len = msg[off++];

	/* Store text message */
	if ((sm->dcs == 0) || ((sm->dcs & 0xfc) == 0x10)) {
		gsm_7bit_decode_n(sm->text, sizeof(sm->text), &msg[off], f_len);
	}

	/* only binary encoded */
	// 00:f5 WSP
	// 7f:f6 USIM data download
	#pragma omp critical (print)
	if ((sm->dcs == 246) || (sm->dcs == 22)) {
		printf("[%06d] %3d %3d %13s", s->id, s->mcc, s->mnc, sm->smsc);

		printf(" %c %3d/%3d U%d %3d", from_network ? 'N' : 'M', sm->pid, sm->dcs, sm->udhi, f_len);

		if (sm->udhi || (msg[off] == 0x02 && ((msg[off+1] == 0x70) || (msg[off+1] == 0x71)))) {
			handle_binary_data(s, &msg[off], f_len);
		} else {
			printf(" RAW %s", osmo_hexdump_nospc(&msg[off], f_len));
		}
		printf("\n");
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

