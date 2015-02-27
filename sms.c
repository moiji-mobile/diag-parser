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

enum sms_class get_sms_class(uint8_t dcs)
{
	uint8_t coding_group = dcs >> 4;
	enum sms_class class = CLASS_NONE;

	if ((coding_group & 0xc) == 0) {
		if (dcs & 0x10) {
			class = (dcs & 0x03);
		}
	} else if (coding_group == 0xf) {
		class = (dcs & 0x03);
	}

	return class;
}

enum sms_alphabet get_sms_alphabet(uint8_t dcs)
{
	uint8_t coding_group = dcs >> 4;
	enum sms_alphabet alpha = DCS_NONE;

	if (dcs == 0x00) {
		/* default alphabet, 7bit */
		alpha = DCS_7BIT_DEFAULT;
		return alpha;
	}

	if ((coding_group & 0xc) == 0) {
		/* DCS 00xx xxxx */

		switch ((dcs >> 2) & 0x03) {
		case 0:
			alpha = DCS_7BIT_DEFAULT;
			break;
		case 1:
			alpha = DCS_8BIT_DATA;
			break;
		case 2:
			alpha = DCS_UCS2;
			break;
		}

		if (dcs & 0x20) {
			alpha |= DCS_COMPRESSED;
		}
	} else if (coding_group == 0xc || coding_group == 0xd)
		alpha = DCS_7BIT_DEFAULT;
	else if (coding_group == 0xe)
		alpha = DCS_UCS2;
	else if (coding_group == 0xf) {
		/* DCS 1111 xxxx */
		if (dcs & 0x04) {
			alpha = DCS_8BIT_DATA;
		} else {
			alpha = DCS_7BIT_DEFAULT;
		}
	}

	return alpha;
}

void handle_text(struct sms_meta *sm, uint8_t *msg, unsigned len)
{
	char text[256];

	if (len == 0) {
		APPEND_INFO(sm, "<NO DATA>");
		return;
	}

	if (sm->alphabet & DCS_COMPRESSED) {
		APPEND_INFO(sm, "<COMPRESSED DATA>");
		return;
	}

	switch (sm->alphabet) {
	case DCS_7BIT_DEFAULT:
		gsm_7bit_decode_n(text, sizeof(text), msg, len);
		if (strlen(text)) {
			//FIXME: sanitize string!
			//APPEND_INFO(sm, "%s", text);
			APPEND_INFO(sm, "TEXT_7BIT");
		} else {
			APPEND_INFO(sm, "<FAILED TO DECODE TEXT>");
		}
		break;
	case DCS_UCS2:
		APPEND_INFO(sm, "TEXT_16BIT");
		break;
	case DCS_NONE:
	case DCS_8BIT_DATA:
		if (sm->pid == 124 ||
		    sm->pid == 127 ||
		    sm->dcs == 246 ||
		    sm->dcs == 22) {
			APPEND_INFO(sm, "OTA ");
			sm->ota = 1;
		}
		APPEND_INFO(sm, "DATA_8BIT");
		break;
	default:
		APPEND_INFO(sm, "<UNKNOWN ALPHABET>");
	}
}

void handle_sec_cp(struct sms_meta *sm, uint8_t *msg, unsigned len)
{
	struct sec_header *sh = (struct sec_header *) msg;

	assert(sm != NULL);
	assert(msg != NULL);

	/* Counter type */
	switch ((sh->spi1 >> 3) & 0x03) {
	case 0:
		APPEND_INFO(sm, "NO_CNTR ");
		sm->ota_counter_type = OTA_CNTR_NONE;
		break;
	case 1:
		APPEND_INFO(sm, "CNTR_AV ");
		sm->ota_counter_type = OTA_CNTR_AVAILABLE;
		break;
	case 2:
		APPEND_INFO(sm, "CNTR_HI ");
		sm->ota_counter_type = OTA_CNTR_HIGHER_THAN_OLD;
		break;
	case 3:
		APPEND_INFO(sm, "CNTR_+1 ");
		sm->ota_counter_type = OTA_CNTR_OLD_PLUS_ONE;
		break;

	}

	/* Encryption type */
	if (sh->spi1 & 0x04) {
		APPEND_INFO(sm, "ENC ");
		sm->ota_enc = 1;

		/* Algo family switch */
		switch (sh->kic & 0x03) {
		case 0:
			APPEND_INFO(sm, "IMPLICIT ");
			sm->ota_enc_algo = OTA_ALGO_IMPLICIT;
			break;
		case 1:
			/* DES family */
			switch((sh->kic>>2) & 0x03) {
			case 0:
				APPEND_INFO(sm, "1DES-CBC ");
				sm->ota_enc_algo = OTA_ALGO_1DES_CBC;
				break;
			case 1:
				APPEND_INFO(sm, "3DES-2K ");
				sm->ota_enc_algo = OTA_ALGO_3DES_2K;
				break;
			case 2:
				APPEND_INFO(sm, "3DES-3K ");
				sm->ota_enc_algo = OTA_ALGO_3DES_3K;
				break;
			case 3:
				APPEND_INFO(sm, "1DES-EBC ");
				sm->ota_enc_algo = OTA_ALGO_1DES_ECB;
				break;
			}
			break;
		case 2:
			/* AES family */
			switch((sh->kic>>2) & 0x03) {
			case 0:
				APPEND_INFO(sm, "AES-CBC ");
				sm->ota_enc_algo = OTA_ALGO_AES_CBC;
				break;
			default:
				APPEND_INFO(sm, "RESERVED ");
				sm->ota_enc_algo = OTA_ALGO_RESERVED;
			}
			break;
		case 3:
			APPEND_INFO(sm, "PROPRIET ");
			sm->ota_enc_algo = OTA_ALGO_PROPRIETARY;
			break;
		}
	} else {
		APPEND_INFO(sm, "NOENC ");
		sm->ota_enc = 0;
		sm->ota_enc_algo = OTA_ALGO_NONE;
	}

	/* Signature/integrity type */
	switch (sh->spi1 & 0x03) {
	case 0:
		APPEND_INFO(sm, "NOCC ");
		sm->ota_sign = OTA_SIGN_NONE;
		break;
	case 1:
		APPEND_INFO(sm, "RC ");
		sm->ota_sign = OTA_SIGN_REDUND_CHECK;
		break;
	case 2:
		APPEND_INFO(sm, "CC ");
		sm->ota_sign = OTA_SIGN_CRYPTO_CHECK;
		break;
	case 3:
		APPEND_INFO(sm, "DS ");
		sm->ota_sign = OTA_SIGN_DIGITAL_SIGN;
		break;
	}

	if (sh->spi1 & 0x03) {
		switch (sh->kid & 0x03) {
		case 0:
			APPEND_INFO(sm, "IMPLICIT ");
			sm->ota_sign_algo = OTA_ALGO_IMPLICIT;
			break;
		case 1:
			/* DES family */
			switch((sh->kid>>2) & 0x03) {
			case 0:
				APPEND_INFO(sm, "1DES-CBC ");
				sm->ota_sign_algo = OTA_ALGO_1DES_CBC;
				break;
			case 1:
				APPEND_INFO(sm, "3DES-2K ");
				sm->ota_sign_algo = OTA_ALGO_3DES_2K;
				break;
			case 2:
				APPEND_INFO(sm, "3DES-3K ");
				sm->ota_sign_algo = OTA_ALGO_3DES_3K;
				break;
			case 3:
				APPEND_INFO(sm, "RESERVED ");
				sm->ota_sign_algo = OTA_ALGO_RESERVED;
				break;
			}
			break;
		case 2:
			APPEND_INFO(sm, "RESERVED ");
			sm->ota_sign_algo = OTA_ALGO_RESERVED;
			break;
		case 3:
			APPEND_INFO(sm, "PROPRIET ");
			sm->ota_sign_algo = OTA_ALGO_PROPRIETARY;
			break;
		}
	} else {
		sm->ota_sign_algo = OTA_ALGO_NONE;
	}

	strncpy(sm->ota_tar, osmo_hexdump_nospc(sh->tar, 3), sizeof(sm->ota_tar));

	APPEND_INFO(sm, "TAR %s ", sm->ota_tar);

	if (((sh->spi1 & 0x04) == 0)) {
		strncpy(sm->ota_counter, osmo_hexdump_nospc(sh->cntr, 5), sizeof(sm->ota_counter));

		APPEND_INFO(sm, "CNTR %s ", sm->ota_counter);
	}
}

void handle_sec_rp(struct sms_meta *sm, uint8_t *msg, unsigned len)
{
	struct sec_header_rp *rp = (struct sec_header_rp *) msg;
	uint8_t sign_len;

	strncpy(sm->ota_tar, osmo_hexdump_nospc(rp->tar, 3), sizeof(sm->ota_tar));

	APPEND_INFO(sm, "TAR %s ", sm->ota_tar);

	sm->ota_por = rp->status;

	APPEND_INFO(sm, "POR %02X ", rp->status);

	if (len > 13) {
		sign_len = (len-13 > 16 ? 16 : len-13);
		APPEND_INFO(sm, "CC %s ", osmo_hexdump_nospc(rp->sign, sign_len));
	} else {
		APPEND_INFO(sm, "CC -- ");
	}
}

void handle_udh(struct sms_meta *sm, uint8_t *msg, unsigned len)
{
	uint8_t header_len;
	uint8_t *user_data;
	unsigned user_data_len;
	uint8_t offset = 1;
	uint8_t ota_cmd = 0;
	uint8_t total_frags;
	uint8_t this_frag;
	char alt_dest[32];

	assert(sm != NULL);
	assert(msg != NULL);

	if (len == 0) {
		APPEND_INFO(sm, "NO DATA");	
		sm->real_length = 0;
		return;
	}
	header_len = msg[0];

	/* Sanity check */
	if (header_len > (len-1)) {
		APPEND_INFO(sm, "SANITY CHECK FAILED (SMS_UDH_LEN)");
		return;
	}

	/* Data offset */
	user_data = msg + header_len + 1;
	user_data_len = len - header_len - 1;

	sm->udh_length = header_len;
	sm->real_length = user_data_len;

	/* Parse header elements (TLV) */
	while (offset <= header_len) {
		uint8_t type = msg[offset++];
		uint8_t vlen = msg[offset++];

		if (offset+vlen > len) {
			APPEND_INFO(sm, "SANITY CHECK FAILED (UDH_IEI_LEN)");
			return;
		}

		/* Definitions from 3GPP TS 23.040 9.2.3.24 */
		switch (type) {
		case 0x00:
			/* Concatenated header, 8bit reference */
			if (vlen != 3) {
				APPEND_INFO(sm, "SANITY CHECK FAILED (SMS_FRAG_HDR)");
				return;
			}
			total_frags = msg[offset+1];
			this_frag = msg[offset+2];
			if (this_frag > total_frags) {
				APPEND_INFO(sm, "SANITY CHECK FAILED (SMS_FRAG_8)");
				return;
			}
			APPEND_INFO(sm, "[%d/%d] ", this_frag, total_frags);	
			sm->concat = 1;
			sm->concat_frag = this_frag;
			sm->concat_total = total_frags;
			break;
		case 0x01:
			/* Special SMS indication */
			if (vlen != 2) {
				APPEND_INFO(sm, "SANITY CHECK FAILED (SMS_SPECIAL_UDH)");
				return;
			}
			break;
		case 0x04:
			/* Application address port, 8bit */
			if (vlen != 2) {
				APPEND_INFO(sm, "SANITY CHECK FAILED (SMS_PORT8_HDR)");
				return;
			}

			sm->src_port = msg[offset+1];
			sm->dst_port = msg[offset+0];

			APPEND_INFO(sm, "PORT8 %d->%d ", sm->src_port, sm->dst_port);	
			break;
		case 0x05:
			/* Application address port, 16bit */
			if (vlen != 4) {
				APPEND_INFO(sm, "SANITY CHECK FAILED (SMS_PORT8_HDR)");
				return;
			}

			sm->src_port = msg[offset+2]<<8|msg[offset+3];
			sm->dst_port = msg[offset+0]<<8|msg[offset+1];

			APPEND_INFO(sm, "PORT16 %d->%d ", sm->src_port, sm->dst_port);	
			break;
		case 0x06:
			/* Service center control parameters */
			if (vlen != 1) {
				APPEND_INFO(sm, "SANITY CHECK FAILED (SMS_SC_PARAM)");
				return;
			}
			break;
		case 0x07:
			/* UDH source indicator */
			if (vlen != 1) {
				APPEND_INFO(sm, "SANITY CHECK FAILED (SMS_SOURCE_IND)");
				return;
			}
			break;
		case 0x08:
			/* Concatenated header, 16bit reference */
			if (vlen != 4) {
				APPEND_INFO(sm, "SANITY CHECK FAILED (SMS_FRAG16_HDR)");
				return;
			}
			total_frags = msg[offset+2];
			this_frag = msg[offset+3];
			if (this_frag > total_frags) {
				APPEND_INFO(sm, "SANITY CHECK FAILED (SMS_FRAG_16)");
				return;
			}
			APPEND_INFO(sm, "[%d/%d] ", this_frag, total_frags);	
			sm->concat = 1;
			sm->concat_frag = this_frag;
			sm->concat_total = total_frags;
			break;
		case 0x0a:
			/* Text formatting (EMS) */
			break;
		case 0x0d:
			/* Predefined animation (EMS) */
			break;
		case 0x14:
			/* Extended object (EMS) */
			break;
		case 0x16:
			/* Compression control (EMS) */
			break;
		case 0x22:
			/* Alternate reply address */
			if (vlen < (msg[offset]/2 + 1)) {
				APPEND_INFO(sm, "SANITY CHECK FAILED (SMS_REPLY_ADDR)");
				return;
			}
			handle_address(&msg[offset+1], msg[offset], alt_dest, 1);
			APPEND_INFO(sm, "REPLY_ADDR=%s ", alt_dest);
			break;
		case 0x24:
			/* National language shift */
			if (vlen != 1) {
				APPEND_INFO(sm, "SANITY CHECK FAILED (SMS_LANG_SHIFT)");
				return;
			}
			APPEND_INFO(sm, "LANG_SHIFT=%d ", msg[offset]);
			break;
		case 0x25:
			/* National language locking shift */
			if (vlen != 1) {
				APPEND_INFO(sm, "SANITY CHECK FAILED (SMS_LANG_LOCK_SHIFT)");
				return;
			}
			APPEND_INFO(sm, "LANG_SHIFT=%d ", msg[offset]);
			break;
		case 0x70:
			/* OTA Command */
			sm->ota = 1;
			sm->ota_iei = 0x70;
			ota_cmd = 1;
			break;
		case 0x71:
			/* OTA Response */
			sm->ota = 1;
			sm->ota_iei = 0x71;
			ota_cmd = 0;
			break;
		case 0x7f:
			/* Non-standard OTA */
			sm->ota = 1;
			sm->ota_iei = 0x7f;
			ota_cmd = 1;
			break;
		case 0xda:
			/* SMSC-specific */
			if (vlen > header_len) {
				APPEND_INFO(sm, "SANITY CHECK FAILED (SMS_SMSC_SPECIFIC)");
				return;
			}
			break;
		default:
			printf("Unhandled UDH-IEI 0x%02x, vlen=%d\n", type, vlen);
		}

		offset += vlen;
	}

	/* Parse message content */
	if (sm->ota) {
		APPEND_INFO(sm, "OTA ");
		if (ota_cmd) {
			handle_sec_cp(sm, user_data, user_data_len);
		} else {
			handle_sec_rp(sm, user_data, user_data_len);
		}
	} else {
		handle_text(sm, user_data, user_data_len);
	}
}

void handle_tpdu(struct session_info *s, uint8_t *msg, const unsigned len, uint8_t from_network, char *smsc)
{
	uint8_t off;
	uint8_t f_len;
	uint8_t vp;
	struct sms_meta *sm;

	assert(s != NULL);
	assert(msg != NULL);
	assert(smsc != NULL);

	if (len < 2 || len > 255) {
		return;
	}

	sm = (struct sms_meta *) malloc(sizeof(struct sms_meta));
	assert(sm != NULL);
	memset(sm, 0, sizeof(*sm));

	/* Store SMSC */
	if (smsc[0]) {
		strncpy(sm->smsc, smsc, sizeof(sm->smsc));
	} else {
		strncpy(sm->smsc, "<NO ADDRESS>", sizeof(sm->smsc));
	}

	/* UDH presence */
	sm->udhi = !!(msg[0] & 0x40);

	/* Validity period */
	vp = (msg[0] >> 3) & 0x03;

	/* Skip flags [+mr] */
	if (from_network) {
		off = 1;
	} else {
		off = 2;
	}

	/* Decode from/to address */
	f_len = msg[off++] + 1;
	handle_address(&msg[off], f_len, sm->msisdn, 1);
	if (from_network) {
		sm->from_network = 1;
		APPEND_MSG_INFO(s, ", FROM %s", sm->msisdn);
	} else {
		sm->from_network = 0;
		APPEND_MSG_INFO(s, ", TO %s", sm->msisdn);
	}
	off += f_len/2 + 1;
	if (off >= len) {
		APPEND_MSG_INFO(s, " <TRUNCATED>");
		free(sm);
		return;
	}

	/* TP-PID and TP-DCS */
	sm->pid = msg[off++];
	sm->dcs = msg[off++];

	/* Decode DCS */
	sm->alphabet = get_sms_alphabet(sm->dcs);
	sm->class = get_sms_class(sm->dcs);

	if (off >= len) {
		APPEND_MSG_INFO(s, " <TRUNCATED>");
		free(sm);
		return;
	}

	/* Validity period */
	if (!from_network) {
		switch (vp) {
		case 0:
			break;
		case 2:
			off += 1;
			break;
		case 1:
		case 3:
			off += 7;
			break;
		}
	}

	/* Timestamp */
	if (from_network) {
		off += 7;
	}
	if (off >= len) {
		APPEND_MSG_INFO(s, " <TRUNCATED>");
		free(sm);
		return;
	}

	/* User data length */
	sm->length = msg[off++];
	if (msg_verbose > 1) {
		fprintf(stderr, "sm->length: %u\n", sm->length);
	}

	/* Data length sanity check */
	if ((sm->dcs & 0xe0) != 0x20) {
		if ((sm->length*7)/8 > (len - off)) {
			if (msg_verbose) {
				printf("len %d off %d sm->len %d sm->adjusted %d\n", len, off, sm->length, ((len-off)*8)/7);
			}
			APPEND_INFO(sm, "<TRUNCATED> ");

			/* Setting new message length (max) */
			sm->length = ((len - off) * 8) / 7;
		}
	} else {
		//FIXME: estimate compressed length
		if (msg_verbose > 1) {
			fprintf(stderr, "FIXME: estimate compressed length\n");
		}
	}

	if (off > len) {
		APPEND_MSG_INFO(s, " <TRUNCATED>");
		free(sm);
		return;
	}

	/* Store unparsed bytes */
	memcpy(sm->data, &msg[off], len - off);

	/* Handle UDH if present */
	if (sm->udhi) {
		handle_udh(sm, &msg[off], sm->length);
	} else {
		handle_text(sm, &msg[off], sm->length);
		sm->real_length = len-off;
	}

	//FIXME: discard normal sms, store only dcs = 192, 22, 246

	/* Append SMS to list */
	if (s->sms_list) {
		sm->sequence = s->sms_list->sequence+1;
	} else {
		sm->sequence = 0;
	}
	sm->next = s->sms_list;
	s->sms_list = sm;
}

void handle_rpdata(struct session_info *s, uint8_t *data, unsigned len, uint8_t from_network)
{
	uint8_t off = 0;
	uint8_t f_len;
	uint8_t type;
	char smsc[GSM48_MI_SIZE];

	assert(s != NULL);
	assert(data != NULL);

	if (!len) {
		return;
	}

	/* originating (SMSC) address length */
	f_len = data[off++];
	if (f_len) {
		/* Sanity check */
		if (!from_network) {
			SET_MSG_INFO(s, "SANITY CHECK FAILED (SMS_SMSC_MO)");
			return;
		}
		handle_address(&data[off], f_len, smsc, 0);
	}
	off += f_len;

	/* destination (SMSC) address length */
	f_len = data[off++];
	if (f_len) {
		/* Sanity check */
		if (from_network) {
			SET_MSG_INFO(s, "SANITY CHECK FAILED (SMS_SMSC_MT)");
			return;
		}
		handle_address(&data[off], f_len, smsc, 0);
	}
	off += f_len;

	/* user data length */
	f_len = data[off++];
	if (f_len > len - off) {
		/* Crop to available data */
		f_len = len - off - 1;
	}

	if (off >= len) {
		SET_MSG_INFO(s, "SANITY CHECK FAILED (SMS_OFFSET)");
		return;
	}

	/* MTI type */
	type = data[off] & 0x03;
	
	if (from_network) {
		switch (type) {
		case 0:
			/* SMS-DELIVER */
			APPEND_MSG_INFO(s, "-DELIVER");
			handle_tpdu(s, &data[off], f_len, from_network, smsc);
			break;
		case 1:
			/* SMS-SUBMIT REPORT */
			APPEND_MSG_INFO(s, "-SUBMIT-REPORT");
			break;
		case 2:
			/* SMS-STATUS REPORT */
			APPEND_MSG_INFO(s, "-STATUS-REPORT");
			break;
		case 3:
			/* RESERVED */
			APPEND_MSG_INFO(s, "-RESERVED");
			break;
		}
	} else {
		switch (type) {
		case 0:
			/* SMS-DELIVER REPORT */
			APPEND_MSG_INFO(s, "-DELIVER-REPORT");
			break;
		case 1:
			/* SMS-SUBMIT */
			APPEND_MSG_INFO(s, "-SUBMIT");
			handle_tpdu(s, &data[off], f_len, from_network, smsc);
			break;
		case 2:
			/* SMS-COMMAND */
			APPEND_MSG_INFO(s, "-COMMAND");
			break;
		case 3:
			/* RESERVED */
			APPEND_MSG_INFO(s, "-RESERVED");
			break;
		}
	}
}

void handle_cpdata(struct session_info *s, uint8_t *data, unsigned len)
{
	struct gsm411_rp_hdr *rp = (struct gsm411_rp_hdr *) data;

	if (len < sizeof(struct gsm411_rp_hdr)) {
		SET_MSG_INFO(s, "SANITY CHECK FAILED (RP_DATA_LEN)");
		return;
	}

	switch (rp->msg_type & 0x0f) {
	case GSM411_MT_RP_DATA_MO:
		SET_MSG_INFO(s, "SMS RP-DATA");
		handle_rpdata(s, rp->data, len-sizeof(struct gsm411_rp_hdr), 0);
		s->mo = 1;
		break;
	case GSM411_MT_RP_DATA_MT:
		SET_MSG_INFO(s, "SMS RP-DATA");
		handle_rpdata(s, rp->data, len-sizeof(struct gsm411_rp_hdr), 1);
		s->mt = 1;
		break;
	case GSM411_MT_RP_ACK_MO:
		SET_MSG_INFO(s, "SMS RP-ACK");
		s->mt = 1;
		break;
	case GSM411_MT_RP_ACK_MT:
		SET_MSG_INFO(s, "SMS RP-ACK");
		s->mo = 1;
		break;
	case GSM411_MT_RP_ERROR_MO:
		SET_MSG_INFO(s, "SMS RP-ERROR");
		s->mt = 1;
		break;
	case GSM411_MT_RP_ERROR_MT:
		SET_MSG_INFO(s, "SMS RP-ACK");
		s->mo = 1;
		break;
	case GSM411_MT_RP_SMMA_MO:
		SET_MSG_INFO(s, "SMS RP-SMMA");
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
		SET_MSG_INFO(s, "SMS CP-ACK");
		break;
	case GSM411_MT_CP_ERROR:
		SET_MSG_INFO(s, "SMS CP-ERROR");
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
	char *data;
	char *data_hex;
	char *tar;
	char *counter;

	assert(sm != NULL);
	assert(query != NULL);

	smsc = strescape_or_null(sm->smsc);
	msisdn = strescape_or_null(sm->msisdn);
	info = strescape_or_null(sm->info);
	tar = strescape_or_null(sm->ota_tar);
	counter = strescape_or_null(sm->ota_counter);
	if (sm->length) { 
		data_hex = strescape_or_null(osmo_hexdump_nospc(sm->data,sm->length));
		data = malloc(strlen(data_hex)+2);
		snprintf(data, strlen(data_hex)+2, "X%s", data_hex);
		free(data_hex);
	} else {
		data = strdup("'<NO DATA>'"); 
	}

	snprintf(query, len, "INSERT INTO sms_meta (id,sequence,from_network,pid,dcs,alphabet,"
		"class,udhi,concat,concat_frag,concat_total,"
		"src_port,dst_port,ota,ota_iei,ota_enc,ota_enc_algo,"
		"ota_sign,ota_sign_algo,ota_counter,ota_counter_value,ota_tar,ota_por,"
		"smsc,msisdn,info,length,udh_length,real_length,data)"
		" VALUES (%d,%d,%d,%d,%d,%d,"
		"%d,%d,%d,%d,%d,"
		"%d,%d,%d,%d,%d,%d,"
		"%d,%d,%d,%s,%s,%d,"
		"%s,%s,%s,%d,%d,%d,%s);\n",
		sid, sm->sequence, sm->from_network, sm->pid, sm->dcs, sm->alphabet,
		sm->class, sm->udhi, sm->concat, sm->concat_frag, sm->concat_total,
		sm->src_port, sm->dst_port, sm->ota, sm->ota_iei, sm->ota_enc, sm->ota_enc_algo,
		sm->ota_sign, sm->ota_sign_algo, sm->ota_counter_type, counter, tar, sm->ota_por,
		smsc, msisdn, info, sm->length, sm->udh_length, sm->real_length, data);

	free(smsc);
	free(msisdn);
	free(info);
	free(data);
}

