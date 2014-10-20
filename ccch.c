#include "cch.h"
#include "bit_func.h"
#include "l3_handler.h"
#include "gsm_interleave.h"
#include "output.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <osmocom/gsm/a5.h>
#include <assert.h>

uint8_t compute_ber(struct session_info *s, struct radio_message *m)
{
	unsigned i, j, uplink;
	unsigned bit_errors = 0;
	uint8_t raw_coded[CONV_SIZE];

	encode_signalling(m->msg, raw_coded);

	uplink = !!(m->bb.arfcn[0] & ARFCN_UPLINK);

	if (m->flags & MSG_CIPHERED) {
		uint8_t ks[114];

		for (j=0; j<4; j++) {
			if (uplink)
				osmo_a5(s->cipher, s->key, m->bb.fn[j], 0, ks);
			else
				osmo_a5(s->cipher, s->key, m->bb.fn[j], ks, 0);

			for (i=0; i<114; i++) {
				if ((raw_coded[j*114+i]^ks[i]) != m->bb.data[j*114+i])
					bit_errors++;
			}
		}
	} else {
		for (j=0; j<4; j++) {
			for (i=0; i<114; i++) {
				if (raw_coded[j*114+i] != m->bb.data[j*114+i])
					bit_errors++;
			}
		}
	}

	return (bit_errors > CONV_SIZE/2 ? CONV_SIZE/2 : bit_errors);
}

int try_decode(struct session_info *s, struct radio_message *m)
{
	int ret, uplink;
	unsigned i, j;
	int8_t snr_amp;
	int8_t deciphered[CONV_SIZE];
	int8_t conv_data[CONV_SIZE];

	uplink = !!(m->bb.arfcn[0] & ARFCN_UPLINK);

	if (m->flags & MSG_CIPHERED) {
		uint8_t ks[114];

		for (j=0; j<4; j++) {
			if (uplink)
				osmo_a5(s->cipher, s->key, m->bb.fn[j], 0, ks);
			else
				osmo_a5(s->cipher, s->key, m->bb.fn[j], ks, 0);

			snr_amp = m->bb.snr[j] >> 1;
			for (i=0; i<114; i++) {
				deciphered[j*114+i] = (m->bb.data[j*114+i]^ks[i] ? -snr_amp : snr_amp);
			}
		}
	} else {
		for (j=0; j<4; j++) {
			snr_amp = m->bb.snr[j] >> 1;
			for (i=0; i<114; i++) {
				deciphered[j*114+i] = (m->bb.data[j*114+i] ? -snr_amp : snr_amp);
			}
		}
	}

	gsm_deinter_sacch((uint8_t*)deciphered, (uint8_t*)conv_data);

	ret = decode_signalling(conv_data, m->msg);
	if (ret) {
		m->flags |= MSG_DECODED;
		m->msg_len = 23;
		m->rat = RAT_GSM;

		if (m->flags & MSG_SACCH)
			handle_lapdm(s, &s->chan_sacch[uplink], &m->msg[2], 21, m->bb.fn[0], uplink);
		else
			handle_lapdm(s, &s->chan_sdcch[uplink], m->msg, 23, m->bb.fn[0], uplink);
	}

	return ret;
}

uint8_t chan_burst_id(uint8_t chan_nr)
{
	return 0;
}

void process_ccch(struct session_info *s, struct burst_buf *bb, struct l1ctl_burst_ind *bi)
{
	int i;
	struct radio_message *m;
	uint32_t fn;
	uint16_t arfcn;
	uint8_t type;

	/* append data to message buffer */

	assert(bb->count <= 3);

	expand_msb(bi->bits, bb->data + bb->count * 114, 114);

	fn = ntohl(bi->frame_nr);
	arfcn = ntohs(bi->band_arfcn);
	//type = chan_detect(fn, bi->chan_nr, &subch);
	type = (bi->chan_nr < 0x20) ? 1 : 0;

	/* if a burst is already present */
	if (bb->count) {
		if (!type) {
			uint32_t next_fn = (bb->fn[bb->count-1] + 1) % (2048*26*51);
	
			/* check burst ordering */
			if (fn != next_fn) {
				bb->count = 0;
				return;
			}
		}
	}

	bb->snr[bb->count] = bi->snr;
	bb->rxl[bb->count] = bi->rx_level;
	bb->fn[bb->count] = fn;
	bb->arfcn[bb->count] = arfcn;
	bb->count++;

	/* Return if not enough bursts for a full gsm message */
	if (bb->count < 4)
		return;

	/* fill new message structure */
	m = malloc(sizeof(struct radio_message));
	m->chan_nr = bi->chan_nr;

	if (bi->flags & BI_FLG_SACCH) {
		m->flags = MSG_SACCH;
	} else {
		m->flags = MSG_SDCCH;
	}

	if (s->cipher || (type && not_zero(s->key, 8)))
		m->flags |= MSG_CIPHERED;

	memcpy(&m->bb, bb, sizeof(bb));

	m->info[0] = 0;

	/* link to the list */
	if (s->first_msg == NULL) {
		s->first_msg = m;
	}
	if (s->last_msg) {
		s->last_msg->next = m;
	}
	m->next = NULL;
	m->prev = s->last_msg;
	s->last_msg = m;

	/* ready for decoding */
	try_decode(s, m);

	/* reset burst buffer */
	bb->count = 0;

	return;
}

