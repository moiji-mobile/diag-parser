#include "cch.h"
#include "output.h"
#include "bit_func.h"
#include <osmocom/gsm/a5.h>
#include <arpa/inet.h>
#include <stdlib.h>

#include "gsm_interleave.h"
#include "l3_handler.h"

int process_tch(struct session_info *s, struct l1ctl_burst_ind *bi, uint8_t *msg)
{
	int ret, ul;
	uint16_t arfcn;
	uint32_t fn;
	uint8_t conv_data[CONV_SIZE];
	struct burst_buf *bb;

	arfcn = ntohs(bi->band_arfcn);
	ul = !!(arfcn & ARFCN_UPLINK);
	fn = ntohl(bi->frame_nr);

	bb = &s->facch[ul];

	/* append data to message buffer */
	expand_msb(bi->bits, bb->data + bb->count * 114, 114);

	if(not_zero(s->key, 8)) {
		int i;
		uint8_t ks[114];
		if (ul)
			osmo_a5(1, s->key, fn, 0, ks);
		else
			osmo_a5(1, s->key, fn, ks, 0);

		for (i=0; i<114; i++) {
			bb->data[bb->count * 114 + i] ^= ks[i];
		}
	}

	// not used
	bb->sbit[bb->count * 2 + 0] = !!(bi->bits[14] & 0x10);
	bb->sbit[bb->count * 2 + 1] = !!(bi->bits[14] & 0x20);

	bb->snr[bb->count] = bi->snr;
	bb->rxl[bb->count] = bi->rx_level;

	/* check burst flags */
	switch (bi->bits[14] & 0x30) {
	case 0x00:
		/* TCH + TCH */
		//printf("TCH\n");
		/* voice blocks or flags corrupted */
		if (bb->count) {
			/* already had errors? */
			if (bb->errors < 2) {
				/* give a try and record error */
				bb->count++;
				bb->errors++;
			} else {
				/* discard all bursts in buffer */
				bb->count = 0;
				bb->errors = 0;
				return 0;
			}
		} else {
			/* process voice */
			return 0;
		}
		break;
	case 0x20:
		/* FACCH + TCH */
		//printf("FACCH+TCH\n");
		if (bb->count == 0) {
			/* start burst buffering */
			bb->count = 1;
		} else {
			/* check how many bursts in buffer */
			if (bb->count < 4) {
				/* all ok, append */
				bb->count++;
			} else {
				/* severely errored burst, other errors? */
				if (bb->errors < 2) {
					/* give a try and record error */
					bb->count++;
					bb->errors++;
				} else {
					/* discard all bursts in buffer */
					bb->count = 0;
					bb->errors = 0;
					return 0;
				}
			}
		}
		break;
	case 0x10:
		/* TCH + FACCH */
		//printf("TCH+FACCH\n");
		if (bb->count > 3) {
			/* all ok, append */
			bb->count++;
		} else {
			/* severely errored burst, other errors? */
			if (bb->errors < 2) {
				/* give a try and record error */
				bb->count++;
				bb->errors++;
			} else {
				/* discard all bursts in buffer */
				bb->count = 0;
				bb->errors = 0;
				return 0;
			}
		}
		break;
	case 0x30:
		/* FACCH + FACCH (or GPRS) */
		//printf("FACCH\n");
		if (bb->count > 3) {
			/* probably overlapping FACCHs */
			bb->count++;
			//record a & b facch separately
		} else {
			/* overlapping and misaligned? */
			bb->count++;
			bb->errors++;
		}
	}

	/* Return if not enough bursts for a full gsm message */
	if (bb->count == 8) {
		struct radio_message *m;

		/* try to decode FACCH */

		/* de-interleaving */
		gsm_deinter_facch(bb->data, conv_data);

		ret = decode_signalling(conv_data, msg);
		if (!ret) {
			/* skip one burst and wait next */
			// some circular buffer needed
			memcpy(bb->data, bb->data + 114, 7 * 114);
			memcpy(bb->sbit, bb->sbit + 2, 7 * 2);
			bb->count = 7;
			bb->errors /= 2; // approximated value
			return 0;
		}

		m = malloc(sizeof(struct radio_message));
		memcpy(&m->bb, bb, sizeof(*bb));
		m->chan_nr = bi->chan_nr;
		m->flags = MSG_FACCH|MSG_DECODED;
		if (s->have_key)
			m->flags |= MSG_CIPHERED;
		memcpy(m->msg, msg, 23);
		m->msg_len = 23;

		handle_lapdm(s, &s->chan_facch[ul], m->msg, m->msg_len, m->bb.fn[0], ul);

		net_send_msg(m);

		/* check overlapping status */
		if ((bi->bits[14] & 0x30) == 0x30) {
			/* start subsequent message processing */
			memcpy(bb->data, bb->data + 4 * 114, 4 * 114);
			memcpy(bb->sbit, bb->sbit + 4 * 2, 4 * 2);
			bb->count = 4;
			bb->errors /= 2; // approximated value
			memset(bb->data + bb->count*114, 0, sizeof(bb->data)/2);
		} else {
			/* nothing else in the buffer, reset */
			bb->count = 0;
			bb->errors = 0;
			memset(bb->data, 0, sizeof(bb->data));
		}

		return 23;
	}

	return 0;
}
