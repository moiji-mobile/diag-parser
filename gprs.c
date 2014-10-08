#include "string.h"
#include <arpa/inet.h>

#include "bit_func.h"
#include "cch.h"
#include "punct.h"
#include "viterbi.h"
#include "gprs.h"
#include "rlcmac.h"
#include "gsm_interleave.h"
#include "crc.h"

static unsigned map_cs2[456];
static unsigned map_cs3[456];

void gprs_init()
{
	fill_punct_cs2(map_cs2);
	fill_punct_cs3(map_cs3);
	memset(tbf_table, 0, sizeof(tbf_table));
}

inline unsigned distance(const uint8_t *a, const uint8_t *b, const unsigned size)
{
	int i, distance = 0;

	for (i=0; i<size; i++) {
		distance += !!(a[i] ^ b[i]);
	}

	return distance;
}

enum {CS1 = 0, CS2, CS3, CS4};

int cs_estimate(const uint8_t *sflags)
{
	int i;
	unsigned cs_dist[4];
	const uint8_t cs_pattern[][8] = {{1, 1, 1, 1, 1, 1, 1, 1},
					 {1, 1, 0, 0, 1, 0, 0, 0},
					 {0, 0, 1, 0, 0, 0, 0, 1},
					 {0, 0, 0, 1, 0, 1, 1, 0}};

	for (i=0;i<4;i++) {
		cs_dist[i] = distance(sflags, cs_pattern[i], 8);
	}

	if (cs_dist[0] < cs_dist[1])
		i = CS1;
	else
		i = CS2;
	if (cs_dist[2] < cs_dist[i])
		i = CS3;
	if (cs_dist[3] < cs_dist[i])
		i = CS4;
	return i;
}

int usf6_estimate(const uint8_t *data)
{
	int i, min;
	unsigned usf_dist[8];
	const uint8_t usf_pattern[][6] = {{0, 0, 0, 0, 0, 0},
					  {0, 0, 1, 0, 1, 1},
					  {0, 1, 0, 1, 1, 0},
					  {0, 1, 1, 1, 0, 1},
					  {1, 0, 0, 1, 0, 1},
					  {1, 0, 1, 1, 1, 0},
					  {1, 1, 0, 0, 1, 1},
					  {1, 1, 1, 0, 0, 0}};


	for (i=0; i<8; i++) {
		usf_dist[i] = distance(data, usf_pattern[i], 6);
	}

	for (i=1, min=0; i<8; i++) {
		if (usf_dist[i] < usf_dist[min])
			min = i;
	}

	return min;
}

int usf12_estimate(const uint8_t *data)
{
	int i, min;
	unsigned usf_dist[8];
	const uint8_t usf_pattern[][12] = {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
					   {0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0, 1},
					   {0, 0, 1, 1, 0, 1, 1, 1, 0, 1, 1, 0},
					   {0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1},
					   {1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1},
					   {1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0},
					   {1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 1},
					   {1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0}};


	for (i=0; i<8; i++) {
		usf_dist[i] = distance(data, usf_pattern[i], 12);
	}

	for (i=1, min=0; i<8; i++) {
		if (usf_dist[i] < usf_dist[min])
			min = i;
	}

	return min;
}

int process_pdch(struct session_info *s, struct l1ctl_burst_ind *bi, uint8_t *gprs_msg)
{
	int len, ret, usf;
	uint8_t	ts, ul;
	uint32_t fn;
	uint16_t arfcn;
	struct burst_buf *bb;
	struct radio_message m;
	uint8_t conv_data[CONV_SIZE];
	int8_t depunct_data[2*CONV_SIZE];
	uint8_t decoded_data[2*CONV_SIZE];
	const uint8_t ccitt_poly[16 + 1] = {1, 0, 0, 0, 1, 0, 0, 0,
					    0, 0, 0, 1, 0, 0, 0, 0,
					    1};

	const uint8_t ccitt_rem[16] = {1, 1, 1, 1, 1, 1, 1, 1,
				       1, 1, 1, 1, 1, 1, 1, 1};

	/* get burst parameters */
	fn = ntohl(bi->frame_nr);
	arfcn = ntohs(bi->band_arfcn);
	ul = !!(arfcn & ARFCN_UPLINK);
	ts = bi->chan_nr & 7;

	/* select frame queue */
	if (ul)
		bb = &s->gprs[2*ts + 0];
	else
		bb = &s->gprs[2*ts + 1];

	/* check burst alignment */
	if (((fn % 13) % 4) != bb->count)
		return 0;

	/* enqueue data into message buffer */
	expand_msb(bi->bits, bb->data + bb->count * 114, 114);

	/* save stealing flags */
	bb->sbit[bb->count * 2 + 0] = !!(bi->bits[14] & 0x10);
	bb->sbit[bb->count * 2 + 1] = !!(bi->bits[14] & 0x20);

	bb->snr[bb->count] = bi->snr;
	bb->rxl[bb->count] = bi->rx_level;
	bb->arfcn[bb->count] = arfcn;
	bb->fn[bb->count] = fn;
	bb->count++;

	/* Return if not enough bursts for a full message */
	if (bb->count < 4)
		return 0;

	/* de-interleaving */
	memset(conv_data, 0, sizeof(conv_data));
	gsm_deinter_sacch(bb->data, conv_data);

	len = 0;

	switch (cs_estimate(bb->sbit)) {
	case CS1:
		len = decode_signalling(conv_data, gprs_msg);
		break;
	case CS2:
		/* depuncture and convert to soft bits */
		depunct(conv_data, depunct_data, 294*2, map_cs2);

		/* Viterbi decode */
		conv_cch_decode(depunct_data, decoded_data, 294);

		/* decode USF bits */
		usf = usf6_estimate(decoded_data);

		/* rebuild original data string for CRC check */
		decoded_data[3] = (usf >> 2) & 1;
		decoded_data[4] = (usf >> 1) & 1;
		decoded_data[5] = (usf >> 0) & 1;

		/* compute CRC-16 (CCITT) */
		ret = parity_check(decoded_data + 3, 271, ccitt_poly, ccitt_rem, 16);

		if (!ret) {
			compress_lsb(decoded_data + 3, gprs_msg, 33 * 8);
			len = 33;
		}
		break;
	case CS3:
		/* depuncture and convert to soft bits */
		depunct(conv_data, depunct_data, 338*2, map_cs3);

		/* Viterbi decode */
		conv_cch_decode(depunct_data, decoded_data, 338);

		/* decode USF bits */
		usf = usf6_estimate(decoded_data);

		/* rebuild original data string for CRC check */
		decoded_data[3] = (usf >> 2) & 1;
		decoded_data[4] = (usf >> 1) & 1;
		decoded_data[5] = (usf >> 0) & 1;

		/* compute CRC-16 (CCITT) */
		ret = parity_check(decoded_data + 3, 315, ccitt_poly, ccitt_rem, 16);

		if (!ret) {
			compress_lsb(decoded_data + 3, gprs_msg, 39 * 8);
			len = 39;
		}
		break;
	case CS4:
		/* decode USF bits */
		usf = usf12_estimate(conv_data);

		/* rebuild original data string for CRC check */
		conv_data[9] = (usf >> 2) & 1;
		conv_data[10] = (usf >> 1) & 1;
		conv_data[11] = (usf >> 0) & 1;

		/* compute CRC-16 (CCITT) */
		ret = parity_check(conv_data + 9, 431, ccitt_poly, ccitt_rem, 16);

		if (!ret) {
			compress_lsb(conv_data + 9, gprs_msg, 53 * 8);
			len = 53; // last byte not used (0x2b)
		}
		break;
	}

	/* if a message is decoded */
	if (len) {
		int i;
		unsigned s_sum, r_sum;

		/* fill gprs message struct */
		memcpy(&m.bb, bb, sizeof(bb));
		m.rat = RAT_GSM;
		m.domain = DOMAIN_PS;
		m.chan_nr = ts;
		m.msg_len = len;
		memcpy(m.msg, gprs_msg, len);

		/* call handler */
		rlc_type_handler(&m);
	}

	/* reset buffer */
	memset(bb->data, 0, sizeof(bb->data));
	bb->count = 0;

	return len;
}

