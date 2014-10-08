#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <osmocom/core/gsmtap.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/select.h>
#include <osmocom/gsm/rsl.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/gsm/gsm_utils.h>

#include "process.h"
#include "gsm_interleave.h"
#include "sch.h"
#include "cch.h"
#include "chan_detect.h"
#include "crc.h"

#include "process.h"
#include "session.h"
#include "l3_handler.h"
#include "ccch.h"

void process_init()
{
	gsm_interleave_init();
	gprs_init();
}

int process_handle_burst(struct session_info *s, struct l1ctl_burst_ind *bi)
{
	int len, ul;
	uint32_t fn;
	uint8_t type, subch, ts;
	uint8_t msg[54];
	struct burst_buf *bb = 0;

	rsl_dec_chan_nr(bi->chan_nr, &type, &subch, &ts);

	fn = ntohl(bi->frame_nr);
	ul = !!(ntohs(bi->band_arfcn) & ARFCN_UPLINK);

	//printf("fn %d ts %d ul %d snr %d ", fn, ts, ul, bi->snr);
	//printf(" sub %d\n", chan_detect(fn, ts, comb, &sub), sub);

	switch (type) {
	case RSL_CHAN_Lm_ACCHs:
		// interleaved user data and signalling
		break;
	case RSL_CHAN_Bm_ACCHs:
		if (bi->flags & BI_FLG_SACCH) {
			/* burst is SACCH/T */
			process_ccch(s, &s->saccht[ul], bi);
		} else {
			//FIXME: detect type of channel
			/* try TCH (FACCH) */
			len = process_tch(s, bi, msg);
			/* try PDCH */
			//len = process_pdch(s, bi, msg);
		}
		break;
	case RSL_CHAN_BCCH:
		//FIXME: check fn to know which type it really is
	case RSL_CHAN_SDCCH4_ACCH:
		//FIXME: check fn to know which type it really is
	case RSL_CHAN_SDCCH8_ACCH:
		//FIXME: check fn to know which type it really is
		if (bi->flags & BI_FLG_SACCH) {
			bb = &s->sacch;
		} else {
			bb = &s->sdcch;
		}
		process_ccch(s, bb, bi);
		break;
	case RSL_CHAN_RACH:
	case RSL_CHAN_PCH_AGCH:
	default:
		printf("Type not handled! %.02x\n", type);
	}

	return 0;
}

void process_end()
{
}
