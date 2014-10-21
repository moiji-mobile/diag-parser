#include <time.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <osmocom/gsm/rsl.h>
#include <osmocom/core/utils.h>
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <assert.h>
#include <arpa/inet.h>

#include "diag_input.h"
#include "process.h"
#include "session.h"
#include "diag_structs.h"
#include "l3_handler.h"

struct diag_packet {
	uint16_t msg_class;
	uint16_t len;
	uint16_t inner_len;
	uint16_t msg_protocol;
	uint64_t timestamp;
	uint8_t msg_type;
	uint8_t msg_subtype;
	uint8_t data_len;
	uint8_t data[0];
} __attribute__ ((packed));

void diag_init(unsigned start_sid, unsigned start_cid)
{
#ifdef USE_MYSQL
	session_init(start_sid, start_cid, 0, 0, CALLBACK_MYSQL);
	//msg_verbose = 1;
#else
#ifdef USE_SQLITE
	session_init(start_sid, start_cid, 0, 1, CALLBACK_SQLITE);
#else
	session_init(start_sid, start_cid, 0, 0, CALLBACK_CONSOLE);
#endif
#endif
}

void diag_destroy()
{
	session_destroy();
}

inline
uint32_t get_fn(struct diag_packet *dp)
{
	return (dp->timestamp/204800)%GSM_MAX_FN;
}

inline
void print_common(struct diag_packet *dp, unsigned len)
{
	printf("%u [%02u] ", get_fn(dp), dp->len);
	printf("%04x/%03u/%03u ", dp->msg_protocol, dp->msg_type, dp->msg_subtype);
	printf("[%03u] %s\n", dp->data_len, osmo_hexdump_nospc(dp->data, len-2-sizeof(struct diag_packet)));
}

struct radio_message * handle_3G(struct diag_packet *dp, unsigned len)
{
	unsigned payload_len;
	struct radio_message *m;

	payload_len = dp->len - 16;

	assert(payload_len < sizeof(m->bb.data));

	m = (struct radio_message *) malloc(sizeof(struct radio_message));

	memset(m, 0, sizeof(struct radio_message));

	m->rat = RAT_UMTS;
	m->bb.fn[0] = get_fn(dp);
	switch (dp->msg_type) {
	case 1:
		m->bb.arfcn[0] = ARFCN_UPLINK;
		break;
	case 3:
		m->bb.arfcn[0] = 0;
		break;
	default:
		free(m);
		return 0;
	}

	m->msg_len = payload_len;
	memcpy(m->bb.data, &dp->data[1], payload_len);

	return m;
}

struct radio_message * handle_4G(struct diag_packet *dp, unsigned len)
{
	switch (dp->msg_protocol) {
	case 0xb0c0: // LTE RRC
		if (dp->data[0]) {
			// Uplink
			//(&dp->data[1], dp->len-16);
		} else {
			// Downlink
			//(&dp->data[1], dp->len-16);
		}
		break;
	case 0xb0ec: // LTE NAS EMM DL
		//(&dp->data[1], dp->len-16);
		break;
	case 0xb0ed: // LTE NAS EMM UL
		//(&dp->data[1], dp->len-16);
		break;
	}

	return 0;
}

struct radio_message * handle_nas(struct diag_packet *dp, unsigned len)
{
	/* sanity checks */
	if (dp->msg_subtype + sizeof(struct diag_packet) + 2 > len)
		return 0;

	if (!dp->msg_subtype)
		return 0;

	return new_l3(&dp->data[2], dp->msg_subtype, RAT_GSM, DOMAIN_CS, get_fn(dp), dp->msg_type, MSG_SDCCH);
}

struct radio_message * handle_bcch_and_rr(struct diag_packet *dp, unsigned len)
{
	unsigned dtap_len;

	dtap_len = len - 2 - sizeof(struct diag_packet);

	switch (dp->msg_type) {
	case 0: // SDCCH UL RR
		switch (dp->msg_subtype) {
		case 22: // Classmark change
		case 39: // Paging response
		case 41: // Assignment complete
		case 44: // Handover complete
		case 50: // Ciphering mode complete
		case 52: // GPRS susp. request
		case 96: // UTRAN classmark change
			return new_l3(dp->data, dtap_len, RAT_GSM, DOMAIN_CS, get_fn(dp), 1, MSG_SDCCH);
		default:
			print_common(dp, len);
		}
		break;
	case 4: // SACCH UL
		switch (dp->msg_subtype) {
		case 21: // Measurement report
			return new_l3(dp->data, dtap_len, RAT_GSM, DOMAIN_CS, get_fn(dp), 1, MSG_SACCH);
		default:
			print_common(dp, len);
		}
		break;
	case 128: /* SDCCH DL RR */
		return new_l3(dp->data, dtap_len, RAT_GSM, DOMAIN_CS, get_fn(dp), 0, MSG_SDCCH);
	case 129: /* BCCH */
		return new_l2(dp->data, dp->data_len, RAT_GSM, DOMAIN_CS, get_fn(dp), 0, MSG_BCCH);
	case 131: /* CCCH */
		return new_l2(dp->data, dp->data_len, RAT_GSM, DOMAIN_CS, get_fn(dp), 0, MSG_BCCH);
	case 132: /* SACCH DL RR */
		return new_l3(dp->data, dtap_len, RAT_GSM, DOMAIN_CS, get_fn(dp), 0, MSG_SACCH);
	default:
		print_common(dp, len);
	}

	return 0;
}

void handle_periodic_task()
{
	cell_and_paging_dump(0);
}

void handle_measurements(struct diag_packet *dp, unsigned len)
{
	int i;
	struct gsm_l1_surround_cell_ba_list *cl;
	struct surrounding_cell *sc;

	cl = &dp->msg_type;
	sc = cl->surr_cells;

	printf("Cell data: %s\n", osmo_hexdump_nospc(cl, 8));

	for (i = 0; i < cl->cell_count; i++) {
		printf("Surrounding cell %d: arfcn %u rxlev %d\n",
			i,
			get_arfcn_from_arfcn_and_band(sc[i].bcch_arfcn_and_band),
			ntohs(sc[i].rx_power));
	}
}

void handle_diag(uint8_t *msg, unsigned len)
{
	struct diag_packet *dp = (struct diag_packet *) msg;
	struct radio_message *m = 0;

	if (dp->msg_class != 0x0010) {
		//printf("Class %04x is not supported\n", dp->msg_class);
		return;
	}

	switch(dp->msg_protocol) {
	case 0x412f: // 3G RRC
		m = handle_3G(dp, len);
		break;

	case 0x5071: // Surrounding cell measurements
		handle_measurements(dp, len);
		break;

	case 0x512f: // GSM RR
		m = handle_bcch_and_rr(dp, len);
		break;

	case 0x5230: // GPRS GMM (doubled msg)
		break;

	case 0x713a: // DTAP (2G, 3G)
		m = handle_nas(dp, len);
		break;

	case 0xb0c0: // LTE RRC
	case 0xb0ec: // LTE NAS EMM DL
	case 0xb0ed: // LTE NAS EMM UL
		m = handle_4G(dp, len);
		break;

	default:
		print_common(dp, len);
		break;
	}

	if (m) {
		gettimeofday(&m->timestamp, NULL);
		handle_radio_msg(_s, m);
	}
}
