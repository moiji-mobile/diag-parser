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

void handle_gsm_l1_txlev_timing_advance(struct diag_packet *dp, unsigned len)
{
	struct gsm_l1_txlev_timing_advance *decoded = (struct gsm_l1_txlev_timing_advance*) &dp->msg_type;

	decoded->arfcn_and_band = ntohs(decoded->arfcn_and_band);

	assert(len-16-2 == 4);
	printf("x gsm_l1_txlev_timing_advance\n");
	//printf("x %s\n", osmo_hexdump_nospc(&dp->msg_type, len-16) );
	printf("x -> arfcn: %d\n", get_arfcn_from_arfcn_and_band(decoded->arfcn_and_band));
	printf("x -> band: %d\n", get_band_from_arfcn_and_band(decoded->arfcn_and_band));
	printf("x -> timing advance: %u\n", decoded->timing_advance);
	printf("x -> tx_power_level: %u\n", decoded->tx_power_level);
}

void handle_gsm_l1_surround_cell_ba_list(struct diag_packet *dp, unsigned len)
{
	struct gsm_l1_surround_cell_ba_list *cl = (struct gsm_l1_surround_cell_ba_list *)&dp->msg_type;
	struct surrounding_cell *sc = cl->surr_cells;

	assert(len-16-2 == sizeof(struct surrounding_cell)*cl->cell_count + 1);

	printf("x gsm_l1_surround_cell_ba_list\n");
	int i;
	for (i = 0; i < cl->cell_count; i++) {
		printf("x -> Surrounding cell %d -- arfcn %u band: %u rx_power %d frame_number_offset: %u\n",
			i,
			get_arfcn_from_arfcn_and_band(ntohs(sc[i].bcch_arfcn_and_band)),
			get_band_from_arfcn_and_band(ntohs(sc[i].bcch_arfcn_and_band)),
			sc[i].rx_power,
			sc[i].frame_number_offset
		);
	}
}

void handle_gsm_l1_burst_metrics(struct diag_packet *dp, unsigned len)
{
	struct gsm_l1_burst_metrics *dat = (struct gsm_l1_burst_metrics *)&dp->msg_type;

	assert(len-16-2 == sizeof(struct gsm_l1_burst_metrics));

	printf("x gsm_l1_burst_metrics\n");
	printf("x -> channel: %u\n", dat->channel);
	int i;
	for (i = 0; i < 4; i++) {
		printf("x -> Burst metric %d -- arfcn %u band: %u frame_number: %u rssi: %u rx_power: %d\n",
			i,
			get_arfcn_from_arfcn_and_band(ntohs(dat->metrics[i].arfcn_and_band)),
			get_band_from_arfcn_and_band(ntohs(dat->metrics[i].arfcn_and_band)),
			dat->metrics[i].frame_number,
			dat->metrics[i].rssi,
			dat->metrics[i].rx_power
			//,ntohl(sc[i].frame_number_offset)
		);
	}
}

void handle_gsm_l1_neighbor_cell_auxiliary_measurments(struct diag_packet *dp, unsigned len)
{
	struct gsm_l1_neighbor_cell_auxiliary_measurments *cl = (struct gsm_l1_neighbor_cell_auxiliary_measurments *)&dp->msg_type;

	assert(len-16-2 == sizeof(struct cell)*cl->cell_count + 1);

	printf("x gsm_l1_neighbor_cell_auxiliary_measurments\n");
	int i;
	for (i = 0; i < cl->cell_count; i++) {
		struct cell* c = cl->cells + i;
		printf("x -> cell %d -- arfcn %u band: %u rx_power %d\n",
			i,
			get_arfcn_from_arfcn_and_band(ntohs(c[i].arfcn_and_band)),
			get_band_from_arfcn_and_band(ntohs(c[i].arfcn_and_band)),
			c[i].rx_power
		);
	}
}

void handle_gsm_monitor_bursts_v2(struct diag_packet *dp, unsigned len)
{
	struct gsm_monitor_bursts_v2 *cl = (struct gsm_monitor_bursts_v2 *)&dp->msg_type;

	assert(len-16-2 == sizeof(struct monitor_record)*cl->number_of_records + 4);

	printf("x gsm_monitor_bursts_v2\n");
	int i;
	for (i = 0; i < cl->number_of_records; i++) {
		struct monitor_record* c = cl->records + i;
		printf("x -> record %d -- arfcn %u band: %u frame no %d rx_power %d\n",
			i,
			get_arfcn_from_arfcn_and_band(ntohs(c[i].arfcn_and_band)),
			get_band_from_arfcn_and_band(ntohs(c[i].arfcn_and_band)),
			c[i].frame_number,
			c[i].rx_power
		);
	}
}

void handle_gprs_grr_cell_reselection_measurements(struct diag_packet *dp, unsigned len)
{
	struct gprs_grr_cell_reselection_measurements *cl = (struct gprs_grr_cell_reselection_measurements *)&dp->msg_type;

	//printf("num %d len: %d, shoudl be %d\n", cl->neighboring_6_strongest_cells_count, len-16-2, sizeof(struct neighbor)*cl->neighboring_6_strongest_cells_count + 26);
	//assert(len-16-2 == sizeof(struct neighbor)*cl->neighboring_6_strongest_cells_count + 26);
	assert(len-16-2 == sizeof(struct gprs_grr_cell_reselection_measurements));

	printf("x gprs_grr_cell_reselection_measurements\n");
	int i;
	for (i = 0; i < cl->neighboring_6_strongest_cells_count; i++) {
		struct neighbor* c = cl->neigbors + i;
		printf("x -> neighbor %d -- BCC arfcn %u band: %u  PBCC arfcn %u band: %u rx_level_avg %u\n",
			i,
			get_arfcn_from_arfcn_and_band(ntohs(c[i].neighbor_cell_bcch_arfcn_and_band)),
			get_band_from_arfcn_and_band(ntohs(c[i].neighbor_cell_bcch_arfcn_and_band)),
			get_arfcn_from_arfcn_and_band(ntohs(c[i].neighbor_cell_pbcch_arfcn_and_band)),
			get_band_from_arfcn_and_band(ntohs(c[i].neighbor_cell_pbcch_arfcn_and_band)),
			c[i].neighbor_cell_rx_level_average
		);
	}
}

void handle_diag(uint8_t *msg, unsigned len)
{
	struct diag_packet *dp = (struct diag_packet *) msg;
	struct radio_message *m = 0;

	if (dp->msg_class != 0x0010) {
		if (msg_verbose) {
			fprintf(stderr, "Class %04x is not supported\n", dp->msg_class);
		}
		return;
	}

	switch(dp->msg_protocol) {
	case 0x5071:
		if (msg_verbose) {
			fprintf(stderr, "handle_gsm_l1_surround_cell_ba_list\n");
		}
		handle_gsm_l1_surround_cell_ba_list(dp, len);
		break;

	case 0x506C:
		if (msg_verbose) {
			fprintf(stderr, "handle_gsm_l1_burst_metrics\n");
		}
		handle_gsm_l1_burst_metrics(dp, len);
		break;

	case 0x5076:
		if (msg_verbose) {
			fprintf(stderr, "handle_gsm_l1_txlev_timing_advance\n");
		}
		handle_gsm_l1_txlev_timing_advance(dp, len);
		break;

	case 0x507B:
		if (msg_verbose) {
			fprintf(stderr, "handle_gsm_l1_neighbor_cell_auxiliary_measurments\n");
		}
		handle_gsm_l1_neighbor_cell_auxiliary_measurments(dp,len);
		break;

	case 0x5082:
		if (msg_verbose) {
			fprintf(stderr, "handle_gsm_monitor_bursts_v2\n");
		}
		handle_gsm_monitor_bursts_v2(dp, len);
		break;

	case 0x51FC:
		if (msg_verbose) {
			fprintf(stderr, "handle_gprs_grr_cell_reselection_measurements\n");
		}
		handle_gprs_grr_cell_reselection_measurements(dp, len);
		break;

	case 0x412f: // 3G RRC
		if (msg_verbose) {
			fprintf(stderr, "-> Handling 3G\n");
		}
		m = handle_3G(dp, len);
		break;

	case 0x512f: // GSM RR
		if (msg_verbose) {
			fprintf(stderr, "Handling GSM RR\n");
		}
		m = handle_bcch_and_rr(dp, len);
		break;

	case 0x5230: // GPRS GMM (doubled msg)
		if (msg_verbose) {
			fprintf(stderr, "-> Not handling GPRS GMM\n");
		}
		break;

	case 0x713a: // DTAP (2G, 3G)
		if (msg_verbose) {
			fprintf(stderr, "-> Handling NAS\n");
		}
		m = handle_nas(dp, len);
		break;

	case 0xb0c0: // LTE RRC
	case 0xb0ec: // LTE NAS EMM DL
	case 0xb0ed: // LTE NAS EMM UL
		if (msg_verbose) {
			fprintf(stderr, "-> Handling 4G\n");
		}
		m = handle_4G(dp, len);
		break;

	default:
		if (msg_verbose) {
			fprintf(stderr, "-> Handling default case\n");
		}
		print_common(dp, len);
		break;
	}

	if (m) {
		gettimeofday(&m->timestamp, NULL);
		handle_radio_msg(_s, m);
	}
}
