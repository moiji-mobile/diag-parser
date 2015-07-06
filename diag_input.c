#include <time.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <osmocom/gsm/rsl.h>
#include <osmocom/core/utils.h>
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <arpa/inet.h>
#include <assert.h>

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

struct burst_info {
	uint32_t fn;
	uint16_t arfcn[4];
} last_burst;

struct radio_message *last_m = NULL;

void diag_init(unsigned start_sid, unsigned start_cid, const char *gsmtap_target, char *filename, uint32_t appid)
{
	int callback_type;

#ifdef USE_MYSQL
	callback_type = CALLBACK_MYSQL;
	msg_verbose = 0;
#else
#ifdef USE_SQLITE
	callback_type = CALLBACK_SQLITE;
#else
	callback_type = CALLBACK_CONSOLE;
	//msg_verbose = 1;
#endif
#endif
#ifdef USE_AUTOTIME
	auto_timestamp = 1;
#else
	auto_timestamp = 0;
#endif

	memset(&last_burst, 0, sizeof(last_burst));

	session_init(start_sid, 0, gsmtap_target, callback_type);

	diag_set_filename(filename);
	diag_set_appid(appid);

	cell_init(start_cid, _s[0].timestamp.tv_sec, callback_type);
}

void diag_set_filename(char *filename)
{
	if (filename && (filename[0] != '-')) {
		session_from_filename(filename, &_s[0]);
		session_from_filename(filename, &_s[1]);
	}
}

void diag_set_appid(uint32_t appid)
{
	if (appid)
	{
		_s[0].appid = appid;
		_s[1].appid = appid;
	}
}

void diag_destroy(unsigned *last_sid, unsigned *last_cid)
{
	session_destroy(last_sid, last_cid);
}

inline
uint32_t get_fn(struct diag_packet *dp)
{
	return (dp->timestamp/204800)%GSM_MAX_FN;
}

inline
uint32_t get_epoch(uint8_t *qd_time)
{
	double qd_ts;

	qd_ts = qd_time[1];
	qd_ts += ((uint32_t)qd_time[2]) << 8;
	qd_ts += ((uint32_t)qd_time[3]) << 16;
	qd_ts += ((uint32_t)qd_time[4]) << 24;
	qd_ts *= 1.25*256.0/1000.0;

	/* Sanity check on timestamp (year > 2011) */
	if (qd_ts > 1000000000) {
		/* Adjust timestamp from GPS to UNIX */
		qd_ts += 315964800.0;
	} else {
		/* Use current time */
		int rv = -1;
		struct timeval tv;

		rv = gettimeofday(&tv, NULL);

		if (0 == rv) {
			return tv.tv_sec;
		}
	}

	return qd_ts;
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

	if (len < 16) {
		return 0;
	}

	payload_len = dp->len - 16;

	if (payload_len > len - 16) {
		return 0;
	}

	if (payload_len > sizeof(m->bb.data)) {
		return 0;
	}

	m = (struct radio_message *) malloc(sizeof(struct radio_message));

	memset(m, 0, sizeof(struct radio_message));

	m->rat = RAT_UMTS;

	m->bb.fn[0] = get_fn(dp);

	switch (dp->msg_type) {
	case 0: /* UL-CCCH */
		m->flags = MSG_FACCH;
		m->bb.arfcn[0] = ARFCN_UPLINK;
		break;
	case 1: /* UL-DCCH */
		m->flags = MSG_SDCCH;
		m->bb.arfcn[0] = ARFCN_UPLINK;
		break;
	case 2: /* DL-CCCH */
		m->flags = MSG_FACCH;
		m->bb.arfcn[0] = 0;
		break;
	case 3: /* DL-DCCH */
		m->flags = MSG_SDCCH;
		m->bb.arfcn[0] = 0;
		break;
	case 4: /* DL-BCCH */
		m->flags = MSG_BCCH;
		m->bb.arfcn[0] = 0;
		if (dp->data_len < payload_len) {
			payload_len = dp->data_len;
		}
		break;
	default:
		if (msg_verbose > 1) {
			printf("Discarding 3G message type=%d data=%s\n", dp->msg_type, osmo_hexdump_nospc(dp->data, payload_len));
		}
		free(m);
		return 0;
	}

	m->msg_len = payload_len;

	memcpy(m->bb.data, &dp->data[1], payload_len);

	return m;
}

struct radio_message * handle_4G(struct diag_packet *dp, unsigned len)
{
	unsigned payload_len;
	struct radio_message *m;
	uint8_t *data = NULL;

	if (len < 16) {
		return 0;
	}

	payload_len = dp->len - 16;

	if (payload_len > len - 16) {
		return 0;
	}

	if (payload_len > sizeof(m->bb.data)) {
		return 0;
	}

	data = &dp->data[1];

	m = (struct radio_message *) malloc(sizeof(struct radio_message));

	memset(m, 0, sizeof(struct radio_message));

	m->rat = RAT_LTE;

	m->bb.fn[0] = get_fn(dp);

	switch (dp->msg_protocol) {
	case 0xb0c0: // LTE RRC
		m->flags = MSG_BCCH; // it's not really BCCH, just indicates RRC
		m->bb.arfcn[0] = ((uint16_t) dp->data[4]) << 8 | dp->data[3];
		if (dp->data[0]) {
			// Uplink
			m->bb.arfcn[0] |= ARFCN_UPLINK;
		} else {
			// Downlink
		}

		/* Qualcomm to wireshark conversion */
		switch (dp->data[7]) {
		case 2:	// BCCH-DL-SCH
			m->chan_nr = 5;
			break;
		case 3: // MCCH
			m->chan_nr = 7;
			break;
		case 4: // PCCH
			m->chan_nr = 6;
			break;
		case 5: // DL-CCCH
			m->chan_nr = 0;
			break;
		case 6: // DL-DCCH
			m->chan_nr = 1;
			break;
		case 7: // UL-CCCH
			m->chan_nr = 2;
			break;
		case 8: // UL-DCCH
			m->chan_nr = 3;
			break;
		default:
			// Unhandled
			return NULL;
		}
		// verify len
		payload_len = ((uint16_t)dp->data[9]) << 8 | dp->data[8];
		if (payload_len > len - 15) {
			return 0;
		}
		if (payload_len > sizeof(m->bb.data)) {
			return 0;
		}
		data = &dp->data[10];
		break;
	case 0xb0e0: // LTE NAS ESM DL (protected)
	case 0xb0ea: // LTE NAS EMM DL (protected)
		m->flags = MSG_SDCCH | MSG_CIPHERED;
		m->bb.arfcn[0] = 0;
		break;
	case 0xb0e1: // LTE NAS ESM DL (protected)
	case 0xb0eb: // LTE NAS EMM UL (protected)
		m->flags = MSG_SDCCH | MSG_CIPHERED;
		m->bb.arfcn[0] = ARFCN_UPLINK;
		break;
	case 0xb0e2: // LTE NAS ESM DL
	case 0xb0ec: // LTE NAS EMM DL
		m->flags = MSG_SDCCH;
		m->bb.arfcn[0] = 0;
		break;
	case 0xb0e3: // LTE NAS ESM UL
	case 0xb0ed: // LTE NAS EMM UL
		m->flags = MSG_SDCCH;
		m->bb.arfcn[0] = ARFCN_UPLINK;
		break;
	case 0xb0f3: // EMM ciphering and integrity keys
	default:
		if (msg_verbose > 1) {
			printf("Discarding 4G message type=%d data=%s\n", dp->msg_type, osmo_hexdump_nospc(dp->data, payload_len));
		}
		free(m);
		return NULL;
	}

	m->msg_len = payload_len;

	memcpy(m->bb.data, data, payload_len);

	return m;
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
	case 0x00:
	case 0x05: // SDCCH UL RR
		return new_l3(dp->data, dtap_len, RAT_GSM, DOMAIN_CS, get_fn(dp), 1, MSG_SDCCH);
	case 0x04: // SACCH UL
		return new_l3(dp->data, dtap_len, RAT_GSM, DOMAIN_CS, get_fn(dp), 1, MSG_SACCH);
	case 0x80:
	case 0x85: /* SDCCH DL RR */
		return new_l3(dp->data, dtap_len, RAT_GSM, DOMAIN_CS, get_fn(dp), 0, MSG_SDCCH);
	case 0x81: /* BCCH */
		return new_l2(dp->data, dp->data_len, RAT_GSM, DOMAIN_CS, get_fn(dp), 0, MSG_BCCH);
	case 0x83: /* CCCH */
		return new_l2(dp->data, dp->data_len, RAT_GSM, DOMAIN_CS, get_fn(dp), 0, MSG_BCCH);
	case 0x84: /* SACCH DL RR */
		return new_l3(dp->data, dtap_len, RAT_GSM, DOMAIN_CS, get_fn(dp), 0, MSG_SACCH);
	default:
		print_common(dp, len);
	}

	return 0;
}

void handle_gsm_l1_txlev_timing_advance(struct diag_packet *dp, unsigned len)
{
	struct gsm_l1_txlev_timing_advance *decoded = (struct gsm_l1_txlev_timing_advance*) &dp->msg_type;

	decoded->arfcn_and_band = ntohs(decoded->arfcn_and_band);

	if (len-16-2 != 4) {
		if (msg_verbose > 1) {
			printf("x gsm_l1_txlev_timing_advance length incorrect\n");
		}
		return;
	}

	if (msg_verbose > 1) {
		//printf("x %s\n", osmo_hexdump_nospc(&dp->msg_type, len-16) );
		printf("x -> arfcn: %d\n", get_arfcn_from_arfcn_and_band(decoded->arfcn_and_band));
		printf("x -> band: %d\n", get_band_from_arfcn_and_band(decoded->arfcn_and_band));
		printf("x -> timing advance: %u\n", decoded->timing_advance);
		printf("x -> tx_power_level: %u\n", decoded->tx_power_level);
	}
}

void handle_gsm_l1_surround_cell_ba_list(struct diag_packet *dp, unsigned len)
{
	struct gsm_l1_surround_cell_ba_list *cl = (struct gsm_l1_surround_cell_ba_list *)&dp->msg_type;
	struct surrounding_cell *sc = cl->surr_cells;

	if (len-16-2 != sizeof(struct surrounding_cell)*cl->cell_count + 1) {
		if (msg_verbose > 1) {
			printf("x gsm_l1_surround_cell_ba_list length incorrect\n");
		}
		return;
	}

	if (msg_verbose > 1) {
		int i;

		for (i = 0; i < cl->cell_count; i++) {
			uint8_t band = get_band_from_arfcn_and_band(ntohs(sc[i].bcch_arfcn_and_band));
			if (band == 8 || band == 9) {
				printf("arfcn neighbor %u %d %u\n",
					get_arfcn_from_arfcn_and_band(ntohs(sc[i].bcch_arfcn_and_band)),
					sc[i].rx_power,
					sc[i].frame_number_offset
				);
			}
		}
	}
}

void handle_gsm_l1_burst_metrics(struct diag_packet *dp, unsigned len)
{
	struct gsm_l1_burst_metrics *dat = (struct gsm_l1_burst_metrics *)&dp->msg_type;
	int i;

	if (len-16-2 != sizeof(struct gsm_l1_burst_metrics)) {
		if (msg_verbose > 1) {
			printf("x gsm_l1_burst_metrics length incorrect\n");
		}
		return;
	}

	last_burst.fn = get_fn(dp);

	/* log burst information */
	for (i = 0; i < 4; i++) {
		uint8_t band = get_band_from_arfcn_and_band(ntohs(dat->metrics[i].arfcn_and_band));
		uint16_t n_arfcn = get_arfcn_from_arfcn_and_band(ntohs(dat->metrics[i].arfcn_and_band));
		if (band == 8 || band == 9) {
			last_burst.arfcn[i] = n_arfcn;
		} else {
			last_burst.arfcn[i] = last_burst.arfcn[0];
		}
	}

	if (msg_verbose > 1) {
		for (i = 0; i < 4; i++) {
			uint8_t band = get_band_from_arfcn_and_band(ntohs(dat->metrics[i].arfcn_and_band));
			if (band == 8 || band == 9) {
				printf("arfcn burst %u %d %u %u\n",
					get_arfcn_from_arfcn_and_band(ntohs(dat->metrics[i].arfcn_and_band)),
					dat->metrics[i].rx_power,
					dat->metrics[i].frame_number,
					get_fn(dp)
				);
			}
		}
	}
}

void handle_gsm_l1_neighbor_cell_auxiliary_measurments(struct diag_packet *dp, unsigned len)
{
	struct gsm_l1_neighbor_cell_auxiliary_measurments *cl = (struct gsm_l1_neighbor_cell_auxiliary_measurments *)&dp->msg_type;

	if (len-16-2 != sizeof(struct cell)*cl->cell_count + 1) {
		if (msg_verbose > 1) {
			printf("x gsm_l1_neighbor_cell_auxiliary_measurments length icorrect\n");
		}
		return;
	}

	if (msg_verbose > 1) {
		int i;

		for (i = 0; i < cl->cell_count; i++) {
			struct cell* c = cl->cells + i;
			uint8_t band = get_band_from_arfcn_and_band(ntohs(c[i].arfcn_and_band));

			if (band == 8 || band == 9) {
				printf("arfcn neighbor %u %d\n",
					get_arfcn_from_arfcn_and_band(ntohs(c[i].arfcn_and_band)),
					c[i].rx_power
				);
			}
		}
	}
}

void handle_gsm_monitor_bursts_v2(struct diag_packet *dp, unsigned len)
{
	struct gsm_monitor_bursts_v2 *cl = (struct gsm_monitor_bursts_v2 *)&dp->msg_type;

	if (len-16-2 != sizeof(struct monitor_record)*cl->number_of_records + 4) {
		if (msg_verbose > 1) {
			printf("x gsm_monitor_bursts_v2 length incorrect\n");
		}
		return;
	}

	if (msg_verbose > 1) {
		int i;

		for (i = 0; i < cl->number_of_records; i++) {
			struct monitor_record* c = cl->records + i;
			uint8_t band = get_band_from_arfcn_and_band(ntohs(c[i].arfcn_and_band));
			if (band == 8 || band == 9) {
				printf("arfcn monitor %u %d %d %u\n",
					get_arfcn_from_arfcn_and_band(ntohs(c[i].arfcn_and_band)),
					c[i].rx_power,
					c[i].frame_number,
					get_fn(dp)
				);
			}
		}
	}
}

void handle_gprs_grr_cell_reselection_measurements(struct diag_packet *dp, unsigned len)
{
	struct gprs_grr_cell_reselection_measurements *cl = (struct gprs_grr_cell_reselection_measurements *)&dp->msg_type;

	//printf("num %d len: %d, shoudl be %d\n", cl->neighboring_6_strongest_cells_count, len-16-2, sizeof(struct neighbor)*cl->neighboring_6_strongest_cells_count + 26);
	//assert(len-16-2 == sizeof(struct neighbor)*cl->neighboring_6_strongest_cells_count + 26);
	if (len-16-2 != sizeof(struct gprs_grr_cell_reselection_measurements)) {
		if (msg_verbose > 1) {
			printf("x gprs_grr_cell_reselection_measurements length incorrect\n");
		}
		return;
	}

	if (msg_verbose > 1) {
		int i;

		printf("x gprs_grr_cell_reselection_measurements\n");

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
}

void handle_sacch_report(struct diag_packet *dp, unsigned len)
{
	uint16_t b_arfcn = (uint16_t)(dp->msg_type) << 8 | dp->msg_subtype;
	uint16_t old_arfcn = _s[0].arfcn;

	_s[1].arfcn = _s[0].arfcn = get_arfcn_from_arfcn_and_band(b_arfcn);

	if (old_arfcn != _s[0].arfcn) {
		printf("SACCH report old=%d new=%d\n", old_arfcn, _s[0].arfcn);
	}
}

void handle_diag(uint8_t *msg, unsigned len)
{
	struct diag_packet *dp = (struct diag_packet *) msg;
	struct radio_message *m = NULL;

	if (dp->msg_class != 0x0010) {
		if (dp->msg_class == 0x001d && len > 9) {
			_s[0].timestamp.tv_sec = get_epoch(&msg[3]);
			_s[1].timestamp = _s[0].timestamp;
		}
		if (msg_verbose > 1) {
			fprintf(stderr, "Class %04x is not supported\n", dp->msg_class);
		}
		return;
	}

	/* Avoid short messages */
	if (len < 16)
		return;

	now = get_epoch(&dp->timestamp);
	cell_dump(now, 0, 0);

	switch(dp->msg_protocol) {
	case 0x5071:
		if (msg_verbose > 1) {
			fprintf(stderr, "handle_gsm_l1_surround_cell_ba_list\n");
		}
		handle_gsm_l1_surround_cell_ba_list(dp, len);
		break;

	case 0x506C:
		if (msg_verbose > 1) {
			fprintf(stderr, "handle_gsm_l1_burst_metrics\n");
		}
		handle_gsm_l1_burst_metrics(dp, len);
		break;

	case 0x5076:
		if (msg_verbose > 1) {
			fprintf(stderr, "handle_gsm_l1_txlev_timing_advance\n");
		}
		handle_gsm_l1_txlev_timing_advance(dp, len);
		break;

	case 0x507A:
		// GSM L1 Serving Auxiliary Measurments
		// not really interesting
		break;

	case 0x507B:
		if (msg_verbose > 1) {
			fprintf(stderr, "handle_gsm_l1_neighbor_cell_auxiliary_measurments\n");
		}
		handle_gsm_l1_neighbor_cell_auxiliary_measurments(dp,len);
		break;

	case 0x5082:
		if (msg_verbose > 1) {
			fprintf(stderr, "handle_gsm_monitor_bursts_v2\n");
		}
		handle_gsm_monitor_bursts_v2(dp, len);
		break;

	case 0x513A:
		if (msg_verbose > 1) {
			fprintf(stderr, "handle_sacch_report\n");
		}
		handle_sacch_report(dp, len);
		break;

	case 0x51FC:
		if (msg_verbose > 1) {
			fprintf(stderr, "handle_gprs_grr_cell_reselection_measurements\n");
		}
		handle_gprs_grr_cell_reselection_measurements(dp, len);
		break;

	case 0x412f: // 3G RRC
		if (msg_verbose > 1) {
			fprintf(stderr, "-> Handling 3G\n");
		}
		m = handle_3G(dp, len);
		break;

	case 0x512f: // GSM RR
		if (msg_verbose > 1) {
			fprintf(stderr, "Handling GSM RR\n");
		}
		m = handle_bcch_and_rr(dp, len);
		break;

	case 0x5230: // GPRS GMM (doubled msg)
		if (msg_verbose > 1) {
			fprintf(stderr, "-> Not handling GPRS GMM\n");
		}
		break;

	case 0x713a: // DTAP (2G, 3G)
		if (msg_verbose > 1) {
			fprintf(stderr, "-> Handling NAS\n");
		}
		m = handle_nas(dp, len);
		break;

	case 0xb0c0: // LTE RRC
	case 0xb0e0: // LTE NAS ESM DL (protected)
	case 0xb0e1: // LTE NAS ESM UL (protected)
	case 0xb0e2: // LTE NAS ESM DL
	case 0xb0e3: // LTE NAS ESM UL
	case 0xb0ea: // LTE NAS EMM DL (protected)
	case 0xb0eb: // LTE NAS EMM UL (protected)
	case 0xb0ec: // LTE NAS EMM DL
	case 0xb0ed: // LTE NAS EMM UL
		if (msg_verbose > 1) {
			fprintf(stderr, "-> Handling 4G\n");
		}
		m = handle_4G(dp, len);
		break;

	case 0xb0f3: // unknown LTE
		break;

	default:
		if (msg_verbose > 1) {
			fprintf(stderr, "-> Handling default case\n");
		}
		print_common(dp, len);
		break;
	}

	if (m) {
		/* Attach timestamp */
		m->timestamp.tv_sec = now;
		if (m->bb.fn[0] > last_burst.fn) {
			struct radio_message *z;
			/* Swap m */
			z = m;
			m = last_m;
			last_m = z;
		}
	} else {
		/* Deliver delayed message */
		m = last_m;
		last_m = NULL;
	}

	if (m) {
		/* Attach ARFCN */
		if (m->bb.fn[0] == last_burst.fn) {
			int i;
			for (i = 0; i < 4; i++) {
				m->bb.arfcn[i] = last_burst.arfcn[i];
			}
		}

		handle_radio_msg(_s, m);
	}
}
