#include <stdio.h>
#include <assert.h>
#include <arpa/inet.h>

#include "session.h"
#include "cell_info.h"
#include "bit_func.h"

#define MASK_BCCH	0x01
#define MASK_NEIGH_2	0x02
#define MASK_NEIGH_2b	0x04
#define MASK_NEIGH_2t	0x08
#define MASK_NEIGH_5	0x10
#define MASK_NEIGH_5b	0x20
#define MASK_NEIGH_5t	0x40

#ifndef SQLITE_QUERY
#define SQLITE_QUERY 0
#endif

#include <osmocom/core/bitvec.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/gsm/rsl.h>
#include <osmocom/gsm/gsm48.h>
#include <osmocom/gsm/gsm48_ie.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>

static unsigned cell_info_id;
static struct llist_head cell_list;
static struct osmo_timer_list dump_timer;
static unsigned output_sqlite = 1;
static struct timeval periodic_ts;
static struct session_info s;
unsigned paging_count[3];
unsigned paging_imsi;
unsigned paging_tmsi;

enum si_index {
	SI1 = 0,
	SI2, SI2b, SI2t, SI2q,
	SI3,
	SI4,
	SI5, SI5b, SI5t,
	SI6,
	SI13,

	SI_MAX
};

const char * si_name[] = {
	"SI1",
	"SI2", "SI2b", "SI2t", "SI2q",
	"SI3",
	"SI4",
	"SI5", "SI5b", "SI5t",
	"SI6",
	"SI13"
};

struct cell_info {
	int id;
	int stored;
	struct timeval first_seen;
	struct timeval last_seen;
	/* DIAG or Android */
	int mcc;
	int mnc;
	int lac;
	int cid;
	int rat;
	int bcch_arfcn;
	int c1;
	int c2;
	int power_sum;
	int power_count;
	/* SI3 */
	int msc_ver;
	int combined;
	int agch_blocks;
	int pag_mframes;
	int t3212;
	int dtx;
	/* SI3 & SI4 */
	int cro;
	int temp_offset;
	int pen_time;
	int pwr_offset;
	int gprs;

	struct gsm_sysinfo_freq arfcn_list[1024];

	uint32_t si_counter[SI_MAX];
	uint8_t si_data[SI_MAX][20];
	uint16_t a_count[SI_MAX];

	struct llist_head entry;
};

void cell_make_sql(struct cell_info *ci, char *query, unsigned len, int sqlite);
void paging_make_sql(unsigned epoch_now, char *query, unsigned len, int sqlite);

static void paging_reset()
{
	paging_count[0] = 0;
	paging_count[1] = 0;
	paging_count[2] = 0;
	paging_imsi = 0;
	paging_tmsi = 0;
}

void cell_and_paging_dump(int force)
{
	char query[8192];
	struct cell_info *ci, *ci2;
	struct timeval ts_now;
	unsigned time_delta;

	gettimeofday(&ts_now, NULL);

	/* Elapsed time from measurement start */
	time_delta = ts_now.tv_sec - periodic_ts.tv_sec;

	if (!force && time_delta < 10)
		return;

	/* dump & delete cell_info */
	llist_for_each_entry_safe(ci, ci2, &cell_list, entry) {
		if (!ci->stored) {
			cell_make_sql(ci, query, sizeof(query), output_sqlite);
			if (s.sql_callback && strlen(query))
				(*s.sql_callback)(query);
			ci->stored = 1;
		}
		llist_del(&ci->entry);
		free(ci);
	}

	/* dump paging info */
	paging_make_sql(ts_now.tv_sec, query, sizeof(query), output_sqlite);
	if (s.sql_callback && strlen(query)) {
		(*s.sql_callback)(query);
	}

	/* reset counters */
	paging_reset();

	periodic_ts = ts_now;
}

static void console_callback(const char *sql)
{
	assert(sql != NULL);

	printf("SQL: %s\n", sql);
	fflush(stdout);
}

void cell_init(unsigned start_id, int callback)
{
	INIT_LLIST_HEAD(&cell_list);

	paging_reset();

	gettimeofday(&periodic_ts, NULL);

	cell_info_id = start_id;

	switch (callback) {
	case CALLBACK_NONE:
		break;
#ifdef USE_MYSQL
	case CALLBACK_MYSQL:
		output_sqlite = 0;
		mysql_api_init(&s);
		break;
#endif
#ifdef USE_SQLITE
	case CALLBACK_SQLITE:
		sqlite_api_init(&s);
		break;
#endif
	case CALLBACK_CONSOLE:
		s.sql_callback = console_callback;
		break;
	}
}

void cell_destroy()
{
	cell_and_paging_dump(1);
}

int get_mcc(uint8_t *digits)
{
	int mcc;

	mcc = (digits[0] & 0xf) * 100;
	mcc += (digits[0] >> 4) * 10;
	mcc += (digits[1] & 0xf) * 1;

	return mcc;
}

int get_mnc(uint8_t *digits)
{
	int mnc;

        if ((digits[1] >> 4) == 0xf) {
                mnc = (digits[2] & 0xf) * 10;
                mnc += (digits[2] >> 4) * 1;
        } else {
                mnc = (digits[2] & 0xf) * 100;
                mnc += (digits[2] >> 4) * 10;
                mnc += (digits[1] >> 4) * 1;
        }

	return mnc;
}

int si_index(uint8_t msg_type)
{

	switch (msg_type) {
	case GSM48_MT_RR_SYSINFO_1:
		return SI1;
	case GSM48_MT_RR_SYSINFO_2:
		return SI2;
	case GSM48_MT_RR_SYSINFO_2bis:
		return SI2b;
	case GSM48_MT_RR_SYSINFO_2ter:
		return SI2t;
	case GSM48_MT_RR_SYSINFO_2quater:
		return SI2q;
	case GSM48_MT_RR_SYSINFO_3:
		return SI3;
	case GSM48_MT_RR_SYSINFO_4:
		return SI4;
	case GSM48_MT_RR_SYSINFO_5:
		return SI5;
	case GSM48_MT_RR_SYSINFO_5bis:
		return SI5b;
	case GSM48_MT_RR_SYSINFO_5ter:
		return SI5t;
	case GSM48_MT_RR_SYSINFO_6:
		return SI6;
	case GSM48_MT_RR_SYSINFO_13:
		return SI13;
	}

	return -1;
}

int si_mask(enum si_index index)
{
	switch (index) {
	case SI1:
		return MASK_BCCH;
	case SI2:
		return MASK_NEIGH_2;
	case SI2b:
		return MASK_NEIGH_2b;
	case SI2t:
		return MASK_NEIGH_2t;
	case SI5:
		return MASK_NEIGH_5;
	case SI5b:
		return MASK_NEIGH_5b;
	case SI5t:
		return MASK_NEIGH_5t;
	}

	return 0;
}

struct cell_info * get_from_si(uint8_t msg_type, uint8_t *data, uint8_t len)
{
	struct cell_info *ci = NULL;
	int index;

	assert(data != NULL);
	assert(len < 21);

	index = si_index(msg_type);
	if (index < 0) {
		return 0;
	}

	llist_for_each_entry(ci, &cell_list, entry) {
		if (!memcmp(ci->si_data[index], data, len)) {
			return ci;
		}
	}

	return 0;
}

struct cell_info * get_from_cid(struct session_info *s)
{
	struct cell_info *ci;

	assert(s != NULL);

	// in RAM storage
	llist_for_each_entry(ci, &cell_list, entry) {
		if (ci->mcc != s->mcc)
			continue;
		if (ci->mnc != s->mnc)
			continue;
		if (ci->lac != s->lac)
			continue;
		if (ci->cid != s->cid)
			continue;

		return ci;
	}

	return ci;
}

uint16_t arfcn_count(struct cell_info *ci, enum si_index index)
{
	int i;
	uint16_t count = 0;
	uint8_t mask;

	assert(ci != 0);
	assert(index >= 0);
	assert(index < SI_MAX);

	mask = si_mask(index);

	if (!mask) {
		return count;
	}

	if (ci->si_counter[index] == 0) {
		return count;
	}

	for (i=0; i<1024; i++) {
		if (ci->arfcn_list[i].mask & mask) {
			count++;
		}
	}

	return count;
}

/* code imported from Osmocom-BB sysinfo.c */
static int handle_si3_rest(struct cell_info *ci, uint8_t *si, uint8_t len)
{
	struct bitvec bv;

	memset(&bv, 0, sizeof(bv));
	bv.data_len = len;
	bv.data = si;

	/* Optional Selection Parameters */
	if (bitvec_get_bit_high(&bv) == H) {
		/* Ignore first bit */
		bitvec_get_uint(&bv, 1);
		ci->cro = bitvec_get_uint(&bv, 6);
		ci->temp_offset = bitvec_get_uint(&bv, 3);
		ci->pen_time = bitvec_get_uint(&bv, 5);
	}

	/* Optional Power Offset */
	if (bitvec_get_bit_high(&bv) == H) {
		ci->pwr_offset = bitvec_get_uint(&bv, 3);
	}

	/* System Onformation 2ter Indicator */
	if (bitvec_get_bit_high(&bv) == H);

	/* Early Classark Sending Control */
	if (bitvec_get_bit_high(&bv) == H);

	/* Scheduling if and where */
	if (bitvec_get_bit_high(&bv) == H) {
		bitvec_get_uint(&bv, 3);
	}

	/* GPRS Indicator */
	if (bitvec_get_bit_high(&bv) == H) {
		ci->gprs = 1;
	}

	return 0;
}

/* code imported from Osmocom-BB sysinfo.c */
static int handle_si4_rest(struct cell_info *ci, uint8_t *si, uint8_t len)
{
	struct bitvec bv;

	memset(&bv, 0, sizeof(bv));
	bv.data_len = len;
	bv.data = si;

	/* Optional Selection Parameters */
	if (bitvec_get_bit_high(&bv) == H) {
		bitvec_get_uint(&bv, 1);
		ci->cro = bitvec_get_uint(&bv, 6);
		ci->temp_offset = bitvec_get_uint(&bv, 3);
		ci->pen_time = bitvec_get_uint(&bv, 5);
	}

	/* Optional Power Offset */
	if (bitvec_get_bit_high(&bv) == H) {
		ci->pwr_offset = bitvec_get_uint(&bv, 3);
	}

	/* GPRS Indicator */
	if (bitvec_get_bit_high(&bv) == H) {
		ci->gprs = 1;
	}

	return 0;
}

void handle_si4_data(struct cell_info *ci, uint8_t *data, unsigned len)
{
	uint8_t offset = 0;
	struct gsm48_chan_desc *cd;

	assert(ci != NULL);
	assert(data != NULL);
	assert(len > 0);

	/* Check if CBCH description is present */
	if (data[offset++] != GSM48_IE_CBCH_CHAN_DESC)
		goto check_si4_padding;

	/* CBCH channel info */
	cd = (struct gsm48_chan_desc *) &data[offset];

	/* Jump after descriptor */
	offset += 3;

	assert(offset < len);

	/* Check if CBCH is hopping */
	if (cd->h0.h) {
		/* Check for mobile allocation IE */
		if (data[offset++] == GSM48_IE_CBCH_MOB_AL) {
			/* Skip specified length */
			offset += data[offset] + 1;
		}
	}

check_si4_padding:
	if (data[offset] == 0x2b) {
		return;
	}

	assert(offset < len);

	/* Rest octets present */
	handle_si4_rest(ci, data, len - offset);
}

void handle_sysinfo(struct session_info *s, struct gsm48_hdr *dtap, unsigned len, uint32_t fn)
{
	struct gsm48_system_information_type_1 *si1;
	struct gsm48_system_information_type_2 *si2;
	struct gsm48_system_information_type_2bis *si2b;
	struct gsm48_system_information_type_2ter *si2t;
	struct gsm48_system_information_type_2quater *si2q;
	struct gsm48_system_information_type_3 *si3;
	struct gsm48_system_information_type_4 *si4;
	struct gsm48_system_information_type_5 *si5;
	struct gsm48_system_information_type_5bis *si5b;
	struct gsm48_system_information_type_5ter *si5t;
	struct gsm48_system_information_type_6 *si6;
	struct gsm48_system_information_type_13 *si13;

	struct cell_info *ci = NULL;

	unsigned data_len;
	uint16_t mcc;
	uint16_t mnc;
	uint16_t lac;
	uint16_t cid;
	int index;
	int append = 1;

	assert(s != NULL);
	assert(dtap != NULL);
	assert(len > 3);

	index = si_index(dtap->msg_type);
	if (index < 0) {
		/* Not to be parsed */
		return;
	}

	data_len = len - sizeof(struct gsm48_hdr);

	assert(data_len <= 20);

	/* Find cell in list */
	ci = get_from_si(dtap->msg_type, dtap->data, data_len);
	if (ci) {
		/* Found reference */
		append = 0;
		ci->stored = 0;
	} else {
		/* Allocate new cell */
		ci = (struct cell_info *) malloc(sizeof(struct cell_info));
		memset(ci, 0, sizeof(*ci));
	}

	switch (dtap->msg_type) {
	case GSM48_MT_RR_SYSINFO_1:
		if (!append)
			break;
		si1 = (struct gsm48_system_information_type_1 *) ((uint8_t *)dtap - 1);
		gsm48_decode_freq_list(	ci->arfcn_list, si1->cell_channel_description,
					sizeof(si1->cell_channel_description), 0xff, MASK_BCCH);
		break;
	case GSM48_MT_RR_SYSINFO_2:
		if (!append)
			break;
		si2 = (struct gsm48_system_information_type_2 *) ((uint8_t *)dtap - 1);
		gsm48_decode_freq_list(	ci->arfcn_list, si2->bcch_frequency_list,
					sizeof(si2->bcch_frequency_list), 0xff, MASK_NEIGH_2);
		break;
	case GSM48_MT_RR_SYSINFO_2bis:
		if (!append)
			break;
		si2b = (struct gsm48_system_information_type_2bis *) ((uint8_t *)dtap - 1);
		gsm48_decode_freq_list(	ci->arfcn_list, si2b->bcch_frequency_list,
					sizeof(si2b->bcch_frequency_list), 0xff, MASK_NEIGH_2b);
		break;
	case GSM48_MT_RR_SYSINFO_2ter:
		if (!append)
			break;
		si2t = (struct gsm48_system_information_type_2ter *) ((uint8_t *)dtap - 1);
		gsm48_decode_freq_list(	ci->arfcn_list, si2t->ext_bcch_frequency_list,
					sizeof(si2t->ext_bcch_frequency_list), 0xff, MASK_NEIGH_2t);
		break;
	case GSM48_MT_RR_SYSINFO_2quater:
		if (!append)
			break;
		si2q = (struct gsm48_system_information_type_2quater *) ((uint8_t *)dtap - 1);
		break;
	case GSM48_MT_RR_SYSINFO_3:
		if (!append)
			break;
		si3 = (struct gsm48_system_information_type_3 *) ((uint8_t *)dtap - 1);
		ci->mcc = get_mcc(si3->lai.digits);
		ci->mnc = get_mnc(si3->lai.digits);
		ci->lac = htons(si3->lai.lac);
		ci->cid = htons(si3->cell_identity);
		if (si3->control_channel_desc.ccch_conf == RSL_BCCH_CCCH_CONF_1_C) {
			ci->combined = 1;
		} else {
			ci->combined = 0;
		}
		ci->t3212 = si3->control_channel_desc.t3212;
		ci->agch_blocks = si3->control_channel_desc.bs_ag_blks_res;
		ci->pag_mframes = si3->control_channel_desc.bs_pa_mfrms;
		if (si3->rest_octets[0] != 0x2b) {
			handle_si3_rest(ci, si3->rest_octets, len - sizeof(*si3));
		}
		break;
	case GSM48_MT_RR_SYSINFO_4:
		if (!append)
			break;
		si4 = (struct gsm48_system_information_type_4 *) ((uint8_t *)dtap - 1);
		ci->mcc = get_mcc(si4->lai.digits);
		ci->mnc = get_mnc(si4->lai.digits);
		ci->lac = htons(si4->lai.lac);
		handle_si4_data(ci, si4->data, len - sizeof(*si4));
		break;
	case GSM48_MT_RR_SYSINFO_5:
		if (s->ci) {
			if (append)
				free(ci);
			ci = s->ci;
			append = 0;
		} else {
			s->ci = ci;
		}
		si5 = (struct gsm48_system_information_type_5 *) dtap;
		gsm48_decode_freq_list(	ci->arfcn_list, si5->bcch_frequency_list,
					sizeof(si5->bcch_frequency_list), 0xff, MASK_NEIGH_5);
		break;
	case GSM48_MT_RR_SYSINFO_5bis:
		if (s->ci) {
			if (append)
				free(ci);
			ci = s->ci;
			append = 0;
		} else {
			s->ci = ci;
		}
		si5b = (struct gsm48_system_information_type_5bis *) dtap;
		gsm48_decode_freq_list(	ci->arfcn_list, si5b->bcch_frequency_list,
					sizeof(si5b->bcch_frequency_list), 0xff, MASK_NEIGH_5b);
		break;
	case GSM48_MT_RR_SYSINFO_5ter:
		if (s->ci) {
			if (append)
				free(ci);
			ci = s->ci;
			append = 0;
		} else {
			s->ci = ci;
		}
		si5t = (struct gsm48_system_information_type_5ter *) dtap;
		gsm48_decode_freq_list(	ci->arfcn_list, si5t->bcch_frequency_list,
					sizeof(si5t->bcch_frequency_list), 0xff, MASK_NEIGH_5t);
		break;
	case GSM48_MT_RR_SYSINFO_6:
		if (s->ci) {
			if (append)
				free(ci);
			ci = s->ci;
			append = 0;
		} else {
			s->ci = ci;
		}
		si6 = (struct gsm48_system_information_type_6 *) dtap;
		ci->mcc = get_mcc(si6->lai.digits);
		ci->mnc = get_mnc(si6->lai.digits);
		ci->lac = htons(si6->lai.lac);
		ci->cid = htons(si6->cell_identity);
		break;
	case GSM48_MT_RR_SYSINFO_13:
		si13 = (struct gsm48_system_information_type_13 *) ((uint8_t *)dtap - 1);
		break;
	default:
		printf("<error>\n");
		free(ci);
		return;
	}

	/* Fill or update structure fields */
	ci->last_seen = s->last_msg->timestamp;
	ci->bcch_arfcn = s->last_msg->bb.arfcn[0];
	ci->si_counter[index]++;
	ci->a_count[index] = arfcn_count(ci, index);
	memcpy(ci->si_data[index], dtap->data, data_len);

	/* Append to cell list */
	if (append) {
		ci->first_seen = s->last_msg->timestamp;
		ci->id = cell_info_id++;
		llist_add(&ci->entry, &cell_list);
	}
}

void paging_inc(int pag_type, uint8_t mi_type)
{
	assert(pag_type < 4);

	if (pag_type > 0) {
		paging_count[pag_type - 1]++;
	}

	switch (mi_type) {
	case GSM_MI_TYPE_IMSI:
		paging_imsi++;
		break;
	case GSM_MI_TYPE_TMSI:
		paging_tmsi++;
		break;
	}
}

void handle_paging1(struct gsm48_hdr *dtap, unsigned len)
{
	struct gsm48_paging1 *pag;
	int len1, mi_type, tag;

	if (len < sizeof(*pag))
		return;

	pag = (struct gsm48_paging1 *) dtap;

	len1 = pag->data[0];
	mi_type = pag->data[1] & GSM_MI_TYPE_MASK;

	paging_inc(1, mi_type);

	if (len < sizeof(*pag) + 2 + len1 + 3)
		return;

	tag = pag->data[2 + len1 + 0];
	mi_type = pag->data[2 + len1 + 2] & GSM_MI_TYPE_MASK;
	if (tag != GSM48_IE_MOBILE_ID)
		return;

	paging_inc(0, mi_type);
}

void handle_paging2(struct gsm48_hdr *dtap, unsigned len)
{
	struct gsm48_paging2 *pag;
	int tag, mi_type;

	if (len < sizeof(*pag))
		return;

	pag = (struct gsm48_paging2 *) dtap; 

	paging_inc(2, GSM_MI_TYPE_TMSI);
	paging_inc(0, GSM_MI_TYPE_TMSI);

	/* no optional element */
	if (len < sizeof(*pag) + 3)
		return;

	tag = pag->data[0];
	mi_type = pag->data[2] & GSM_MI_TYPE_MASK;

	if (tag != GSM48_IE_MOBILE_ID)
		return;

	paging_inc(0, mi_type);
}

void handle_paging3(struct gsm48_hdr *dtap, unsigned len)
{
	paging_inc(3, GSM_MI_TYPE_TMSI);
	paging_inc(0, GSM_MI_TYPE_TMSI);
	paging_inc(0, GSM_MI_TYPE_TMSI);
	paging_inc(0, GSM_MI_TYPE_TMSI);
}

void append_arfcn_list(struct cell_info *ci, enum si_index index, char *query, unsigned len)
{
	unsigned offset;
	uint8_t mask;
	int i;

	assert(ci != NULL);
	assert(query != NULL);
	assert(index >= 0);
	assert(index < SI_MAX);
	assert(len > 0);

	/* Sanity checks */
	mask = si_mask(index);
	if (!mask) {
		return;
	}
	if (ci->si_counter[index] == 0) {
		return;
	}
	if (ci->a_count[index] == 0) {
		return;
	}

	snprintf(query, len, "INSERT INTO arfcn_list (id, source, arfcn) VALUES ");

	for (i = 0; i < 1024; i++) {
		if (ci->arfcn_list[i].mask & mask) {
			offset = strlen(query);
			snprintf(&query[offset], len-offset, "(%d,'%s',%d),", ci->id, si_name[index], i); 
		}
	}

	offset = strlen(query);

	assert(offset > 0);

	snprintf(&query[offset-1], len-offset+1, ";");
}

void cell_make_sql(struct cell_info *ci, char *query, unsigned len, int sqlite)
{
	char first_ts[40];
	char last_ts[40];
	char *si_hex[SI_MAX];
	unsigned offset;
	int i;

	/* Format timestamps according to db */
	if (sqlite) {
		snprintf(first_ts, sizeof(first_ts), "datetime(%lu, 'unixepoch')", ci->first_seen.tv_sec);
		snprintf(last_ts, sizeof(last_ts), "datetime(%lu, 'unixepoch')", ci->last_seen.tv_sec);
	} else {
		snprintf(first_ts, sizeof(first_ts), "FROM_UNIXTIME(%lu)", ci->first_seen.tv_sec);
		snprintf(last_ts, sizeof(last_ts), "FROM_UNIXTIME(%lu)", ci->last_seen.tv_sec);
	}

	/* Hex strings for each SI message */
	for (i = 0; i < SI_MAX; i++) {
		if (ci->si_counter[i]) {
			si_hex[i] = strescape_or_null(osmo_hexdump_nospc(ci->si_data[i], 20));
		} else {
			si_hex[i] = strescape_or_null(NULL);
		}
	}

	snprintf(query, len, "INSERT INTO cell_info ("
		"id,first_seen,last_seen,mcc,mnc,lac,cid,"
		"msc_ver,combined,agch_blocks,pag_mframes,t3212,dtx,"
		"cro,temp_offset,pen_time,pwr_offset,gprs,"
		"ba_len,neigh_2,neigh_2b,neigh_2t,"
		"neigh_2q,neigh_5,neigh_5b,neigh_5t,"
		"count_si1,count_si2,count_si2b,"
		"count_si2t,count_si2q,count_si3,"
		"count_si4,count_si5,count_si5b,"
		"count_si5t,count_si6,count_si13,"
		"si1,si2,si2b,si2t,si2q,si3,si4,si5,si5b,si5t,si6,si13) VALUES ("
		"%d,%s,%s,%d,%d,%d,%d,"
		"%d,%d,%d,%d,%d,%d,"
		"%d,%d,%d,%d,%d,"
		"%u,%u,%u,%u,"
		"%u,%u,%u,%u,"
		"%u,%u,%u,"
		"%u,%u,%u,"
		"%u,%u,%u,"
		"%u,%u,%u,"
		"%s,%s,%s,%s,"
		"%s,%s,%s,%s,"
		"%s,%s,%s,%s);",
		ci->id, first_ts, last_ts, ci->mcc, ci->mnc, ci->lac, ci->cid,
		ci->msc_ver, ci->combined, ci->agch_blocks, ci->pag_mframes, ci->t3212, ci->dtx,
		ci->cro, ci->temp_offset, ci->pen_time, ci->pwr_offset, ci->gprs,
		ci->a_count[SI1], ci->a_count[SI2], ci->a_count[SI2b], ci->a_count[SI2t],
		ci->a_count[SI2q], ci->a_count[SI5], ci->a_count[SI5b], ci->a_count[SI5t],
		ci->si_counter[SI1], ci->si_counter[SI2], ci->si_counter[SI2b],
		ci->si_counter[SI2t], ci->si_counter[SI2q], ci->si_counter[SI3],
		ci->si_counter[SI4], ci->si_counter[SI5], ci->si_counter[SI5b],
		ci->si_counter[SI5t], ci->si_counter[SI6], ci->si_counter[SI13],
		si_hex[SI1], si_hex[SI2], si_hex[SI2b], si_hex[SI2t],
		si_hex[SI2q], si_hex[SI3], si_hex[SI4], si_hex[SI5],
		si_hex[SI5b], si_hex[SI5t], si_hex[SI6], si_hex[SI13]
		);

	/* Free hex strings */
	for (i = 0; i < SI_MAX; i++) {
		if (si_hex[i]) {
			free(si_hex[i]);
		}
	}

	/* Append queries for ARFCN storage */
	for (i = 0; i < SI_MAX; i++) {
		offset = strlen(query);
		if (offset >= len) {
			break;
		}
		append_arfcn_list(ci, i, &query[offset], len-offset);
	}
}

void paging_make_sql(unsigned epoch_now, char *query, unsigned len, int sqlite)
{
	char paging_ts[40];
	float time_delta;

	/* Format timestamp according to db */
	if (sqlite) {
		snprintf(paging_ts, sizeof(paging_ts), "datetime(%lu, 'unixepoch')", epoch_now);
	} else {
		snprintf(paging_ts, sizeof(paging_ts), "FROM_UNIXTIME(%lu)", epoch_now);
	}

	time_delta = (float) (epoch_now-periodic_ts.tv_sec);

	if (time_delta > 0.0) {
		snprintf(query, len, "INSERT INTO paging_info VALUES (%s, %f, %f, %f, %f, %f);\n",
				paging_ts,
				(float)paging_count[0]/time_delta,
				(float)paging_count[1]/time_delta,
				(float)paging_count[2]/time_delta,
				(float)paging_imsi/time_delta,
				(float)paging_tmsi/time_delta);
	} else {
		query[0] = 0;
	}
}
