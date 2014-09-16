#include <assert.h>
#include <arpa/inet.h>

#include "session.h"
#include "cell_info.h"

#define MASK_NEIGH_2	0x01
#define MASK_NEIGH_2b	0x02
#define MASK_NEIGH_2t	0x04
#define MASK_NEIGH_2q	0x08
#define MASK_NEIGH_5	0x10
#define MASK_NEIGH_5b	0x20
#define MASK_NEIGH_5t	0x40
#define MASK_BCCH	0x80

#include <osmocom/gsm/rsl.h>
#include <osmocom/gsm/gsm48.h>
#include <osmocom/gsm/gsm48_ie.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>

static struct llist_head cell_list;

void cell_init()
{
	INIT_LLIST_HEAD(&cell_list);
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

void handle_lai(struct session_info *s, uint8_t *data, int cid)
{
	struct gsm48_loc_area_id *lai = (struct gsm48_loc_area_id *) data;

	s->mcc = get_mcc(lai->digits);
	s->mnc = get_mnc(lai->digits);
	s->lac = htons(lai->lac);

	if (cid >= 0) {
		s->cid = cid;
	}
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

void print_arfcn_list(struct gsm_sysinfo_freq *arfcn_list, char *name)
{
	int i;

	assert(arfcn_list != 0);
	assert(name != 0);

	printf(name);

	for (i=0; i<1024; i++) {
		if (arfcn_list[i].mask) {
			printf(" %d", i);
		}
	}

	printf("\n");
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

	/* Find old cell reference */
	ci = get_from_si(dtap->msg_type, dtap->data, data_len);
	if (ci) {
		/* Already seen */
		ci->si_counters[index]++;
		ci->last_seen = s->last_msg->timestamp;
		return;
	}

	/* Allocate new cell */
	ci = (struct cell_info *) malloc(sizeof(struct cell_info));

	memset(ci, 0, sizeof(*ci));

	switch (dtap->msg_type) {
	case GSM48_MT_RR_SYSINFO_1:
		SET_MSG_INFO(s, "SYSTEM INFO 1");
		si1 = (struct gsm48_system_information_type_1 *) ((uint8_t *)dtap - 1);
		gsm48_decode_freq_list(	ci->arfcn_list, si1->cell_channel_description,
					sizeof(si1->cell_channel_description), 0xff, MASK_BCCH);
		print_arfcn_list(ci->arfcn_list, "SI1");
		break;
	case GSM48_MT_RR_SYSINFO_2:
		SET_MSG_INFO(s, "SYSTEM INFO 2");
		si2 = (struct gsm48_system_information_type_2 *) ((uint8_t *)dtap - 1);
		gsm48_decode_freq_list(	ci->arfcn_list, si2->bcch_frequency_list,
					sizeof(si2->bcch_frequency_list), 0xff, MASK_NEIGH_2);
		print_arfcn_list(ci->arfcn_list, "SI2");
		break;
	case GSM48_MT_RR_SYSINFO_2bis:
		SET_MSG_INFO(s, "SYSTEM INFO 2bis");
		si2b = (struct gsm48_system_information_type_2bis *) ((uint8_t *)dtap - 1);
		gsm48_decode_freq_list(	ci->arfcn_list, si2b->bcch_frequency_list,
					sizeof(si2b->bcch_frequency_list), 0xff, MASK_NEIGH_2b);
		print_arfcn_list(ci->arfcn_list, "SI2b");
		break;
	case GSM48_MT_RR_SYSINFO_2ter:
		SET_MSG_INFO(s, "SYSTEM INFO 2ter");
		si2t = (struct gsm48_system_information_type_2ter *) ((uint8_t *)dtap - 1);
		gsm48_decode_freq_list(	ci->arfcn_list, si2t->ext_bcch_frequency_list,
					sizeof(si2t->ext_bcch_frequency_list), 0xff, MASK_NEIGH_2t);
		print_arfcn_list(ci->arfcn_list, "SI2t");
		break;
	case GSM48_MT_RR_SYSINFO_2quater:
		SET_MSG_INFO(s, "SYSTEM INFO 2quater");
		si2q = (struct gsm48_system_information_type_2quater *) ((uint8_t *)dtap - 1);
		break;
	case GSM48_MT_RR_SYSINFO_3:
		SET_MSG_INFO(s, "SYSTEM INFO 3");
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
		printf("SI3 %d-%d-%d-%d\n", ci->mcc, ci->mnc, ci->lac, ci->cid);
		break;
	case GSM48_MT_RR_SYSINFO_4:
		SET_MSG_INFO(s, "SYSTEM INFO 4");
		si4 = (struct gsm48_system_information_type_4 *) ((uint8_t *)dtap - 1);
		ci->mcc = get_mcc(si4->lai.digits);
		ci->mnc = get_mnc(si4->lai.digits);
		ci->lac = htons(si4->lai.lac);
		printf("SI4 %d-%d-%d\n", ci->mcc, ci->mnc, ci->lac);
		break;
	case GSM48_MT_RR_SYSINFO_5:
		SET_MSG_INFO(s, "SYS INFO 5");
		rand_check((uint8_t *)dtap, 18, &s->si5, s->cipher);
		si5 = (struct gsm48_system_information_type_5 *) dtap;
		gsm48_decode_freq_list(	ci->arfcn_list, si5->bcch_frequency_list,
					sizeof(si5->bcch_frequency_list), 0xff, MASK_NEIGH_5);
		print_arfcn_list(ci->arfcn_list, "SI5");
		break;
	case GSM48_MT_RR_SYSINFO_5bis:
		SET_MSG_INFO(s, "SYS INFO 5bis");
		rand_check((uint8_t *)dtap, 18, &s->si5bis, s->cipher);
		si5b = (struct gsm48_system_information_type_5bis *) dtap;
		gsm48_decode_freq_list(	ci->arfcn_list, si5b->bcch_frequency_list,
					sizeof(si5b->bcch_frequency_list), 0xff, MASK_NEIGH_5b);
		print_arfcn_list(ci->arfcn_list, "SI5b");
		break;
	case GSM48_MT_RR_SYSINFO_5ter:
		SET_MSG_INFO(s, "SYS INFO 5ter");
		rand_check((uint8_t *)dtap, 18, &s->si5ter, s->cipher);
		si5t = (struct gsm48_system_information_type_5ter *) dtap;
		gsm48_decode_freq_list(	ci->arfcn_list, si5t->bcch_frequency_list,
					sizeof(si5t->bcch_frequency_list), 0xff, MASK_NEIGH_5t);
		print_arfcn_list(ci->arfcn_list, "SI5t");
		break;
	case GSM48_MT_RR_SYSINFO_6:
		SET_MSG_INFO(s, "SYS INFO 6");
		rand_check((uint8_t *)dtap, 18, &s->si6, s->cipher);
		si6 = (struct gsm48_system_information_type_6 *) dtap;
		handle_lai(s, (uint8_t*)&si6->lai, htons(si6->cell_identity));
		ci->mcc = get_mcc(si6->lai.digits);
		ci->mnc = get_mnc(si6->lai.digits);
		ci->lac = htons(si6->lai.lac);
		ci->cid = htons(si6->cell_identity);
		s->cell_options = si6->cell_options;
		printf("SI6 %d-%d-%d-%d\n", ci->mcc, ci->mnc, ci->lac, ci->cid);
		break;
	case GSM48_MT_RR_SYSINFO_13:
		SET_MSG_INFO(s, "SYSTEM INFO 13");
		si13 = (struct gsm48_system_information_type_13 *) ((uint8_t *)dtap - 1);
		break;
	default:
		free(ci);
		return;
	}

	ci->first_seen = s->last_msg->timestamp;
	ci->last_seen = s->last_msg->timestamp;
	ci->si_counters[index]++;
	memcpy(ci->si_data[index], dtap->data, data_len);

	llist_add(&ci->entry, &cell_list);
}
