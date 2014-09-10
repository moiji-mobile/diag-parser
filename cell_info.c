#include <assert.h>

#include "session.h"
#include "cell_info.h"

#define NEIGH_2		0x01
#define NEIGH_2b	0x02
#define NEIGH_2t	0x04
#define NEIGH_2q	0x08
#define NEIGH_5		0x10
#define NEIGH_5b	0x20
#define NEIGH_5t	0x40

#include <osmocom/gsm/rsl.h>
#include <osmocom/gsm/gsm48.h>
#include <osmocom/gsm/gsm48_ie.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>

struct llist_head cell_list;

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

void match_update_si(uint8_t msg_type, uint8_t *data, unsigned len)
{
	struct cell_info *ci;

	llist_for_each_entry(ci, &cell_list, entry) {
		switch (msg_type) {
		case GSM48_MT_RR_SYSINFO_1:
			if (!strncmp(data, ci->si1, len)) {
				return ci;
			}
			break;
		case GSM48_MT_RR_SYSINFO_2:
			if (!strncmp(data, ci->si2, len)) {
				return ci;
			}
			break;
		case GSM48_MT_RR_SYSINFO_3:
			if (!strncmp(data, ci->si3, len)) {
				return ci;
			}
			break;
		case GSM48_MT_RR_SYSINFO_4:
			if (!strncmp(data, ci->si4, len)) {
				return ci;
			}
			break;
		case GSM48_MT_RR_SYSINFO_5:
			if (!strncmp(data, ci->si5, len)) {
				return ci;
			}
			break;
		case GSM48_MT_RR_SYSINFO_6:
			if (!strncmp(data, ci->si6, len)) {
				return ci;
			}
			break;
		case GSM48_MT_RR_SYSINFO_13:
			if (!strncmp(data, ci->si13, len)) {
				return ci;
			}
			break;
		}
	}

	return 0;
}


struct cell_info * get_cell_info(struct session_info *s)
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

	// try to find it in db?

	// allocate new
	ci = (struct cell_info *) malloc(sizeof(struct cell_info));
	if (!ci) {
		return 0;
	}

	ci->mcc = s->mcc;
	ci->mnc = s->mnc;
	ci->lac = s->lac;
	ci->cid = s->cid;
	// set timestamp
	// copy BA from s?

	llist_add(&ci->entry, &cell_list);

	return ci;
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

	assert(s != NULL);
	assert(dtap != NULL);
	assert(len > 0);

	return;

	ci = get_cell_info(s);
	if (!ci) {
		return;
	}

	switch (dtap->msg_type) {
	case GSM48_MT_RR_SYSINFO_1:
		SET_MSG_INFO(s, "SYSTEM INFO 1");
		si1 = (struct gsm48_system_information_type_1 *) dtap;
		break;
	case GSM48_MT_RR_SYSINFO_2:
		SET_MSG_INFO(s, "SYSTEM INFO 2");
		si2 = (struct gsm48_system_information_type_2 *) dtap;
		break;
	case GSM48_MT_RR_SYSINFO_2bis:
		SET_MSG_INFO(s, "SYSTEM INFO 2bis");
		si2b = (struct gsm48_system_information_type_2bis *) dtap;
		break;
	case GSM48_MT_RR_SYSINFO_2ter:
		SET_MSG_INFO(s, "SYSTEM INFO 2ter");
		si2t = (struct gsm48_system_information_type_2ter *) dtap;
		break;
	case GSM48_MT_RR_SYSINFO_2quater:
		SET_MSG_INFO(s, "SYSTEM INFO 2quater");
		si2q = (struct gsm48_system_information_type_2quater *) dtap;
		break;
	case GSM48_MT_RR_SYSINFO_3:
		SET_MSG_INFO(s, "SYSTEM INFO 3");
		si3 = (struct gsm48_system_information_type_3 *) dtap;
		if (si3->control_channel_desc.ccch_conf == RSL_BCCH_CCCH_CONF_1_C) {
			ci->combined = 1;
		} else {
			ci->combined = 0;
		}
		break;
	case GSM48_MT_RR_SYSINFO_4:
		SET_MSG_INFO(s, "SYSTEM INFO 4");
		si4 = (struct gsm48_system_information_type_4 *) dtap;
		break;
	case GSM48_MT_RR_SYSINFO_5:
		SET_MSG_INFO(s, "SYS INFO 5");
		rand_check((uint8_t *)dtap, 18, &s->si5, s->cipher);
		si5 = (struct gsm48_system_information_type_5 *) dtap;
		gsm48_decode_freq_list(	ci->neigh_list, si5->bcch_frequency_list,
					sizeof(si5->bcch_frequency_list), 0xff, NEIGH_5);
		break;
	case GSM48_MT_RR_SYSINFO_5bis:
		SET_MSG_INFO(s, "SYS INFO 5bis");
		rand_check((uint8_t *)dtap, 18, &s->si5bis, s->cipher);
		si5b = (struct gsm48_system_information_type_5bis *) dtap;
		gsm48_decode_freq_list(	ci->neigh_list, si5b->bcch_frequency_list,
					sizeof(si5b->bcch_frequency_list), 0xff, NEIGH_5b);
		break;
	case GSM48_MT_RR_SYSINFO_5ter:
		SET_MSG_INFO(s, "SYS INFO 5ter");
		rand_check((uint8_t *)dtap, 18, &s->si5ter, s->cipher);
		si5t = (struct gsm48_system_information_type_5ter *) dtap;
		gsm48_decode_freq_list(	ci->neigh_list, si5t->bcch_frequency_list,
					sizeof(si5t->bcch_frequency_list), 0xff, NEIGH_5t);
		break;
	case GSM48_MT_RR_SYSINFO_6:
		SET_MSG_INFO(s, "SYS INFO 6");
		rand_check((uint8_t *)dtap, 18, &s->si6, s->cipher);
		si6 = (struct gsm48_system_information_type_6 *) dtap;
		handle_lai(s, (uint8_t*)&si6->lai, htons(si6->cell_identity));
		s->cell_options = si6->cell_options;
		break;
	case GSM48_MT_RR_SYSINFO_13:
		SET_MSG_INFO(s, "SYSTEM INFO 13");
		si13 = (struct gsm48_system_information_type_13 *) dtap;
		break;
	}
}

