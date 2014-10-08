#include <stdio.h>

#include "chan_detect.h"

uint8_t bcch_detect(uint32_t fn, uint8_t combined, uint8_t *subchan)
{
	uint8_t type = UNKNOWN;
	uint8_t fn_mod = fn % 51;
	uint8_t sacch_sub = ((fn % 102) >= 51) ? 2 : 0;
	*subchan = 0;

	switch (fn_mod) {

	/* FCCH */
	case 0:
	case 10:
	case 20:
	case 30:
	case 40:
		break;

	/* SCH */
	case 1:
	case 11:
	case 21:
	case 31:
	case 41:
		break;

	/* IDLE */
	case 50:
		break;

	/* BCCH */
	case 2:
	case 6:
		type = BCCH;
		break;

	/* CCCH */
	case 12:
	case 16:
		type = CCCH;
		break;

	/* CCCH/SDCCH */
	case 22:
		type = SDCCH;
		*subchan = 0;
		break;
	case 26:
		type = SDCCH;
		*subchan = 1;
		break;
	case 32:
		type = SDCCH;
		*subchan = 2;
		break;
	case 36:
		type = SDCCH;
		*subchan = 3;
		break;

	/* CCCH/SACCH */
	case 42:
		type = SACCH;
		*subchan = 0 + sacch_sub;
		break;
	case 46:
		type = SACCH;
		*subchan = 1 + sacch_sub;
		break;

	/* burst in the middle */
	default:
		break;
	}

	if (!combined) {
		if ((type == SDCCH) || (type == SACCH))
			type = CCCH;
	}

	return type;
}

uint8_t xcch_detect(uint32_t fn, uint8_t *subchan)
{
	uint8_t type = UNKNOWN;
	uint8_t fn_mod = fn % 51;
	uint8_t msg_mod = fn_mod % 4;
	uint8_t sacch_sub = ((fn % 102) >= 51) ? 4 : 0;
	*subchan = 0;

	/* IDLE */
	if (fn_mod > 47)
		return type;

	/* burst in the middle */
	if (msg_mod)
		return type;
		
	/* XCCH */
	if (fn_mod < 32) {
		type = SDCCH;
		*subchan = fn_mod / 4;
	} else {
		type = SACCH;
		*subchan = (fn_mod - 32) / 4 + sacch_sub;
	}

	return type;
}

uint8_t chan_detect(uint32_t fn, uint8_t ts, uint8_t combined, uint8_t *subchan)
{
	uint8_t type;
	uint8_t sub;

	if (ts == 0) {
		type = bcch_detect(fn, combined, &sub);
	} else {
		type = xcch_detect(fn, &sub);
	}

	if (type & BCCH)
		fprintf(stderr, "BCCH");
	if (type & CCCH)
		fprintf(stderr, "CCCH");
	if (type & SDCCH)
		fprintf(stderr, "SDCCH");
	if (type & SACCH)
		fprintf(stderr, "SACCH");

	if (subchan)
		*subchan = sub;

	return type;
}
