#include "address.h"
#include "bit_func.h"
#include <string.h>
#include <assert.h>
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <stdio.h>

int handle_addr_national(uint8_t *data, unsigned digit_len, char *dest)
{
	assert(data != NULL);
	assert(dest != NULL);
	assert(digit_len > 0);

	/* Check first digit */
	if (data[0] & 0x0f) {
		/* Insert additional 0 */
		dest[0] = '0';
		dest++;
	}

	return bcd2str(data, dest, digit_len, 0);
}

int handle_addr_e164(uint8_t *data, unsigned digit_len, char *dest)
{
	assert(data != NULL);
	assert(dest != NULL);
	assert(digit_len > 0);

	/* Insert "+" before number */
	dest[0] = '+';

	/* remove leading 00, if present */
	if (data[0] == 0x00) {
		if (digit_len < 2) {
			return 0;
		}
		digit_len -= 2;
		data++;
	}

	return bcd2str(data, &dest[1], digit_len, 0);
}

void handle_address(uint8_t *data, unsigned len, char *dest, int digit_only)
{
	uint8_t ext;
	uint8_t ton;
	uint8_t npi;
	uint8_t digit_len;
	uint8_t ret;

	assert(data != NULL);
	assert(dest != NULL);

	/* Special case */
	if (len == 0) {
		snprintf(dest, 32, "<NO ADDRESS>");
		return;
	}

	/* Decode basic info */
	ext = (data[0] & 0x80);
	ton = (data[0] & 0x70) >> 4;
	npi = (data[0] & 0x0f);

	/* Check if extension is present */
	if (ext) {
		/* Not present */
		if (len == 1) {
			digit_len = 1;
		} else {
			digit_len = (len-1)*2;
		}
		data++;
	} else {
		/* Present */
		if (data[1] & 0x60) {
			/* Restricted number */
			strncpy(dest, "<hidden>", 32);
			return;
		}
		if (len == 2) {
			digit_len = 1;
		} else {
			digit_len = (len-2)*2;
		}
		data += 2;
	}
	if (digit_only)
		digit_len = len;

	assert(digit_len > 0);

	if (digit_len > 31) {
		digit_len = 31;
	}

	switch (ton) {
	case 2: /* National */
		switch (npi) {
		case 1: /* E.164 */
			ret = handle_addr_national(data, digit_len, dest);
			break;
		default:
			ret = bcd2str(data, dest, digit_len, 0);
		}
		break;
	case 1: /* International */
		switch (npi) {
		case 1: /* E.164 */
			ret = handle_addr_e164(data, digit_len, dest);
			break;
		default:
			ret = bcd2str(data, dest, digit_len, 0);
		} 
		break;
	case 5: /* Alphanumeric - GSM 7bit */
		ret = gsm_7bit_decode_n(dest, GSM48_MI_SIZE, data, (digit_len+1)/2);
		//printf("digit_len=%d string=%s\n", digit_len, dest);
		break;
	case 0: /* Unknown */
	case 3: /* Network specific */
	case 4: /* Subscriber number */
	case 6: /* Abbreviated number */
	case 7: /* Reserved value */
	default:
		switch (npi) {
		case 8: /* National */
			ret = handle_addr_national(data, digit_len, dest);
			break;
		case 0: /* Unknown */
		case 1: /* E.164 */
		case 3: /* Data numbering X.121 */
		case 4: /* Telex numbering F.69 */
		case 5: /* Private / SMSC specific */
		case 6: /* Land mobile E.212 / National */
		case 9: /* Private */
		case 10: /* Ermes numbering */
		case 13: /* Internet IP */
		case 15: /* Reserved value */
		default:
			ret = bcd2str(data, dest, digit_len, 0);
		} 
		break;
	}

	if (!dest[0] || !is_printable(dest, ret)) {
		snprintf(dest, GSM48_MI_SIZE, "<NON-PRINTABLE>");
	}
}
