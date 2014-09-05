#include "address.h"
#include "bit_func.h"
#include <string.h>
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>

int handle_addr_national(uint8_t *data, unsigned digit_len, char *dest)
{
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
	/* Insert "+" before number */
	dest[0] = '+';

	/* remove leading 00, if present */
	if (data[0] == 0x00) {
		digit_len -= 2;
		data++;
	}

	return bcd2str(data, &dest[1], digit_len, 0);
}

void handle_address(uint8_t *data, unsigned len, char *dest, int digit_only)
{
	uint8_t ext = (data[0] & 0x80);
	uint8_t ton = (data[0] & 0x70) >> 4;
	uint8_t npi = (data[0] & 0x0f);
	uint8_t digit_len;

	/* check if extension is present */
	if (ext) {
		/* not present */
		data++;
		digit_len = (len-1)*2;
	} else {
		/* present */
		if (data[1] & 0x60) {
			/* restricted number */
			strcpy(dest, "<hidden>");
			return;
		}
		data += 2;
		digit_len = (len-2)*2;
	}
	if (digit_only)
		digit_len = len*2;

	switch (ton) {
	case 2: /* National */
		switch (npi) {
		case 1: /* E.164 */
			handle_addr_national(data, digit_len, dest);
		default:
			bcd2str(data, dest, digit_len, 0);
		}
		break;
	case 1: /* International */
		switch (npi) {
		case 1: /* E.164 */
			handle_addr_e164(data, digit_len, dest);
			break;
		default:
			bcd2str(data, dest, digit_len, 0);
		} 
		break;
	case 5: /* Alphanumeric - GSM 7bit */
		gsm_7bit_decode_n(dest, GSM48_MI_SIZE, data, (len*8)/7);
		break;
	case 0: /* Unknown */
	case 3: /* Network specific */
	case 4: /* Subscriber number */
	case 6: /* Abbreviated number */
	case 7: /* Reserved value */
	default:
		switch (npi) {
		case 8: /* National */
			handle_addr_national(data, digit_len, dest);
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
			bcd2str(data, dest, digit_len, 0);
		} 
		break;
	}
}
