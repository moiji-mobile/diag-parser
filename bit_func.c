#include <stdio.h>
#include <string.h>

#include "bit_func.h"

inline int not_zero(uint8_t *t, unsigned size)
{
	unsigned i;

	for (i=0; i<size; i++) {
		if (t[i])
			break;
	}

	if (i == size)
		return 0;
	else
		return 1;
}

inline void compress_lsb(const uint8_t *in, uint8_t *out, unsigned size)
{

	unsigned i, dbyte;
	uint8_t dbit;

	for (i=0; i<size; i++) {
		dbyte = i >> 3;
		dbit = 1 << (i & 7);

		if (in[i])
			out[dbyte] |= dbit;
		else
			out[dbyte] &= ~dbit;
	}
}

inline void compress_msb(const uint8_t *in, uint8_t *out, unsigned size)
{
	unsigned i, dbyte;
	uint8_t dbit;

	for (i=0; i<size; i++) {
		dbyte = i >> 3;
		dbit  = 1 << (7 - (i & 7));

		if (in[i])
			out[dbyte] |= dbit;
		else
			out[dbyte] &= ~dbit;
	}
}

inline void expand_lsb(const uint8_t *in, uint8_t *out, unsigned size)
{
	unsigned i, dbyte;
	uint8_t dbit;

	for (i=0; i<size; i++) {
		dbyte = i >> 3;
		dbit  = 1 << (i & 7);
		out[i] = !!(in[dbyte] & dbit);
	}
}

inline void expand_msb(const uint8_t *in, uint8_t *out, unsigned size)
{
	unsigned i, dbyte;
	uint8_t dbit;

	for (i=0; i<size; i++) {
		dbyte = i >> 3;
		dbit  = 1 << (7 - (i & 7));
		out[i] = !!(in[dbyte] & dbit);
	}
}

inline int hex_bin2str(const uint8_t *vec, char *str, unsigned len)
{
	int i;
	char hexchar[] = {'0', '1', '2', '3', '4', '5', '6', '7',
			  '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
	
	for (i=0;i<len;i++) {
		str[2*i+0] = hexchar[vec[i] >> 4];
		str[2*i+1] = hexchar[vec[i] & 0x0f];
	}

	return i;
}

inline int hex_str2bin(const char *str, uint8_t *vec, unsigned len)
{
	int i = 0;

	while (str[i] && (i / 2 < len)) {
		switch (str[i]) {
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			if (i & 1)
				vec[i/2] |= (str[i] - '0');
			else
				vec[i/2] = (str[i] - '0') << 4;
			break;
		case 'a':
		case 'b':
		case 'c':
		case 'd':
		case 'e':
		case 'f':
			if (i & 1)
				vec[i/2] |= (str[i] - 'a' + 10);
			else
				vec[i/2] = (str[i] - 'a' + 10) << 4;
			break;
		case 'A':
		case 'B':
		case 'C':
		case 'D':
		case 'E':
		case 'F':
			if (i & 1)
				vec[i/2] |= (str[i] - 'A' + 10);
			else
				vec[i/2] = (str[i] - 'A' + 10) << 4;
			break;
		default:
			return i/2;
		}

		i++;
	}

	return i/2;
}

inline int bcd2str(uint8_t *bcd, char *s, unsigned len, unsigned off)
{
	char code[] = {'0', '1', '2', '3', '4', '5', '6', '7',
			  '8', '9', '*', '*', '#', '*', '#'};
	unsigned i;
	uint8_t n;

	for (i=off; i<len; i++) {
		if (i & 1) {
			n = bcd[i/2] >> 4;
		} else {
			n = bcd[i/2] & 0xf;
		}

		if (n < 15) {
			*(s++) = code[n];
		} else {
			break;
		}
	}

	*s = 0;

	return i;
}

inline unsigned hamming_distance(uint8_t *v1, uint8_t *v2, unsigned len)
{
	unsigned i, diff = 0;

	for (i=0; i<len; i++) {
		diff += !!(v1[i]^v2[i]);
	}

	return diff;
}

unsigned fread_unescape(FILE *f, uint8_t *msg, unsigned len)
{
	unsigned i;
	int ret;

	for (i=0; i<len; i++) {
		ret = fread(&msg[i], 1, 1, f);
		if (!ret || msg[i] == 0x7e) {
			break;
		}
		
		/* unescape if needed */
		if (msg[i] == 0x7d) {
			ret = fread(&msg[i], 1, 1, f);
			if (!ret)
				break;
			msg[i] = (msg[i] & 0x0f) | 0x70;
		}
	}

	return i;
}

char * strescape_or_null(char *str)
{
	char *escaped;
	size_t len;

	if (!str || !str[0]) {
		return strdup("NULL");
	}

	len = strlen(str);

	escaped = malloc(len + 3);

	snprintf(escaped, len + 3, "'%s'", str);

	return escaped;
}
