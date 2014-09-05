#include <stdint.h>
#include <string.h>

void fill_punct_cs2(unsigned *pattern)
{
	int i,j,k;

	for (i=0, j=3, k=0; (i<588) && (j<147); i++) {
		/* puncture? */
		if (i == (4*j+3)) {
			/* update puncturing index*/
			switch (++j) {
			case 9:
			case 21:
			case 33:
			case 45:
			case 57:
			case 69:
			case 81:
			case 93:
			case 105:
			case 117:
			case 129:
			case 141:
				j++;
			}
		} else {
			pattern[k++] = i;
		}
	}
}

void fill_punct_cs3(unsigned *pattern)
{
	int i,j,k;

	for (i=0, j=2, k=0; j<112; i++) {
		/* puncture? */
		if (i == (6*j+3))
			continue;
		if (i == (6*j+5)) {
			/* update puncturing index*/
			j++;
		} else {
			pattern[k++] = i;
		}
	}
	while (k<456)
		pattern[k++] = i++;
}

void depunct(uint8_t *in, int8_t *out, unsigned size, unsigned *pattern)
{
	int i;
	memset(out, 0, size);
	for (i=0; i<456; i++) {
		out[pattern[i]] = in[i] ? -127 : 127;
	}
}

