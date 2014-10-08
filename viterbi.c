/* (C) 2011 by Sylvain Munaut <tnt@246tNt.com>
 *
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "viterbi.h"

#define CONV_N		2
#define CONV_K		5
#define CONV_N_STATES	(1<<(CONV_K-1))

#define MAX_AE			0x00ffffff


static const uint8_t conv_cch_next_output[CONV_N_STATES][2] = {
        {0, 3}, {3, 0}, {3, 0}, {0, 3},
        {0, 3}, {3, 0}, {3, 0}, {0, 3},
        {1, 2}, {2, 1}, {2, 1}, {1, 2},
        {1, 2}, {2, 1}, {2, 1}, {1, 2}
};

static const uint8_t conv_cch_next_state[CONV_N_STATES][2] = {
        {0, 8}, {0, 8}, {1, 9}, {1, 9},
        {2, 10}, {2, 10}, {3, 11}, {3, 11},
        {4, 12}, {4, 12}, {5, 13}, {5, 13},
        {6, 14}, {6, 14}, {7, 15}, {7, 15}
};

int conv_cch_encode(const uint8_t *in, uint8_t *out, unsigned size)
{
        unsigned int i, state = 0, o;

        for(i = 0; i < size; i++) {
                o = conv_cch_next_output[state][in[i]];
                state = conv_cch_next_state[state][in[i]];
                *out++ = !!(o & 2);
                *out++ = o & 1;
        }

	return 0;
}

int conv_cch_decode(int8_t *input, uint8_t *output, int n)
{
	int i, s, b;
	unsigned int ae[CONV_N_STATES];
	unsigned int ae_next[CONV_N_STATES];
	int8_t in_sym[CONV_N];
	int8_t ev_sym[CONV_N];
	int state_history[CONV_N_STATES][n];
	int min_ae;
	int min_state;
	int cur_state;

	/* Initial error (only state 0 is valid) */
	ae[0] = 0;
	for (i=1; i<CONV_N_STATES; i++) {
		ae[i] = MAX_AE;
	}

	/* Scan the treillis */
	for (i=0; i<n; i++) {
		/* Reset next accumulated error */
		for (s=0; s<CONV_N_STATES; s++) {
			ae_next[s] = MAX_AE;
		}

		/* Get input */
		in_sym[0] = input[2*i+0];
		in_sym[1] = input[2*i+1];

		/* Scan all states */
		for (s=0; s<CONV_N_STATES; s++)
		{
			/* Scan possible input bits */
			for (b=0; b<2; b++)
			{
				int nae;

				/* Next output and state */
				uint8_t out   = conv_cch_next_output[s][b];
				uint8_t state = conv_cch_next_state[s][b];

				/* Expand */
				ev_sym[0] = out & 2 ? -127 : 127;
				ev_sym[1] = out & 1 ? -127 : 127;

				/* New error for this path */
				#define DIFF(x,y) (((x-y)*(x-y)) >> 9)
				nae = ae[s] + \
					DIFF(ev_sym[0], in_sym[0]) + \
					DIFF(ev_sym[1], in_sym[1]);

				/* Is it survivor */
				if (ae_next[state] > nae) {
					ae_next[state] = nae;
					state_history[state][i+1] = s;
				}
			}
		}

		/* Copy accumulated error */
		memcpy(ae, ae_next, sizeof(int) * CONV_N_STATES);
	}

	/* Find state with least error */
	min_ae = MAX_AE;
	min_state = -1;

	for (s=0; s<CONV_N_STATES; s++)
	{
		if (ae[s] < min_ae) {
			min_ae = ae[s];
			min_state = s;
		}
	}

	/* Traceback */
	cur_state = min_state;
	for (i=n-1; i >= 0; i--)
	{
		min_state = cur_state;
		cur_state = state_history[cur_state][i+1];
		if (conv_cch_next_state[cur_state][0] == min_state)
			output[i] = 0;
		else
			output[i] = 1;
	}

	return 0;
}
