#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "diag_input.h"
#include "bit_func.h"
#include "assert.h"
#include <osmocom/core/utils.h>

int main(int argc, char *argv[])
{
	uint8_t msg[4096]; 
	int len = 0;
	char diag_hex[4096];
	char *ptr = NULL;
	unsigned unused1, unused2;

	if (argc < 3) {
		printf("Not enough arguments\n");
		printf("Usage: %s <session_info id> <cell_info id>\n", argv[0]);
		fflush(stdout);
		return -1;
	}

	diag_init(atoi(argv[1]), atoi(argv[2]), NULL, NULL);

	printf("PARSER_OK\n");
	fflush(stdout);

	for (;;) {
		/* Get one line from stdin */
		ptr = fgets(diag_hex, sizeof(diag_hex), stdin);
		if (!ptr) {
			break;
		}

		/* Skip empty lines */
		len = strlen(diag_hex);
		if (len == 0 || (diag_hex[0] == '\n')) {
			continue;
		}

		/* Cut trailing \n */
		if (diag_hex[len-1] == '\r') {
			len--;
		}
		if (diag_hex[len-1] == '\n') {
			len--;
		}
		diag_hex[len] = 0;

		/* Prepare data buffer */
		memset(msg, 0x2b, sizeof(msg));

		/* Parse hex into binary */
		len = osmo_hexparse(diag_hex, msg, sizeof(msg));
		assert(len >= 0);

		if (len > 0) {
			handle_diag(msg, len);
		}
	}

	diag_destroy(&unused1, &unused2);

	return 0;
}

