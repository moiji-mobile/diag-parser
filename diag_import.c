#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "diag_input.h"
#include "bit_func.h"
#include <stdlib.h>

int main(int argc, char *argv[])
{
	uint8_t msg[4096]; 
	unsigned len = 0;

	if (argc < 3) {
		printf("Not enough arguments\n");
		printf("Usage: %s <session_info id> <cell_info id>\n", argv[0]);
		fflush(stdout);
		return -1;
	}

	diag_init(atoi(argv[1]), atoi(argv[2]));

	for (;;) {
		memset(msg, 0x2b, sizeof(msg));
		len = fread_unescape(stdin, msg, sizeof(msg));

		if (!len) {
			break;
		}

		handle_diag(msg, len);

		handle_periodic_task();
	}

	diag_destroy();

	return 0;
}

