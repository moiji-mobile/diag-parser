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
	FILE *infile = stdin;

	if (argc < 3 || argc > 4) {
		printf("Wrong number of arguments\n");
		printf("Usage: %s <session_info id> <cell_info id> [filename]\n", argv[0]);
		return -1;
	}

	if (argc == 4) {
		infile = fopen(argv[3], "rb");
		if (!infile) {
			printf("Cannot open input file: %s\n", argv[3]);
			return -1;
		}
		diag_init(atoi(argv[1]), atoi(argv[2]), argv[3]);
	} else {
		diag_init(atoi(argv[1]), atoi(argv[2]), NULL);
	}

	printf("PARSER_OK\n");
	fflush(stdout);

	for (;;) {
		memset(msg, 0x2b, sizeof(msg));
		len = fread_unescape(infile, msg, sizeof(msg));

		if (!len) {
			break;
		}

		handle_diag(msg, len);
	}

	diag_destroy();

	fclose(infile);

	return 0;
}

