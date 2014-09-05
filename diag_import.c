#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "diag_input.h"
#include "bit_func.h"

int main()
{
	uint8_t msg[4096]; 
	unsigned len = 0;

	diag_init();

	for (;;) {
		memset(msg, 0x2b, sizeof(msg));
		len = fread_unescape(stdin, msg, sizeof(msg));

		if (!len) {
			break;
		}

		handle_diag(msg, len);
	}

	diag_destroy();

	return 0;
}

