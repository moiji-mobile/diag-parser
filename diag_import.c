#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <err.h>

#include "diag_input.h"
#include "bit_func.h"
#include <stdlib.h>

static void usage(const char *progname, const char *reason)
{
	printf("%s\n", reason);
	printf("Usage: %s [-s <id>] [-c <id>] <filename>\n", progname);
	printf("	-s <id>    - First session_info ID to be used for SQL\n");
	printf("	-c <id>    - First cell_info ID to be used for SQL\n");
	printf("	<filename> - Read DIAG data from <filename>\n");
	exit(1);
}

int main(int argc, char *argv[])
{
	uint8_t msg[4096]; 
	unsigned len = 0;
	FILE *infile = NULL;
	char *infile_name;
	int bflag, ch, fd;
	long sid = 0;
	long cid = 0;

	while ((ch = getopt(argc, argv, "s:c:")) != -1) {
		switch (ch) {
			case 's':
				sid = atol(optarg);
				break;
			case 'c':
				cid = atol(optarg);
				break;
			case '?':
			default:
				usage(argv[0], "Invalid arguments");
		}
	}

	argc -= optind;
	argv += optind;

	if (argc == 0)
	{
		errx(1, "Invalid arguments");
	}

	printf("PARSER_OK\n");
	fflush(stdout);

	while (argc > 0)
	{
		infile_name = strdup(argv[0]);

		if (strcmp(infile_name, "-") == 0)
		{
			infile = stdin;
		} else
		{
			infile = fopen(infile_name, "rb");
		}

		if (!infile)
		{
			err(1, "Cannot open input file: %s", infile_name);
		}

		diag_init(sid, cid, infile_name);
		for (;;) {
			memset(msg, 0x2b, sizeof(msg));
			len = fread_unescape(infile, msg, sizeof(msg));

			if (!len) {
				break;
			}

			handle_diag(msg, len);
		}
		diag_destroy(&sid, &cid);
		fclose(infile);

		argc--;
		argv++;
	};

	return 0;
}

