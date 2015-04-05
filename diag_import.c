#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <err.h>

#include "diag_input.h"
#include "bit_func.h"
#include "session.h"
#include <stdlib.h>

static void usage(const char *progname, const char *reason)
{
	printf("%s\n", reason);
	printf("Usage: %s [-s <id>] [-c <id>] [-f <filelist>] [filenames]\n", progname);
	printf("	-s <id>       - First session_info ID to be used for SQL\n");
	printf("	-c <id>       - First cell_info ID to be used for SQL\n");
	printf("	-g <target>   - Target host for GSMTAP UDP stream\n");
	printf("	-f <filelist> - Read list of input files from <filelist>\n");
	printf("	-a <appid>    - Set appid to <appid> (in hex)\n");
	printf("	-v            - Verbose messages\n");
	printf("	[filenames]   - Read DIAG data from [filenames]\n");
	exit(1);
}

static void
chop_newline(char *line)
{
	int newline_pos = strlen(line) - 1;
	if (newline_pos >= 0 && line[newline_pos] == '\n')
	{
		line[newline_pos] = '\0';
	}
}

int main(int argc, char *argv[])
{
	char infile_name[FILENAME_MAX];
	FILE *filelist = NULL;
	char *filelist_name = NULL;
	char *gsmtap_target = NULL;
	uint32_t appid = 0;
	int ch;
	long sid = 0;
	long cid = 0;
	int line = 0;

	msg_verbose = 0;

	while ((ch = getopt(argc, argv, "s:c:g:f:a:v")) != -1) {
		switch (ch) {
			case 's':
				sid = atol(optarg);
				break;
			case 'c':
				cid = atol(optarg);
				break;
			case 'g':
				gsmtap_target = strdup(optarg);
				break;
			case 'f':
				filelist_name = strdup(optarg);
				break;
			case 'a':
				appid = strtol(optarg, (char **)NULL, 16);
				break;
			case 'v':
				msg_verbose++;
				break;
			case '?':
			default:
				usage(argv[0], "Invalid arguments");
		}
	}

	argc -= optind;
	argv += optind;

	if (filelist_name == NULL && argc == 0)
	{
		errx(1, "Invalid arguments");
	}

	printf("PARSER_OK\n");
	fflush(stdout);

	//  Handle files passed to command line first
	while (argc > 0)
	{
		process_file(&sid, &cid, gsmtap_target, argv[0], appid);
		argc--;
		argv++;
	};

	//  Handle file list
	if (filelist_name)
	{
		filelist = fopen(filelist_name, "rb");
		if (!filelist)
		{
			err(1, "Cannot open file list: %s", filelist_name);
		}

		while (!feof(filelist))
		{
			fgets(infile_name, sizeof(infile_name), filelist);
			++line;
			if (ferror(filelist))
			{
				err(1, "Cannot open file in %s:%d", filelist_name, line);
			}
			chop_newline(infile_name);
			process_file(&sid, &cid, gsmtap_target, infile_name, appid);
		}
		fclose(filelist);
	}

	return 0;
}

void
process_file(long *sid, long *cid, char *gsmtap_target, char *infile_name, uint32_t appid)
{
	uint8_t msg[4096];
	FILE *infile = NULL;
	unsigned len = 0;

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

	diag_init(*sid, *cid, gsmtap_target, infile_name, appid);
	for (;;) {
		memset(msg, 0x2b, sizeof(msg));
		len = fread_unescape(infile, msg, sizeof(msg));

		if (!len) {
			break;
		}

		handle_diag(msg, len);
	}
	diag_destroy(sid, cid);
	fclose(infile);
}
