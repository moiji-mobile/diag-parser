#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <err.h>

#include "diag_input.h"
#include "bit_func.h"
#include "session.h"
#include <stdlib.h>

void process_file(char *infile_name, int do_init);

static void usage(const char *progname, const char *reason)
{
	printf("%s\n", reason);
	printf("Usage: %s [-f <filelist>] [filenames]\n", progname);
	printf("	-g <target>   - Target host for GSMTAP UDP stream\n");
	printf("	-p <pcapfile> - Write to PCAP file\n");
	printf("	-f <filelist> - Read list of input files from <filelist>\n");
	printf("	-i            - Initialize device\n");
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
	char *pcap_target = NULL;
	uint32_t appid = 0;
	int ch;
	long sid = 0;
	long cid = 0;
	int line = 0;
	int init = 0;

	msg_verbose = 0;

	while ((ch = getopt(argc, argv, "p:g:f:vi")) != -1) {
		switch (ch) {
			case 'g':
				gsmtap_target = strdup(optarg);
				break;
			case 'p':
				pcap_target = strdup(optarg);
				break;
			case 'f':
				filelist_name = strdup(optarg);
				break;
			case 'i':
				init = 1;
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

	diag_init(sid, cid, gsmtap_target, pcap_target, NULL, appid);

	printf("PARSER_OK\n");
	fflush(stdout);

	//  Handle files passed to command line first
	while (argc > 0)
	{
		process_file(argv[0], init);
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
			char *ret = fgets(infile_name, sizeof(infile_name), filelist);
			++line;
			if (ferror(filelist))
			{
				err(1, "Error parsing file list %s:%d", filelist_name, line);
			}
			if (ret) {
				chop_newline(infile_name);
				process_file(infile_name, init);
			}
		}
		fclose(filelist);
	}

	diag_destroy(&sid, &cid);

	return 0;
}

void
process_file(char *infile_name, int do_init)
{
	uint8_t msg[4096];
	FILE *infile = NULL;
	unsigned len = 0;

	if (strcmp(infile_name, "-") == 0)
	{
		infile = stdin;
	} else
	{
		infile = fopen(infile_name, "rb+");
	}

	if (!infile)
	{
		err(1, "Cannot open input file: %s", infile_name);
	}

	if (do_init)
		diag_set_log(infile);
	diag_set_filename(infile_name);

	for (;;) {
		len = fread_unescape(infile, msg, sizeof(msg));

		if (len < 1) {
			break;
		}

		/* Terminate message with standard GSM padding */
		if (len < sizeof(msg) - 1) {
			msg[len] = 0x2b;
		}

		handle_diag(msg, len);
	}
	fclose(infile);
}
