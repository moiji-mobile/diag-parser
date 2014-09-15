#ifndef CELL_INFO_H
#define CELL_INFO_H

#include <osmocom/core/linuxlist.h>

enum si_index {
	SI1 = 0,
	SI2, SI2b, SI2t, SI2q,
	SI3,
	SI4,
	SI5, SI5b, SI5t,
	SI6,
	SI13,

	SI_MAX
};

struct cell_info {
	int id;
	int stored;
	struct timeval first_seen;
	struct timeval last_seen;
	int mcc;
	int mnc;
	int lac;
	int cid;
	int rat;
	int bcch_arfcn;
	int ba_len;
	int power_sum;
	int power_count;
	int gprs;
	int t3212;
	int cro;
	int c1;
	int c2;
	int agch_blocks;
	int pag_mframes;
	int combined;
	struct gsm_sysinfo_freq arfcn_list[1024];
	uint32_t si_counters[SI_MAX];
	uint8_t si_data[SI_MAX][20];

	struct llist_head entry;
};

void cell_init();
int get_mcc(uint8_t *digits);
int get_mnc(uint8_t *digits);
void handle_lai(struct session_info *s, uint8_t *data, int cid);
void handle_sysinfo(struct session_info *s, struct gsm48_hdr *dtap, unsigned len, uint32_t fn);

#endif
